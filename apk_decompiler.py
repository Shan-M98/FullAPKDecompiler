#!/usr/bin/env python3
"""
APK Full Decompiler - Decompiles APK and converts all binary files to readable formats

Usage: python apk_decompiler.py <path_to_apk>

Converts:
- APK -> decompiled resources/smali (apktool)
- .dex -> Java source (jadx)
- .so -> C pseudocode (Ghidra)
- .xrsc -> JSON (custom parser)
- .zip -> extracted contents
- .prof/.profm -> method list
- .p12 -> PEM certificates
- Other binary -> hex dump
"""

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import urllib.request
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Optional, List, Dict, Tuple
import threading

# Tool download URLs
TOOL_URLS = {
    "apktool": "https://github.com/iBotPeaches/Apktool/releases/download/v2.10.0/apktool_2.10.0.jar",
    "jadx": "https://github.com/skylot/jadx/releases/download/v1.5.0/jadx-1.5.0.zip",
}

# Get CPU count for parallelism
CPU_COUNT = os.cpu_count() or 4


class APKDecompiler:
    def __init__(self, apk_path: str, output_dir: Optional[str] = None, tools_dir: Optional[str] = None,
                 skip_so: bool = False, skip_dex: bool = False, parallel: int = 0, resume: bool = False,
                 verbose: bool = False):
        self.apk_path = Path(apk_path).resolve()
        if not self.apk_path.exists():
            raise FileNotFoundError(f"APK not found: {self.apk_path}")

        self.skip_so = skip_so
        self.skip_dex = skip_dex
        self.resume = resume
        self.verbose = verbose
        # parallel=0 means auto-detect, otherwise use specified value
        self.parallel = parallel if parallel > 0 else max(1, CPU_COUNT // 2)

        self.apk_name = self.apk_path.stem
        self.output_dir = Path(output_dir) if output_dir else self.apk_path.parent / f"{self.apk_name}_decompiled"
        self.tools_dir = Path(tools_dir) if tools_dir else self.apk_path.parent / "decompiler_tools"

        # Tool paths
        self.apktool_jar = None
        self.jadx_bin = None
        self.ghidra_dir = None

        # Java path
        self.java_home = os.environ.get("JAVA_HOME", "")
        self.java_bin = self._find_java()

        # Stats (thread-safe)
        self._stats_lock = threading.Lock()
        self.stats = {
            "so_files": 0,
            "dex_files": 0,
            "xrsc_files": 0,
            "zip_files": 0,
            "prof_files": 0,
            "other_binary": 0,
            "skipped": 0,
            "errors": []
        }

        # Progress tracking
        self._progress_lock = threading.Lock()

    def _increment_stat(self, key: str, value: int = 1) -> None:
        """Thread-safe stat increment."""
        with self._stats_lock:
            self.stats[key] += value

    def _add_error(self, error: str) -> None:
        """Thread-safe error append."""
        with self._stats_lock:
            self.stats["errors"].append(error)

    def _find_java(self) -> str:
        """Find Java executable."""
        java_exe = "java.exe" if platform.system() == "Windows" else "java"

        # Check JAVA_HOME first
        if self.java_home:
            java_path = Path(self.java_home) / "bin" / java_exe
            if java_path.exists():
                return str(java_path)

        # Check common locations (check parent of tools_dir for local JDK)
        search_dirs = [
            self.apk_path.parent,
            self.tools_dir.parent if self.tools_dir else None,
            Path("C:/Program Files/Java"),
            Path("C:/Program Files/Eclipse Adoptium"),
            Path("/usr/lib/jvm"),
        ]

        for search_dir in search_dirs:
            if search_dir and search_dir.exists():
                # Look for jdk directories
                for jdk_dir in search_dir.glob("jdk*"):
                    java_path = jdk_dir / "bin" / java_exe
                    if java_path.exists():
                        return str(java_path)

        # Try system PATH
        if shutil.which(java_exe):
            return java_exe

        return ""

    def _download_file(self, url: str, dest: Path, desc: str = "") -> bool:
        """Download a file with progress."""
        print(f"  Downloading {desc or url}...")
        try:
            with urllib.request.urlopen(url, timeout=300) as response:
                total_size = int(response.headers.get('content-length', 0))
                downloaded = 0
                chunk_size = 65536  # 64KB chunks for faster download

                with open(dest, 'wb') as f:
                    while True:
                        chunk = response.read(chunk_size)
                        if not chunk:
                            break
                        f.write(chunk)
                        downloaded += len(chunk)
                        if total_size:
                            pct = (downloaded / total_size) * 100
                            print(f"\r  Progress: {pct:.1f}% ({downloaded // 1024 // 1024}MB)", end="", flush=True)
                print()
            return True
        except Exception as e:
            print(f"  Error downloading: {e}")
            return False

    def setup_tools(self) -> bool:
        """Download and setup required tools."""
        print("\n[1/6] Setting up tools...")
        self.tools_dir.mkdir(parents=True, exist_ok=True)

        # Check Java
        if not self.java_bin:
            print("  ERROR: Java not found. Please install JDK 11+ and set JAVA_HOME")
            print("  Download from: https://adoptium.net/")
            return False
        print(f"  Java found: {self.java_bin}")
        print(f"  Parallel workers: {self.parallel}")

        # Setup apktool - search multiple locations
        apktool_locations = [
            self.tools_dir / "apktool.jar",
            self.apk_path.parent / "apktool.jar",
            *self.apk_path.parent.glob("apktool*.jar"),
        ]

        self.apktool_jar = None
        for loc in apktool_locations:
            if loc.exists():
                self.apktool_jar = loc
                break

        if not self.apktool_jar:
            self.apktool_jar = self.tools_dir / "apktool.jar"
            if not self._download_file(TOOL_URLS["apktool"], self.apktool_jar, "apktool"):
                return False
        print(f"  apktool: {self.apktool_jar}")

        # Setup jadx
        jadx_bin_name = "jadx.bat" if platform.system() == "Windows" else "jadx"
        jadx_locations = [
            self.tools_dir / "jadx" / "bin" / jadx_bin_name,
            self.apk_path.parent / "jadx" / "bin" / jadx_bin_name,
        ]

        self.jadx_bin = None
        for loc in jadx_locations:
            if loc.exists():
                self.jadx_bin = loc
                break

        if not self.jadx_bin:
            jadx_dir = self.tools_dir / "jadx"
            jadx_zip = self.tools_dir / "jadx.zip"
            if not self._download_file(TOOL_URLS["jadx"], jadx_zip, "jadx"):
                return False
            print("  Extracting jadx...")
            with zipfile.ZipFile(jadx_zip, 'r') as zf:
                zf.extractall(jadx_dir)
            jadx_zip.unlink()
            self.jadx_bin = jadx_dir / "bin" / jadx_bin_name
            if platform.system() != "Windows":
                os.chmod(self.jadx_bin, 0o755)
        print(f"  jadx: {self.jadx_bin}")

        # Setup Ghidra - search multiple locations
        ghidra_locations = [
            self.tools_dir / "ghidra",
            self.apk_path.parent / "ghidra_11.2.1_PUBLIC",
            *self.apk_path.parent.glob("ghidra*"),
        ]

        self.ghidra_dir = None
        for loc in ghidra_locations:
            if loc.exists() and (loc / "support").exists():
                self.ghidra_dir = loc
                break

        if self.ghidra_dir:
            print(f"  Ghidra: {self.ghidra_dir}")
        else:
            print("  Ghidra: Not found (SO decompilation will use fallback)")
            print("    To enable full decompilation, download from: https://ghidra-sre.org/")

        return True

    def decompile_apk(self) -> bool:
        """Decompile APK using apktool."""
        print("\n[2/6] Decompiling APK with apktool...")

        apktool_output = self.output_dir / "apktool"

        # Resume check
        if self.resume and apktool_output.exists() and any(apktool_output.iterdir()):
            print("  Resuming: apktool output exists, skipping...")
            self._increment_stat("skipped")
            return True

        apktool_output.mkdir(parents=True, exist_ok=True)

        success_count = 0
        fail_count = 0

        # Handle XAPK (zip containing APKs)
        if self.apk_path.suffix.lower() == ".xapk":
            print("  Detected XAPK format, extracting...")
            xapk_extract = self.output_dir / "xapk_extracted"
            try:
                with zipfile.ZipFile(self.apk_path, 'r') as zf:
                    zf.extractall(xapk_extract)
            except zipfile.BadZipFile as e:
                print(f"  ERROR: Invalid XAPK/ZIP file: {e}")
                self._add_error(f"XAPK extraction failed: {e}")
                return False
            except Exception as e:
                print(f"  ERROR: Failed to extract XAPK: {e}")
                self._add_error(f"XAPK extraction failed: {e}")
                return False

            # Find and decompile each APK
            apk_files = list(xapk_extract.glob("*.apk"))
            if not apk_files:
                print("  WARNING: No APK files found in XAPK")
                self._add_error("No APK files found in XAPK")
                return False

            print(f"  Found {len(apk_files)} APK(s) in XAPK")

            # Decompile APKs in parallel
            with ThreadPoolExecutor(max_workers=min(self.parallel, len(apk_files))) as executor:
                futures = {}
                for apk in apk_files:
                    apk_out = apktool_output / apk.stem
                    futures[executor.submit(self._run_apktool, apk, apk_out)] = apk.name

                for future in as_completed(futures):
                    apk_name = futures[future]
                    try:
                        if future.result():
                            success_count += 1
                        else:
                            fail_count += 1
                            self._add_error(f"apktool failed for: {apk_name}")
                    except Exception as e:
                        fail_count += 1
                        self._add_error(f"apktool exception for {apk_name}: {e}")
        else:
            if self._run_apktool(self.apk_path, apktool_output / "main"):
                success_count += 1
            else:
                fail_count += 1
                self._add_error(f"apktool failed for: {self.apk_path.name}")

        print(f"  Decompilation complete: {success_count} succeeded, {fail_count} failed")

        if success_count == 0:
            print("  ERROR: All APK decompilations failed!")
            return False

        return True

    def _run_apktool(self, apk: Path, output: Path) -> bool:
        """Run apktool on a single APK."""
        print(f"  Decompiling: {apk.name}")
        cmd = [
            self.java_bin, "-jar", str(self.apktool_jar),
            "d", str(apk),
            "-o", str(output),
            "-f",  # Force overwrite
            "-j", str(self.parallel),  # Use multiple threads
        ]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            if result.returncode != 0:
                print(f"    Warning: apktool returned {result.returncode}")
                if result.stderr:
                    print(f"    {result.stderr[:500]}")
            return result.returncode == 0
        except subprocess.TimeoutExpired:
            print(f"    Timeout decompiling {apk.name}")
            return False
        except Exception as e:
            print(f"    Error: {e}")
            return False

    def convert_dex_files(self) -> None:
        """Convert DEX/APK files to Java source using jadx."""
        print("\n[3/6] Converting to Java source with jadx...")

        if self.skip_dex:
            print("  Skipped (--skip-dex flag)")
            return

        java_output = self.output_dir / "converted" / "java"
        java_output.mkdir(parents=True, exist_ok=True)

        # Find APK files to process (jadx can decompile APKs directly)
        # For XAPK: look in xapk_extracted folder
        # For APK: use original file
        apk_files = []

        xapk_extracted = self.output_dir / "xapk_extracted"
        if xapk_extracted.exists():
            apk_files = list(xapk_extracted.glob("*.apk"))

        if not apk_files and self.apk_path.suffix.lower() == ".apk":
            apk_files = [self.apk_path]

        # Also check for any .dex files directly
        dex_files = list(self.output_dir.rglob("*.dex"))

        if not apk_files and not dex_files:
            print("  No APK or DEX files found for Java conversion")
            return

        print(f"  Found {len(apk_files)} APK files, {len(dex_files)} DEX files")

        def process_apk(apk_file: Path) -> Tuple[int, Optional[str]]:
            out_path = java_output / apk_file.stem

            # Resume check
            if self.resume and out_path.exists() and any(out_path.rglob("*.java")):
                return (1, None)  # Skipped

            cmd = [
                str(self.jadx_bin),
                "-d", str(out_path),
                "--no-res",
                "-j", str(self.parallel),
                "-q",
                str(apk_file)
            ]

            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)
                if result.returncode != 0 and result.stderr and "error" in result.stderr.lower():
                    return (1, f"jadx partial failure {apk_file.name}")
                return (1, None)
            except subprocess.TimeoutExpired:
                return (0, f"jadx timeout: {apk_file.name}")
            except Exception as e:
                return (0, f"jadx error {apk_file.name}: {e}")

        # Process APK files
        if apk_files:
            with ThreadPoolExecutor(max_workers=min(self.parallel, len(apk_files))) as executor:
                futures = {executor.submit(process_apk, apk): apk.name for apk in apk_files}

                for i, future in enumerate(as_completed(futures)):
                    count, error = future.result()
                    self._increment_stat("dex_files", count)
                    if error:
                        self._add_error(error)
                    print(f"\r  Progress: {i+1}/{len(apk_files)} APKs", end="", flush=True)
            print()

        # Process standalone DEX files if any
        if dex_files:
            dex_dirs: Dict[Path, List[Path]] = {}
            for dex in dex_files:
                parent = dex.parent
                if parent not in dex_dirs:
                    dex_dirs[parent] = []
                dex_dirs[parent].append(dex)

            for dex_dir, files in dex_dirs.items():
                main_dex = next((f for f in files if f.name == "classes.dex"), files[0])
                try:
                    rel_path = dex_dir.relative_to(self.output_dir)
                except ValueError:
                    rel_path = Path(dex_dir.name)
                out_path = java_output / rel_path

                if self.resume and out_path.exists() and any(out_path.rglob("*.java")):
                    self._increment_stat("dex_files", len(files))
                    continue

                cmd = [
                    str(self.jadx_bin),
                    "-d", str(out_path),
                    "--no-res",
                    "-j", str(self.parallel),
                    "-q",
                    str(main_dex)
                ]
                try:
                    subprocess.run(cmd, capture_output=True, text=True, timeout=1800)
                    self._increment_stat("dex_files", len(files))
                except Exception as e:
                    self._add_error(f"DEX conversion {rel_path}: {e}")

        print(f"  Converted {self.stats['dex_files']} files to Java")

    def convert_so_files(self) -> None:
        """Convert .so files to C pseudocode using Ghidra."""
        print("\n[4/6] Converting SO files to C pseudocode...")

        if self.skip_so:
            print("  Skipped (--skip-so flag)")
            return

        so_files = list(self.output_dir.rglob("*.so"))
        if not so_files:
            print("  No SO files found")
            return

        # Filter out standard libraries that don't need decompilation
        skip_libs = {"libc++_shared.so", "libc.so", "libm.so", "libdl.so", "liblog.so", "libz.so"}
        so_files = [f for f in so_files if f.name not in skip_libs]

        print(f"  Found {len(so_files)} SO files (excluding standard libs)")

        so_output = self.output_dir / "converted" / "so_decompiled"
        so_output.mkdir(parents=True, exist_ok=True)

        # Check if Ghidra is available
        analyzer = None
        if self.ghidra_dir:
            analyzer_name = "analyzeHeadless.bat" if platform.system() == "Windows" else "analyzeHeadless"
            analyzer = self.ghidra_dir / "support" / analyzer_name
            if not analyzer.exists():
                analyzer = None

        if analyzer:
            # Create Ghidra project in temp dir to avoid path issues with special chars
            import tempfile
            ghidra_temp = Path(tempfile.mkdtemp(prefix="ghidra_proj_"))
            ghidra_project = ghidra_temp / "project"
            ghidra_project.mkdir(parents=True, exist_ok=True)

            # Remove any stale lock files
            for lock_file in ghidra_project.glob("*.lock"):
                try:
                    lock_file.unlink()
                except:
                    pass

            # Create Java export script (more reliable than Jython)
            script_dir = self.ghidra_dir / "Ghidra" / "Features" / "Decompiler" / "ghidra_scripts"
            script_path = script_dir / "ExportAllFunctions.java"

            # Create/update the export script (uses script args for output path)
            script_content = '''//Exports decompiled C code for all functions - headless version
//@category Export

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import java.io.*;

public class ExportAllFunctions extends GhidraScript {

    @Override
    public void run() throws Exception {
        String baseName = currentProgram.getName().replace(".so", "");

        // Get output path from script arguments, or use current directory
        String[] args = getScriptArgs();
        String outputPath;
        if (args != null && args.length > 0 && args[0].length() > 0) {
            outputPath = args[0] + "/" + baseName + "_decompiled.c";
        } else {
            outputPath = baseName + "_decompiled.c";
        }

        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);

        PrintWriter writer = new PrintWriter(new FileWriter(outputPath));
        writer.println("/* Decompiled by Ghidra */");
        writer.println("/* Program: " + currentProgram.getName() + " */");
        writer.println("/* Architecture: " + currentProgram.getLanguage().getProcessor() + " */");
        writer.println();

        FunctionManager funcManager = currentProgram.getFunctionManager();
        FunctionIterator functions = funcManager.getFunctions(true);

        int count = 0;
        int skipped = 0;

        while (functions.hasNext()) {
            Function func = functions.next();

            if (func.isExternal() || func.isThunk()) {
                skipped++;
                continue;
            }

            try {
                DecompileResults results = decompiler.decompileFunction(func, 30, monitor);

                if (results.decompileCompleted()) {
                    DecompiledFunction decompiledFunc = results.getDecompiledFunction();
                    if (decompiledFunc != null) {
                        String code = decompiledFunc.getC();
                        writer.println("/************************************************************/");
                        writer.println("/* " + func.getName() + " @ " + func.getEntryPoint() + " */");
                        writer.println("/************************************************************/");
                        writer.println(code);
                        writer.println();
                        count++;
                    }
                }
            } catch (Exception e) {
                skipped++;
            }
        }

        decompiler.dispose();
        writer.close();

        println("=== EXPORT COMPLETE ===");
        println("Decompiled: " + count + " functions");
        println("Skipped: " + skipped + " functions");
        println("Output: " + outputPath);
    }
}
'''
            script_path.write_text(script_content)
            print(f"  Ghidra export script: {script_path}")
        else:
            ghidra_project = None
            script_path = None

        # Process SO files SEQUENTIALLY to avoid Ghidra project locking issues
        completed = 0
        failed = 0
        skipped = 0

        # Create temp directories with safe names (Windows cmd.exe has issues with & in paths)
        # Both input SO files and output C files need safe paths
        temp_so_dir = Path(tempfile.mkdtemp(prefix="ghidra_so_")) if analyzer else None
        temp_output_dir = Path(tempfile.mkdtemp(prefix="ghidra_out_")) if analyzer else None

        for so_file in so_files:
            output_c = so_output / f"{so_file.stem}_decompiled.c"

            # Resume check - skip if already decompiled with substantial content
            if output_c.exists() and output_c.stat().st_size > 1000:
                completed += 1
                skipped += 1
                self._increment_stat("so_files")
                print(f"\r  Progress: {completed}/{len(so_files)} (skipped: {skipped}, failed: {failed})", end="", flush=True)
                continue

            success = False
            if analyzer:
                # Remove lock files before each run
                for lock_file in ghidra_project.glob("*.lock"):
                    try:
                        lock_file.unlink()
                    except:
                        pass

                # Copy SO file to temp dir to avoid path issues with special chars (& etc)
                temp_so_file = temp_so_dir / so_file.name
                try:
                    shutil.copy2(so_file, temp_so_file)
                except Exception as e:
                    self._add_error(f"SO copy failed {so_file.name}: {e}")
                    temp_so_file = so_file  # Fall back to original path

                # Phase 1: Import and analyze
                cmd_import = [
                    str(analyzer),
                    str(ghidra_project),
                    "SOProject",
                    "-import", str(temp_so_file),
                    "-overwrite",
                ]

                # Add timeout for large files
                file_size = so_file.stat().st_size
                timeout = 300 if file_size < 10_000_000 else 600 if file_size < 50_000_000 else 1200

                try:
                    if self.verbose:
                        print(f"\n    [IMPORT] {so_file.name}")

                    result = subprocess.run(cmd_import, capture_output=True, text=True, timeout=timeout)

                    if self.verbose:
                        if result.returncode != 0:
                            print(f"    Import returned: {result.returncode}")
                        # Show relevant output
                        for line in (result.stdout + result.stderr).split('\n'):
                            if any(kw in line.lower() for kw in ['error', 'import', 'success', 'fail']):
                                print(f"    {line[:100]}")

                    # Check if import succeeded (look for "succeeded" or absence of "No load spec")
                    if "No load spec found" in (result.stdout + result.stderr):
                        # File is encrypted/packed, cannot import
                        self._add_error(f"SO import failed (encrypted/packed): {so_file.name}")
                    else:
                        # Phase 2: Export decompiled code
                        # Use temp output directory to avoid Windows CMD issues with special chars
                        # Convert to forward slashes for Java
                        temp_output_str = str(temp_output_dir).replace("\\", "/")
                        temp_output_c = temp_output_dir / f"{so_file.stem}_decompiled.c"

                        cmd_export = [
                            str(analyzer),
                            str(ghidra_project),
                            "SOProject",
                            "-process", so_file.name,
                            "-postScript", "ExportAllFunctions.java", temp_output_str,
                            "-noanalysis",
                            "-scriptPath", str(script_path.parent),
                        ]

                        if self.verbose:
                            print(f"    [EXPORT] {so_file.name} -> {temp_output_str}")

                        result2 = subprocess.run(cmd_export, capture_output=True, text=True, timeout=timeout)

                        if self.verbose:
                            for line in (result2.stdout + result2.stderr).split('\n'):
                                if any(kw in line for kw in ['EXPORT', 'Decompiled:', 'Output:', 'error', 'Error']):
                                    print(f"    {line[:100]}")

                        # Check if output file was created in temp dir and copy to final location
                        if temp_output_c.exists() and temp_output_c.stat().st_size > 100:
                            shutil.copy2(temp_output_c, output_c)
                            temp_output_c.unlink()  # Clean up temp file
                            success = True
                        elif "EXPORT COMPLETE" in (result2.stdout + result2.stderr):
                            # Script completed but file might be elsewhere
                            for search_dir in [temp_output_dir, ghidra_project]:
                                for pattern in [f"{so_file.stem}_decompiled.c", f"*{so_file.stem}*.c"]:
                                    for alt in search_dir.glob(pattern):
                                        if alt.stat().st_size > 100:
                                            shutil.copy2(alt, output_c)
                                            alt.unlink()
                                            success = True
                                            break
                                    if success:
                                        break
                                if success:
                                    break

                except subprocess.TimeoutExpired:
                    self._add_error(f"SO timeout: {so_file.name}")
                except Exception as e:
                    self._add_error(f"SO Ghidra error {so_file.name}: {e}")

            # Fallback: extract strings and basic info if Ghidra failed
            if not success:
                self._extract_so_info(so_file, output_c)
                failed += 1

            # Clean up temp SO file
            if temp_so_dir and (temp_so_dir / so_file.name).exists():
                try:
                    (temp_so_dir / so_file.name).unlink()
                except:
                    pass

            completed += 1
            self._increment_stat("so_files")
            print(f"\r  Progress: {completed}/{len(so_files)} (skipped: {skipped}, failed: {failed})", end="", flush=True)

        # Clean up temp directories
        for temp_dir in [temp_so_dir, temp_output_dir]:
            if temp_dir and temp_dir.exists():
                try:
                    shutil.rmtree(temp_dir)
                except:
                    pass
        if analyzer and 'ghidra_temp' in dir() and ghidra_temp.exists():
            try:
                shutil.rmtree(ghidra_temp)
            except:
                pass

        print(f"\n  Processed {self.stats['so_files']} SO files ({skipped} resumed, {failed} fallback)")

    def _extract_so_info(self, so_file: Path, output: Path) -> None:
        """Extract basic info from SO file when Ghidra fails or unavailable."""
        try:
            # Read file in chunks to handle large files
            file_size = so_file.stat().st_size
            hash_obj = hashlib.sha256()
            strings = []

            with open(so_file, 'rb') as f:
                # Read first 10MB for string extraction
                data = f.read(min(file_size, 10 * 1024 * 1024))
                hash_obj.update(data)
                strings = self._extract_strings_fast(data)

                # Continue hashing rest of file
                while True:
                    chunk = f.read(1024 * 1024)
                    if not chunk:
                        break
                    hash_obj.update(chunk)

            with open(output, 'w', encoding='utf-8') as f:
                f.write(f"// Basic extraction from: {so_file.name}\n")
                f.write(f"// Size: {file_size:,} bytes\n")
                f.write(f"// SHA256: {hash_obj.hexdigest()}\n")
                f.write(f"// Strings found: {len(strings)}\n\n")

                f.write("// === Extracted Strings ===\n")
                for s in strings[:2000]:
                    # Escape for C comment
                    s_escaped = s.replace("*/", "* /")
                    f.write(f"// {s_escaped}\n")

        except Exception as e:
            self._add_error(f"SO extraction {so_file.name}: {e}")

    def convert_xrsc_files(self) -> None:
        """Convert .xrsc files to JSON."""
        print("\n[5/6] Converting XRSC files to JSON...")

        xrsc_files = list(self.output_dir.rglob("*.xrsc"))
        if not xrsc_files:
            print("  No XRSC files found")
            return

        print(f"  Found {len(xrsc_files)} XRSC files")

        xrsc_output = self.output_dir / "converted" / "xrsc"
        xrsc_output.mkdir(parents=True, exist_ok=True)

        all_results = []
        results_lock = threading.Lock()

        def process_xrsc(xrsc_file: Path) -> Optional[dict]:
            json_out = xrsc_output / f"{xrsc_file.stem}.json"

            # Resume check
            if self.resume and json_out.exists():
                try:
                    with open(json_out, 'r', encoding='utf-8') as f:
                        return json.load(f)
                except:
                    pass

            try:
                result = self._parse_xrsc(xrsc_file)
                with open(json_out, 'w', encoding='utf-8') as f:
                    json.dump(result, f, indent=2, ensure_ascii=False)
                return result
            except Exception as e:
                self._add_error(f"XRSC parse {xrsc_file.name}: {e}")
                return None

        # Process in parallel
        with ThreadPoolExecutor(max_workers=self.parallel) as executor:
            futures = [executor.submit(process_xrsc, f) for f in xrsc_files]

            for future in as_completed(futures):
                result = future.result()
                if result:
                    with results_lock:
                        all_results.append(result)
                    self._increment_stat("xrsc_files")

        # Save combined file
        combined = xrsc_output / "all_strings.json"
        with open(combined, 'w', encoding='utf-8') as f:
            json.dump(all_results, f, indent=2, ensure_ascii=False)

        print(f"  Converted {self.stats['xrsc_files']} files")

    def _parse_xrsc(self, filepath: Path) -> dict:
        """Parse an .xrsc NxString file."""
        with open(filepath, 'rb') as f:
            data = f.read()

        result = {
            'file': filepath.name,
            'path': str(filepath.relative_to(self.output_dir)),
            'magic': None,
            'locale': None,
            'strings': []
        }

        if data[:8] == b'NxString':
            result['magic'] = 'NxString'
            pos = 12
            locale_end = data.find(b'\x00', pos)
            if locale_end > pos:
                result['locale'] = data[pos:locale_end].decode('utf-8', errors='replace')
                pos = locale_end + 1
            strings = self._extract_strings_fast(data[pos:])
        else:
            strings = self._extract_strings_fast(data)

        result['strings'] = strings
        result['string_count'] = len(strings)
        return result

    def _process_font_files(self, converted: Path) -> None:
        """Extract metadata from font files."""
        font_output = converted / "fonts"

        font_files = []
        for ext in [".ttf", ".otf", ".woff", ".woff2"]:
            font_files.extend([f for f in self.output_dir.rglob(f"*{ext}")
                              if "converted" not in str(f)])

        if not font_files:
            return

        font_output.mkdir(parents=True, exist_ok=True)
        print(f"  Processing {len(font_files)} font files...")

        for ff in font_files:
            out_file = font_output / f"{ff.name}.txt"
            if self.resume and out_file.exists():
                continue

            try:
                file_size = ff.stat().st_size
                with open(ff, 'rb') as f:
                    data = f.read(min(4096, file_size))

                with open(out_file, 'w', encoding='utf-8') as f:
                    f.write(f"Font File: {ff.name}\n")
                    f.write(f"Path: {ff.relative_to(self.output_dir)}\n")
                    f.write(f"Size: {file_size:,} bytes\n")

                    # Detect font type
                    if data[:4] == b'\x00\x01\x00\x00':
                        f.write("Format: TrueType Font (TTF)\n")
                    elif data[:4] == b'OTTO':
                        f.write("Format: OpenType Font (OTF)\n")
                    elif data[:4] == b'wOFF':
                        f.write("Format: Web Open Font Format (WOFF)\n")
                    elif data[:4] == b'wOF2':
                        f.write("Format: Web Open Font Format 2 (WOFF2)\n")

                    # Extract readable strings (font names, etc.)
                    strings = self._extract_strings_fast(data, min_length=4)
                    if strings:
                        f.write("\nExtracted strings (potential font names):\n")
                        for s in strings[:50]:
                            f.write(f"  {s}\n")

                self._increment_stat("other_binary")
            except Exception as e:
                self._add_error(f"Font metadata {ff.name}: {e}")

    def _process_signature_files(self, converted: Path) -> None:
        """Process JAR signature and certificate files."""
        sig_output = converted / "signatures"

        # Find RSA/DSA signature files and SF manifest files
        sig_files = []
        for pattern in ["*.RSA", "*.DSA", "*.EC", "*.SF"]:
            sig_files.extend([f for f in self.output_dir.rglob(pattern)
                             if "converted" not in str(f)])

        # Also find PEM files
        pem_files = [f for f in self.output_dir.rglob("*.pem") if "converted" not in str(f)]

        if not sig_files and not pem_files:
            return

        sig_output.mkdir(parents=True, exist_ok=True)
        print(f"  Processing {len(sig_files)} signature files, {len(pem_files)} PEM files...")

        # Process signature files
        for sf in sig_files:
            out_file = sig_output / f"{sf.name}.txt"
            if self.resume and out_file.exists():
                continue

            try:
                if sf.suffix.upper() == ".SF":
                    # SF files are text manifests
                    with open(sf, 'r', encoding='utf-8', errors='replace') as f:
                        content = f.read()
                    with open(out_file, 'w', encoding='utf-8') as f:
                        f.write(f"Signature Manifest: {sf.name}\n")
                        f.write("=" * 50 + "\n\n")
                        f.write(content)
                else:
                    # RSA/DSA/EC are binary PKCS#7 signatures
                    # Try to extract with openssl
                    try:
                        result = subprocess.run(
                            ["openssl", "pkcs7", "-in", str(sf), "-inform", "DER", "-print_certs", "-text"],
                            capture_output=True, text=True, timeout=30
                        )
                        with open(out_file, 'w', encoding='utf-8') as f:
                            f.write(f"Certificate from: {sf.name}\n")
                            f.write("=" * 50 + "\n\n")
                            f.write(result.stdout or result.stderr or "Could not parse certificate")
                    except Exception:
                        # Fallback: hex dump
                        self._hex_dump(sf, out_file)

                self._increment_stat("other_binary")
            except Exception as e:
                self._add_error(f"Signature file {sf.name}: {e}")

        # Copy PEM files (already readable)
        for pf in pem_files:
            out_file = sig_output / pf.name
            if self.resume and out_file.exists():
                continue
            try:
                shutil.copy2(pf, out_file)
                self._increment_stat("other_binary")
            except Exception as e:
                self._add_error(f"PEM copy {pf.name}: {e}")

    def process_other_binaries(self) -> None:
        """Process other binary files (zip, prof, p12, etc.)."""
        print("\n[6/6] Processing other binary files...")

        converted = self.output_dir / "converted"

        # Process font files
        self._process_font_files(converted)

        # Process signature/certificate files
        self._process_signature_files(converted)

        # Process ZIP files in parallel
        zip_files = [zf for zf in self.output_dir.rglob("*.zip")
                     if "converted" not in str(zf) and "tools" not in str(zf)]

        if zip_files:
            zip_output = converted / "extracted_zips"
            zip_output.mkdir(parents=True, exist_ok=True)

            def extract_zip(zf: Path) -> bool:
                extract_dir = zip_output / zf.stem
                if self.resume and extract_dir.exists():
                    return True
                try:
                    with zipfile.ZipFile(zf, 'r') as z:
                        z.extractall(extract_dir)
                    return True
                except Exception as e:
                    self._add_error(f"ZIP extract {zf.name}: {e}")
                    return False

            with ThreadPoolExecutor(max_workers=self.parallel) as executor:
                results = list(executor.map(extract_zip, zip_files))
                self._increment_stat("zip_files", sum(results))

            print(f"  Extracted {self.stats['zip_files']} ZIP files")

        # Process profile files
        prof_files = [pf for pf in self.output_dir.rglob("*.prof") if "converted" not in str(pf)]
        prof_files += [pf for pf in self.output_dir.rglob("*.profm") if "converted" not in str(pf)]

        if prof_files:
            prof_output = converted / "profiles"
            prof_output.mkdir(parents=True, exist_ok=True)

            for pf in prof_files:
                try:
                    out_file = prof_output / f"{pf.name}.txt"
                    if self.resume and out_file.exists():
                        self._increment_stat("prof_files")
                        continue
                    self._parse_profile(pf, out_file)
                    self._increment_stat("prof_files")
                except Exception as e:
                    self._add_error(f"Profile parse {pf.name}: {e}")

            print(f"  Parsed {self.stats['prof_files']} profile files")

        # Process certificates
        p12_files = [pf for pf in self.output_dir.rglob("*.p12") if "converted" not in str(pf)]
        if p12_files:
            cert_output = converted / "certificates"
            cert_output.mkdir(parents=True, exist_ok=True)

            for p12 in p12_files:
                out_file = cert_output / f"{p12.stem}.txt"
                if not (self.resume and out_file.exists()):
                    self._extract_cert_info(p12, out_file)

        # Process other binary files (hex dump)
        binary_output = converted / "binary_dumps"
        binary_output.mkdir(parents=True, exist_ok=True)

        # Extended list of binary extensions
        other_extensions = {".bin", ".model", ".dat", ".cvr", ".czl", ".pb", ".flatbuf"}
        for ext in other_extensions:
            for bf in self.output_dir.rglob(f"*{ext}"):
                if "converted" in str(bf):
                    continue
                out_file = binary_output / f"{bf.name}.txt"
                if self.resume and out_file.exists():
                    self._increment_stat("other_binary")
                    continue
                self._hex_dump(bf, out_file)
                self._increment_stat("other_binary")

        # Process known extensionless binary files
        known_binaries = [
            "MetadataProto_default", "ph_raw", "ph_index", "nd",
            "tiktok_methods_profile_*",  # Profile data
            "stamp-cert-sha256",  # Certificate stamps
        ]
        for pattern in known_binaries:
            for bf in self.output_dir.rglob(pattern):
                if "converted" in str(bf) or not bf.is_file():
                    continue
                out_file = binary_output / f"{bf.name}.txt"
                if self.resume and out_file.exists():
                    self._increment_stat("other_binary")
                    continue
                self._hex_dump(bf, out_file)
                self._increment_stat("other_binary")

        # Process obfuscated AppsFlyer files (s-appsflyer/*)
        appsflyer_dirs = list(self.output_dir.rglob("s-appsflyer"))
        for af_dir in appsflyer_dirs:
            if "converted" in str(af_dir) or not af_dir.is_dir():
                continue
            for bf in af_dir.iterdir():
                if bf.is_file():
                    out_file = binary_output / f"appsflyer_{bf.name}.txt"
                    if self.resume and out_file.exists():
                        self._increment_stat("other_binary")
                        continue
                    self._hex_dump(bf, out_file)
                    self._increment_stat("other_binary")

        # Process res/raw files without extensions (map styles, etc.)
        raw_dirs = list(self.output_dir.rglob("res/raw"))
        for raw_dir in raw_dirs:
            if "converted" in str(raw_dir) or not raw_dir.is_dir():
                continue
            for rf in raw_dir.iterdir():
                if rf.is_file() and "." not in rf.name:
                    out_file = binary_output / f"raw_{rf.name}.txt"
                    if self.resume and out_file.exists():
                        self._increment_stat("other_binary")
                        continue
                    # Check if it's actually JSON (map styles often are)
                    try:
                        with open(rf, 'rb') as f:
                            head = f.read(100)
                        if head.strip().startswith(b'{') or head.strip().startswith(b'['):
                            # It's JSON, copy with .json extension
                            json_out = binary_output / f"raw_{rf.name}.json"
                            shutil.copy2(rf, json_out)
                        else:
                            self._hex_dump(rf, out_file)
                    except:
                        self._hex_dump(rf, out_file)
                    self._increment_stat("other_binary")

    def _parse_profile(self, prof_file: Path, output: Path) -> None:
        """Extract info from ART profile file."""
        with open(prof_file, 'rb') as f:
            data = f.read()

        with open(output, 'w', encoding='utf-8') as f:
            f.write(f"Profile: {prof_file.name}\n")
            f.write(f"Size: {len(data)} bytes\n")
            f.write(f"Magic: {data[:4].hex()}\n\n")

            strings = self._extract_strings_fast(data, min_length=10)
            f.write("Extracted strings/methods:\n")
            for s in strings:
                if '.' in s or '/' in s:
                    f.write(f"  {s}\n")

    def _extract_cert_info(self, p12_file: Path, output: Path) -> None:
        """Extract certificate info (if openssl available)."""
        try:
            result = subprocess.run(
                ["openssl", "pkcs12", "-info", "-in", str(p12_file), "-nokeys", "-passin", "pass:"],
                capture_output=True, text=True, timeout=30
            )
            with open(output, 'w') as f:
                f.write(result.stdout or result.stderr or "Could not extract certificate info")
        except Exception:
            with open(output, 'w') as f:
                f.write(f"Certificate file: {p12_file.name}\n")
                f.write(f"Size: {p12_file.stat().st_size} bytes\n")
                f.write("Note: Install openssl to extract certificate details\n")

    def _detect_format(self, data: bytes) -> Tuple[str, str]:
        """Detect file format from magic bytes. Returns (format_name, description)."""
        if len(data) < 4:
            return ("unknown", "Too small to identify")

        # Check magic bytes
        magic = data[:4]
        magic8 = data[:8] if len(data) >= 8 else data

        # SQLite
        if data[:16] == b'SQLite format 3\x00':
            return ("sqlite", "SQLite 3 Database")

        # Protobuf (heuristic: starts with field tag, usually 0x08-0x7a for small field numbers)
        if magic[0] in range(0x08, 0x7b) and magic[0] & 0x07 in (0, 1, 2, 5):
            return ("protobuf", "Possible Protocol Buffer")

        # Gzip
        if magic[:2] == b'\x1f\x8b':
            return ("gzip", "Gzip compressed")

        # Zlib
        if magic[:2] in (b'\x78\x01', b'\x78\x9c', b'\x78\xda'):
            return ("zlib", "Zlib compressed")

        # ZIP/JAR
        if magic == b'PK\x03\x04':
            return ("zip", "ZIP archive")

        # PNG
        if magic8 == b'\x89PNG\r\n\x1a\n':
            return ("png", "PNG image")

        # JPEG
        if magic[:2] == b'\xff\xd8':
            return ("jpeg", "JPEG image")

        # JSON (heuristic)
        stripped = data.lstrip()
        if stripped and stripped[0:1] in (b'{', b'['):
            return ("json", "JSON data")

        # XML
        if data.lstrip().startswith(b'<?xml') or data.lstrip().startswith(b'<'):
            return ("xml", "XML data")

        # FlatBuffers (heuristic: starts with root table offset)
        if len(data) >= 8:
            # FlatBuffers files often start with a 4-byte offset
            offset = int.from_bytes(data[:4], 'little')
            if 4 <= offset < len(data) and offset < 1000:
                return ("flatbuf", "Possible FlatBuffer")

        return ("binary", "Unknown binary format")

    def _decode_protobuf_raw(self, data: bytes) -> Optional[str]:
        """Try to decode protobuf data without schema using protoc --decode_raw."""
        try:
            result = subprocess.run(
                ["protoc", "--decode_raw"],
                input=data,
                capture_output=True,
                timeout=10
            )
            if result.returncode == 0 and result.stdout:
                return result.stdout.decode('utf-8', errors='replace')
        except FileNotFoundError:
            # protoc not installed
            return None
        except Exception:
            pass
        return None

    def _dump_sqlite(self, db_file: Path) -> Optional[str]:
        """Dump SQLite database schema and sample data."""
        try:
            import sqlite3
            conn = sqlite3.connect(str(db_file))
            cursor = conn.cursor()

            output = []
            output.append("=== SQLite Database ===\n")

            # Get tables
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = cursor.fetchall()
            output.append(f"Tables: {len(tables)}\n\n")

            for (table_name,) in tables:
                output.append(f"--- Table: {table_name} ---\n")

                # Get schema
                cursor.execute(f"PRAGMA table_info({table_name})")
                columns = cursor.fetchall()
                output.append("Columns:\n")
                for col in columns:
                    output.append(f"  {col[1]} ({col[2]})\n")

                # Get row count
                cursor.execute(f"SELECT COUNT(*) FROM {table_name}")
                count = cursor.fetchone()[0]
                output.append(f"Rows: {count}\n")

                # Sample data (first 5 rows)
                if count > 0:
                    cursor.execute(f"SELECT * FROM {table_name} LIMIT 5")
                    rows = cursor.fetchall()
                    output.append("Sample data:\n")
                    for row in rows:
                        output.append(f"  {row}\n")
                output.append("\n")

            conn.close()
            return ''.join(output)
        except Exception as e:
            return f"SQLite error: {e}"

    def _hex_dump(self, binary_file: Path, output: Path, max_bytes: int = 8192) -> None:
        """Create hex dump of binary file with format detection."""
        file_size = binary_file.stat().st_size
        with open(binary_file, 'rb') as f:
            data = f.read(min(file_size, max_bytes))
            full_data = data if file_size <= max_bytes else None

        # Read full file for small files (needed for protobuf/sqlite)
        if file_size <= 1024 * 1024:  # 1MB limit
            with open(binary_file, 'rb') as f:
                full_data = f.read()

        # Detect format
        fmt, fmt_desc = self._detect_format(data)

        with open(output, 'w', encoding='utf-8') as f:
            f.write(f"File: {binary_file.name}\n")
            f.write(f"Size: {file_size:,} bytes\n")
            f.write(f"SHA256: {hashlib.sha256(data).hexdigest()}\n")
            f.write(f"Detected format: {fmt_desc}\n\n")

            # Format-specific handling
            if fmt == "sqlite" and full_data:
                # Write to temp file and dump
                import tempfile
                with tempfile.NamedTemporaryFile(delete=False, suffix='.db') as tmp:
                    tmp.write(full_data)
                    tmp_path = tmp.name
                try:
                    sqlite_dump = self._dump_sqlite(Path(tmp_path))
                    if sqlite_dump:
                        f.write(sqlite_dump)
                finally:
                    os.unlink(tmp_path)

            elif fmt == "protobuf" and full_data:
                f.write("=== Protobuf Decode (raw) ===\n")
                decoded = self._decode_protobuf_raw(full_data)
                if decoded:
                    f.write(decoded)
                    f.write("\n")
                else:
                    f.write("(protoc not available or decode failed)\n")
                    f.write("Install protobuf: https://github.com/protocolbuffers/protobuf/releases\n\n")

            elif fmt == "json":
                f.write("=== JSON Content ===\n")
                try:
                    import json as json_mod
                    parsed = json_mod.loads(data.decode('utf-8'))
                    f.write(json_mod.dumps(parsed, indent=2, ensure_ascii=False)[:10000])
                    f.write("\n")
                except:
                    f.write(data.decode('utf-8', errors='replace')[:5000])
                    f.write("\n")

            elif fmt == "xml":
                f.write("=== XML Content ===\n")
                f.write(data.decode('utf-8', errors='replace')[:5000])
                f.write("\n")

            elif fmt == "gzip" and full_data:
                f.write("=== Gzip Decompressed ===\n")
                try:
                    import gzip
                    decompressed = gzip.decompress(full_data)
                    # Recursively detect inner format
                    inner_fmt, inner_desc = self._detect_format(decompressed)
                    f.write(f"Inner format: {inner_desc}\n")
                    if inner_fmt == "protobuf":
                        decoded = self._decode_protobuf_raw(decompressed)
                        if decoded:
                            f.write(decoded[:10000])
                    else:
                        strings = self._extract_strings_fast(decompressed)
                        f.write(f"Extracted {len(strings)} strings:\n")
                        for s in strings[:200]:
                            f.write(f"  {s}\n")
                except Exception as e:
                    f.write(f"Decompression failed: {e}\n")

            elif fmt == "zlib" and full_data:
                f.write("=== Zlib Decompressed ===\n")
                try:
                    import zlib
                    decompressed = zlib.decompress(full_data)
                    inner_fmt, inner_desc = self._detect_format(decompressed)
                    f.write(f"Inner format: {inner_desc}\n")
                    if inner_fmt == "protobuf":
                        decoded = self._decode_protobuf_raw(decompressed)
                        if decoded:
                            f.write(decoded[:10000])
                    else:
                        strings = self._extract_strings_fast(decompressed)
                        f.write(f"Extracted {len(strings)} strings:\n")
                        for s in strings[:200]:
                            f.write(f"  {s}\n")
                except Exception as e:
                    f.write(f"Decompression failed: {e}\n")

            # Always include hex dump for unknown/binary formats
            if fmt in ("binary", "unknown", "flatbuf"):
                f.write(f"=== Hex Dump (first {len(data)} bytes) ===\n")
                for i in range(0, min(len(data), 2048), 16):
                    chunk = data[i:i+16]
                    hex_part = ' '.join(f'{b:02x}' for b in chunk)
                    ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
                    f.write(f"{i:08x}  {hex_part:<48}  {ascii_part}\n")

            # Always extract strings
            f.write("\n=== Extracted Strings ===\n")
            strings = self._extract_strings_fast(full_data if full_data else data)
            for s in strings[:200]:
                f.write(f"  {s}\n")

    def _extract_strings_fast(self, data: bytes, min_length: int = 4) -> List[str]:
        """Extract readable strings from binary data using regex (fast)."""
        # Match sequences of printable ASCII characters
        pattern = rb'[\x20-\x7e\t\r\n]{' + str(min_length).encode() + rb',}'
        matches = re.findall(pattern, data)

        strings = []
        for match in matches:
            try:
                s = match.decode('utf-8', errors='ignore').strip()
                if s and not s.isspace():
                    strings.append(s)
            except:
                pass

        return strings

    def generate_report(self) -> None:
        """Generate summary report."""
        report_path = self.output_dir / "decompilation_report.md"

        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(f"# APK Decompilation Report\n\n")
            f.write(f"**APK:** {self.apk_path.name}\n")
            f.write(f"**Output:** {self.output_dir}\n")
            f.write(f"**Parallel workers:** {self.parallel}\n\n")

            f.write("## Conversion Summary\n\n")
            f.write(f"| File Type | Count |\n")
            f.write(f"|-----------|-------|\n")
            f.write(f"| DEX -> Java | {self.stats['dex_files']} |\n")
            f.write(f"| SO -> C | {self.stats['so_files']} |\n")
            f.write(f"| XRSC -> JSON | {self.stats['xrsc_files']} |\n")
            f.write(f"| ZIP extracted | {self.stats['zip_files']} |\n")
            f.write(f"| Profile files | {self.stats['prof_files']} |\n")
            f.write(f"| Other binary | {self.stats['other_binary']} |\n")
            f.write(f"| Skipped (resume) | {self.stats['skipped']} |\n\n")

            if self.stats['errors']:
                f.write("## Errors\n\n")
                for err in self.stats['errors']:
                    f.write(f"- {err}\n")

            f.write("\n## Output Structure\n\n")
            f.write("```\n")
            f.write(f"{self.output_dir.name}/\n")
            f.write("|-- apktool/           # Decompiled resources and smali\n")
            f.write("|-- converted/\n")
            f.write("|   |-- java/          # Java source from DEX\n")
            f.write("|   |-- so_decompiled/ # C pseudocode from SO\n")
            f.write("|   |-- xrsc/          # JSON from XRSC strings\n")
            f.write("|   |-- extracted_zips/# Extracted archives\n")
            f.write("|   |-- profiles/      # Parsed profile files\n")
            f.write("|   |-- certificates/  # Certificate info\n")
            f.write("|   |-- signatures/    # RSA/SF signature files\n")
            f.write("|   |-- fonts/         # Font file metadata\n")
            f.write("|   +-- binary_dumps/  # Hex dumps of binaries\n")
            f.write("+-- decompilation_report.md\n")
            f.write("```\n")

        print(f"\nReport saved to: {report_path}")

    def run(self) -> bool:
        """Run the full decompilation pipeline."""
        print(f"\n{'='*60}")
        print(f"APK Full Decompiler")
        print(f"{'='*60}")
        print(f"Input: {self.apk_path}")
        print(f"Output: {self.output_dir}")
        if self.resume:
            print("Mode: Resume (skipping existing outputs)")

        # Setup
        if not self.setup_tools():
            return False

        # Create output directory
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Decompile APK
        if not self.decompile_apk():
            print("\nERROR: APK decompilation failed. Cannot continue.")
            print("Check that the APK file is valid and not corrupted.")
            self.generate_report()
            return False

        # Convert all binary formats
        self.convert_dex_files()
        self.convert_so_files()
        self.convert_xrsc_files()
        self.process_other_binaries()

        # Generate report
        self.generate_report()

        has_errors = len(self.stats["errors"]) > 0
        print(f"\n{'='*60}")
        if has_errors:
            print(f"Decompilation complete with {len(self.stats['errors'])} error(s)")
        else:
            print("Decompilation complete!")
        print(f"{'='*60}")
        print(f"\nStats:")
        print(f"  DEX files converted: {self.stats['dex_files']}")
        print(f"  SO files processed: {self.stats['so_files']}")
        print(f"  XRSC files parsed: {self.stats['xrsc_files']}")
        print(f"  ZIP files extracted: {self.stats['zip_files']}")
        print(f"  Skipped (resume): {self.stats['skipped']}")
        print(f"  Errors: {len(self.stats['errors'])}")

        return True


def main():
    parser = argparse.ArgumentParser(
        description="Fully decompile an APK and convert all binary files to readable formats",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python apk_decompiler.py app.apk
  python apk_decompiler.py app.xapk -o ./output
  python apk_decompiler.py app.apk --parallel 8
  python apk_decompiler.py app.apk --resume

Supported conversions:
  .dex   -> Java source code (jadx)
  .so    -> C pseudocode (Ghidra) or string extraction
  .xrsc  -> JSON (custom parser)
  .zip   -> Extracted contents
  .prof  -> Method list
  .p12   -> Certificate info
  Other  -> Hex dump + strings
        """
    )

    parser.add_argument("apk", help="Path to APK or XAPK file")
    parser.add_argument("-o", "--output", help="Output directory (default: <apk_name>_decompiled)")
    parser.add_argument("--tools-dir", help="Directory for downloaded tools (default: ./decompiler_tools)")
    parser.add_argument("--skip-so", action="store_true", help="Skip SO file decompilation")
    parser.add_argument("--skip-dex", action="store_true", help="Skip DEX to Java conversion")
    parser.add_argument("-p", "--parallel", type=int, default=0,
                        help=f"Number of parallel workers (default: auto, detected {CPU_COUNT // 2})")
    parser.add_argument("--resume", action="store_true", help="Resume interrupted run, skip existing outputs")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output for debugging")

    args = parser.parse_args()

    try:
        decompiler = APKDecompiler(
            apk_path=args.apk,
            output_dir=args.output,
            tools_dir=args.tools_dir,
            skip_so=args.skip_so,
            skip_dex=args.skip_dex,
            parallel=args.parallel,
            resume=args.resume,
            verbose=args.verbose
        )

        success = decompiler.run()
        sys.exit(0 if success else 1)

    except FileNotFoundError as e:
        print(f"Error: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nInterrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
