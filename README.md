# APK Decompiler

A powerful Python tool that fully decompiles Android APK/XAPK files, converting all binary formats to human-readable source code.

## Features

- **DEX to Java** - Converts Dalvik bytecode to Java source using JADX
- **SO to C** - Decompiles native ARM/ARM64 libraries to C pseudocode using Ghidra
- **Resource Extraction** - Decodes AndroidManifest.xml, resources, and assets using apktool
- **XAPK Support** - Handles split APKs and app bundles
- **Auto-download** - Automatically downloads required tools (apktool, JADX)
- **Resume Support** - Can resume interrupted decompilation sessions
- **Parallel Processing** - Multi-threaded for faster processing
- **Cross-platform** - Works on Windows, Linux, and macOS

## Installation

### Prerequisites

- **Python 3.8+**
- **Java JDK 11+** (required for apktool and JADX)
  - Download from [Adoptium](https://adoptium.net/)
  - Ensure `java` is in your PATH or set `JAVA_HOME`

### Quick Start

```bash
# Clone the repository
git clone https://github.com/yourusername/apk-decompiler.git
cd apk-decompiler

# Run on an APK (tools will auto-download)
python apk_decompiler.py your_app.apk
```

### Optional: Ghidra for Native Library Decompilation

For full `.so` decompilation to C pseudocode:

1. Download [Ghidra](https://ghidra-sre.org/) (free, by NSA)
2. Extract to the same directory as the script (e.g., `ghidra_11.2.1_PUBLIC/`)
3. The script will automatically detect and use it

Without Ghidra, `.so` files will only have string extraction (fallback mode).

## Usage

### Basic Usage

```bash
# Decompile an APK
python apk_decompiler.py app.apk

# Decompile an XAPK (split APK bundle)
python apk_decompiler.py app.xapk

# Specify output directory
python apk_decompiler.py app.apk -o ./output
```

### Advanced Options

```bash
# Resume an interrupted decompilation
python apk_decompiler.py app.apk --resume

# Skip DEX decompilation (resources only)
python apk_decompiler.py app.apk --skip-dex

# Skip SO decompilation
python apk_decompiler.py app.apk --skip-so

# Set parallel workers
python apk_decompiler.py app.apk --parallel 8

# Verbose output (for debugging)
python apk_decompiler.py app.apk -v
```

### All Options

```
usage: apk_decompiler.py [-h] [-o OUTPUT] [--tools-dir TOOLS_DIR] [--skip-so]
                         [--skip-dex] [-p PARALLEL] [--resume] [-v]
                         apk

positional arguments:
  apk                   Path to APK or XAPK file

options:
  -h, --help            Show help message
  -o, --output          Output directory (default: <apk_name>_decompiled)
  --tools-dir           Directory for downloaded tools (default: ./decompiler_tools)
  --skip-so             Skip SO file decompilation
  --skip-dex            Skip DEX to Java conversion
  -p, --parallel        Number of parallel workers (default: auto)
  --resume              Resume interrupted run, skip existing outputs
  -v, --verbose         Enable verbose output for debugging
```

## Output Structure

```
app_decompiled/
├── apktool/                    # Decoded resources and smali
│   ├── AndroidManifest.xml     # Decoded manifest
│   ├── res/                    # Decoded resources
│   ├── smali/                  # Smali bytecode
│   └── ...
├── converted/
│   ├── java/                   # Java source code from DEX
│   ├── so_decompiled/          # C pseudocode from native libraries
│   ├── extracted_zips/         # Contents of embedded archives
│   ├── signatures/             # APK signature files
│   ├── certificates/           # Certificate information
│   └── binary_dumps/           # Hex dumps of other binaries
├── xapk_extracted/             # (XAPK only) Extracted split APKs
└── decompilation_report.md     # Summary report
```

## Supported Conversions

| Input | Output | Tool Used |
|-------|--------|-----------|
| `.dex` | Java source | JADX |
| `.so` (ARM/ARM64) | C pseudocode | Ghidra |
| `.so` (fallback) | Strings + metadata | Built-in |
| `AndroidManifest.xml` | Decoded XML | apktool |
| `resources.arsc` | Decoded resources | apktool |
| `.xapk` | Extracted APKs | Built-in |
| `.zip` (embedded) | Extracted contents | Built-in |
| Signatures | Parsed info | Built-in |

## Examples

### Decompile a Simple APK

```bash
python apk_decompiler.py messenger.apk
```

Output:
```
============================================================
APK Full Decompiler
============================================================
Input: messenger.apk
Output: messenger_decompiled

[1/6] Setting up tools...
  Java found: /usr/bin/java
  apktool: downloading...
  jadx: downloading...
  Ghidra: ghidra_11.2.1_PUBLIC

[2/6] Decompiling APK with apktool...
  Decoded AndroidManifest.xml
  Decoded resources

[3/6] Converting to Java source with jadx...
  Converted 15 DEX files -> 25,000 Java files

[4/6] Converting SO files to C pseudocode...
  Decompiled 12 native libraries

[5/6] Converting XRSC files to JSON...
  No XRSC files found

[6/6] Processing other binary files...
  Processed signatures and certificates

============================================================
Decompilation complete!
============================================================
```

### Handle Protected/Encrypted Libraries

Some apps use encrypted native libraries. These will fall back to string extraction:

```
Errors:
- SO import failed (encrypted/packed): libprotected.so
```

This is expected for protected apps. The tool still extracts useful strings and metadata.

## Troubleshooting

### "Java not found"

Ensure Java 11+ is installed and in your PATH:
```bash
java -version
```

### "Ghidra not found"

SO files will use fallback mode (string extraction only). To enable full decompilation:
1. Download Ghidra from https://ghidra-sre.org/
2. Extract to the script directory
3. Re-run the decompiler

### Timeout on Large Files

Large native libraries may timeout. Increase timeout or use `--skip-so`:
```bash
python apk_decompiler.py large_app.apk --skip-so
```

### Permission Denied (Linux/macOS)

```bash
chmod +x apk_decompiler.py
```

## Dependencies

**Python**: Standard library only (no pip packages required)

**External Tools** (auto-downloaded):
- [apktool](https://github.com/iBotPeaches/Apktool) - APK decoding
- [JADX](https://github.com/skylot/jadx) - DEX to Java
- [Ghidra](https://ghidra-sre.org/) - Native library decompilation (optional)

## License

MIT License - see [LICENSE](LICENSE) file.

## Acknowledgments

- [apktool](https://github.com/iBotPeaches/Apktool) by iBotPeaches
- [JADX](https://github.com/skylot/jadx) by skylot
- [Ghidra](https://ghidra-sre.org/) by NSA

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
