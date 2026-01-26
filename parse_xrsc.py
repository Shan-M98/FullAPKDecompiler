#!/usr/bin/env python3
"""
Parser for TikTok/ByteDance NxString (.xrsc) localization files
Format: Binary string resource format used by TikTok for i18n
"""

import struct
import sys
import os
import json

def parse_xrsc(filepath):
    """Parse an .xrsc NxString file and extract strings."""
    with open(filepath, 'rb') as f:
        data = f.read()

    result = {
        'file': os.path.basename(filepath),
        'magic': None,
        'version': None,
        'locale': None,
        'string_count': 0,
        'strings': []
    }

    # Check magic header
    if data[:8] != b'NxString':
        print(f"Warning: {filepath} doesn't have NxString magic header")
        # Try to extract readable strings anyway
        strings = extract_readable_strings(data)
        result['strings'] = strings
        return result

    result['magic'] = 'NxString'

    # Parse header (format varies, but basic structure)
    # Byte 8-11: version/flags
    # Byte 12-15: some size info
    # Then locale name (null-terminated)

    pos = 8
    # Read 4 bytes of version/flags
    if len(data) >= pos + 4:
        result['version'] = struct.unpack('<I', data[pos:pos+4])[0]
        pos += 4

    # Read 4 bytes
    if len(data) >= pos + 4:
        pos += 4

    # Read locale name (null-terminated string)
    locale_end = data.find(b'\x00', pos)
    if locale_end > pos:
        result['locale'] = data[pos:locale_end].decode('utf-8', errors='replace')
        pos = locale_end + 1

    # Try to find and extract strings from the data section
    # The format uses an index table followed by string data

    # Look for UTF-8 strings in the remaining data
    strings = extract_readable_strings(data[pos:])
    result['strings'] = strings
    result['string_count'] = len(strings)

    return result

def extract_readable_strings(data, min_length=4):
    """Extract readable ASCII/UTF-8 strings from binary data."""
    strings = []
    current = []

    for byte in data:
        # Check if printable ASCII or common UTF-8
        if 32 <= byte <= 126 or byte in [9, 10, 13]:  # printable + tab/newline
            current.append(chr(byte))
        else:
            if len(current) >= min_length:
                s = ''.join(current).strip()
                if s and not s.isspace():
                    strings.append(s)
            current = []

    # Don't forget last string
    if len(current) >= min_length:
        s = ''.join(current).strip()
        if s and not s.isspace():
            strings.append(s)

    return strings

def main():
    # Fix Windows console encoding
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

    if len(sys.argv) < 2:
        print("Usage: python parse_xrsc.py <file.xrsc> [output.json]")
        print("       python parse_xrsc.py <directory> [output.json]")
        sys.exit(1)

    input_path = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else None

    results = []

    if os.path.isfile(input_path):
        result = parse_xrsc(input_path)
        results.append(result)
        print(f"Parsed: {result['file']}")
        print(f"  Magic: {result['magic']}")
        print(f"  Locale: {result['locale']}")
        print(f"  Strings found: {result['string_count']}")
        if result['strings'][:5]:
            print(f"  Sample strings: {result['strings'][:5]}")

    elif os.path.isdir(input_path):
        for root, dirs, files in os.walk(input_path):
            for fname in files:
                if fname.endswith('.xrsc'):
                    fpath = os.path.join(root, fname)
                    try:
                        result = parse_xrsc(fpath)
                        results.append(result)
                        print(f"Parsed: {fpath} - {result['string_count']} strings")
                    except Exception as e:
                        print(f"Error parsing {fpath}: {e}")

    if output_file:
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        print(f"\nResults saved to: {output_file}")

    return results

if __name__ == '__main__':
    main()
