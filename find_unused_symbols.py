#!/usr/bin/env python3
"""
Find unused functions, macros, and enums in the nghttp2 library.
Excludes symbols defined in lib/includes/nghttp2/ (public API).

Usage:
    python3 find_unused_symbols.py

This script analyzes the nghttp2 library source code to find private symbols
(functions, macros, enums) that are defined but never used. It excludes symbols
that are part of the public API.
"""

import os
import re
import sys
from pathlib import Path


def get_lib_files(lib_dir):
    """Get all .c and .h files in lib directory, excluding public headers."""
    files = []
    public_dir = os.path.join(lib_dir, 'includes', 'nghttp2')
    
    for root, dirs, filenames in os.walk(lib_dir):
        if os.path.abspath(root).startswith(os.path.abspath(public_dir)):
            continue
            
        for filename in filenames:
            if filename.endswith(('.c', '.h')):
                files.append(os.path.join(root, filename))
    
    return files


def get_all_project_files(base_dir):
    """Get all source files in the entire project."""
    files = []
    
    for root, dirs, filenames in os.walk(base_dir):
        if '.git' in root or 'build' in root:
            continue
            
        for filename in filenames:
            if filename.endswith(('.c', '.h', '.cc', '.cpp')):
                files.append(os.path.join(root, filename))
    
    return files


def get_public_api_symbols(public_header):
    """Extract all symbols from the public API header."""
    symbols = set()
    
    if not os.path.exists(public_header):
        return symbols
    
    with open(public_header, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()
    
    # Remove comments
    content = re.sub(r'/\*.*?\*/', '', content, flags=re.DOTALL)
    content = re.sub(r'//.*?$', '', content, flags=re.MULTILINE)
    
    # Extract all symbols that look like functions, types, macros, enums
    for match in re.finditer(r'\b([a-zA-Z_][a-zA-Z0-9_]*)\b', content):
        name = match.group(1)
        if name.startswith('nghttp2_') or name.startswith('NGHTTP2_') or name.startswith('sfparse_'):
            symbols.add(name)
    
    return symbols


def extract_definitions(filepath):
    """Extract function, macro, and enum definitions from a file."""
    functions = {}
    macros = {}
    enums = {}
    
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()
    
    no_comments = re.sub(r'/\*.*?\*/', '', content, flags=re.DOTALL)
    no_comments = re.sub(r'//.*?$', '', no_comments, flags=re.MULTILINE)
    
    # Extract function definitions
    func_pattern = r'\b(?:static\s+)?(?:inline\s+|STIN\s+)?(?:const\s+)?([a-zA-Z_][a-zA-Z0-9_*\s]+)\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\([^)]*\)\s*\{'
    for match in re.finditer(func_pattern, no_comments):
        func_name = match.group(2).strip()
        if func_name not in ['if', 'for', 'while', 'switch', 'main']:
            functions[func_name] = filepath
    
    # Extract macros (uppercase convention only - lowercase macros not detected)
    # This is intentional to focus on constant-like macros and avoid false positives
    macro_pattern = r'^\s*#define\s+([A-Z_][A-Z0-9_]*)'
    for match in re.finditer(macro_pattern, content, re.MULTILINE):
        macro_name = match.group(1)
        if not (macro_name.endswith('_H') or macro_name.endswith('_H_')):
            macros[macro_name] = filepath
    
    # Extract enum type names and members
    enum_pattern = r'(?:typedef\s+)?enum\s+([a-zA-Z_][a-zA-Z0-9_]*)'
    for match in re.finditer(enum_pattern, no_comments):
        enums[match.group(1)] = filepath
    
    enum_member_pattern = r'(?:typedef\s+)?enum\s*(?:[a-zA-Z_][a-zA-Z0-9_]*)?\s*\{([^}]+)\}'
    for match in re.finditer(enum_member_pattern, no_comments, re.DOTALL):
        members = match.group(1)
        for member in re.finditer(r'\b([A-Z_][A-Z0-9_]*)\s*(?:=|,|(?=\}))', members):
            member_name = member.group(1)
            if member_name not in ['INT32_MIN', 'INT32_MAX', 'UINT32_MAX']:
                enums[member_name] = filepath
    
    return functions, macros, enums


def count_symbol_usage(files, symbol, is_macro=False):
    """Count how many times a symbol is referenced.
    
    Note: This function uses simple pattern matching and may not detect all
    forms of indirect usage, such as macro token concatenation (##NAME).
    """
    count = 0
    
    for filepath in files:
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except (IOError, OSError):
            continue
        
        # Remove comments
        no_comments = re.sub(r'/\*.*?\*/', '', content, flags=re.DOTALL)
        no_comments = re.sub(r'//.*?$', '', no_comments, flags=re.MULTILINE)
        
        if is_macro:
            # For macros, check various uses
            patterns = [
                r'#\s*if(?:n?def)?\s+' + re.escape(symbol) + r'\b',
                r'#\s*if\s+.*\bdefined\s*\(\s*' + re.escape(symbol) + r'\s*\)',
                r'\b' + re.escape(symbol) + r'\b',
            ]
            
            for pattern in patterns:
                count += len(re.findall(pattern, no_comments))
        else:
            # For functions/enums, count occurrences
            pattern = r'\b' + re.escape(symbol) + r'\b'
            count += len(re.findall(pattern, no_comments))
    
    return count


def main():
    # Determine base directory (script location or current directory)
    script_dir = Path(__file__).parent.absolute()
    if (script_dir / 'lib').exists():
        base_dir = str(script_dir)
    else:
        base_dir = os.getcwd()
    
    lib_dir = os.path.join(base_dir, 'lib')
    public_header = os.path.join(lib_dir, 'includes', 'nghttp2', 'nghttp2.h')
    
    if not os.path.exists(lib_dir):
        print(f"Error: lib directory not found at {lib_dir}")
        print("Please run this script from the nghttp2 repository root")
        return 1
    
    print("Analyzing nghttp2 for unused private symbols...")
    print("=" * 70)
    
    lib_files = get_lib_files(lib_dir)
    all_files = get_all_project_files(base_dir)
    
    print(f"Found {len(lib_files)} library source files (excluding public headers)")
    print(f"Found {len(all_files)} total source files in project")
    
    public_symbols = get_public_api_symbols(public_header)
    print(f"Found {len(public_symbols)} public API symbols")
    
    all_functions = {}
    all_macros = {}
    all_enums = {}
    
    for filepath in lib_files:
        functions, macros, enums = extract_definitions(filepath)
        all_functions.update(functions)
        all_macros.update(macros)
        all_enums.update(enums)
    
    private_functions = {k: v for k, v in all_functions.items() if k not in public_symbols}
    private_macros = {k: v for k, v in all_macros.items() if k not in public_symbols}
    private_enums = {k: v for k, v in all_enums.items() if k not in public_symbols}
    
    print(f"\nFound {len(private_functions)} private function definitions")
    print(f"Found {len(private_macros)} private macro definitions")
    print(f"Found {len(private_enums)} private enum definitions/members")
    
    unused_functions = []
    unused_macros = []
    unused_enums = []
    
    print("\nChecking for unused private functions...")
    for i, (func, filepath) in enumerate(sorted(private_functions.items())):
        if (i + 1) % 50 == 0:
            print(f"  Checked {i + 1}/{len(private_functions)}...")
        usage_count = count_symbol_usage(all_files, func, is_macro=False)
        # If symbol appears only once (its definition), it's unused
        if usage_count <= 1:
            unused_functions.append((func, filepath, usage_count))
    
    print("Checking for unused private macros...")
    for i, (macro, filepath) in enumerate(sorted(private_macros.items())):
        usage_count = count_symbol_usage(all_files, macro, is_macro=True)
        # Macros often appear twice (definition + possible use in #ifdef)
        if usage_count <= 1:
            unused_macros.append((macro, filepath, usage_count))
    
    print("Checking for unused private enums...")
    for i, (enum, filepath) in enumerate(sorted(private_enums.items())):
        if (i + 1) % 50 == 0:
            print(f"  Checked {i + 1}/{len(private_enums)}...")
        usage_count = count_symbol_usage(all_files, enum, is_macro=False)
        if usage_count <= 1:
            unused_enums.append((enum, filepath, usage_count))
    
    # Print results
    print("\n" + "=" * 70)
    print("RESULTS")
    print("=" * 70)
    
    if unused_functions:
        print(f"\nUnused Private Functions ({len(unused_functions)}):")
        for func, filepath, count in sorted(unused_functions):
            rel_path = os.path.relpath(filepath, base_dir)
            print(f"  - {func:50s} in {rel_path} (refs: {count})")
    
    if unused_macros:
        print(f"\nUnused Private Macros ({len(unused_macros)}):")
        for macro, filepath, count in sorted(unused_macros):
            rel_path = os.path.relpath(filepath, base_dir)
            print(f"  - {macro:50s} in {rel_path} (refs: {count})")
    
    if unused_enums:
        print(f"\nUnused Private Enums ({len(unused_enums)}):")
        for enum, filepath, count in sorted(unused_enums):
            rel_path = os.path.relpath(filepath, base_dir)
            print(f"  - {enum:50s} in {rel_path} (refs: {count})")
    
    if not unused_functions and not unused_macros and not unused_enums:
        print("\nNo unused private symbols found!")
    else:
        print(f"\nTotal: {len(unused_functions)} functions, {len(unused_macros)} macros, {len(unused_enums)} enums")
        print("\nNote: This analysis uses simple pattern matching and may not detect:")
        print("  - Macro token concatenation (e.g., ##NAME in macro expansions)")
        print("  - Function pointers passed through complex call chains")
        print("  - Symbols used only in platform-specific conditional compilation")
        print("\nManual verification is recommended before removing any symbols.")
    
    return 0


if __name__ == '__main__':
    sys.exit(main())
