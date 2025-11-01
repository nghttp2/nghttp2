# Unused Symbols Report

This document lists unused functions, macros, and enums found in the nghttp2 library.

**Analysis Date:** 2025-11-01
**Scope:** Private symbols in `lib/` directory (excluding public API in `lib/includes/nghttp2/`)

## Summary

- **Unused Functions:** 0
- **Unused Macros:** 6
- **Unused Enums:** 2
- **Total Unused Symbols:** 8

## Methodology

The analysis was performed by:
1. Parsing all source files (`.c` and `.h`) in the `lib/` directory
2. Extracting function definitions, macro definitions, and enum declarations
3. Excluding symbols defined in the public API (`lib/includes/nghttp2/nghttp2.h`)
4. Counting references to each symbol across the entire codebase (including `lib/`, `src/`, `examples/`, `tests/`)
5. Identifying symbols that appear only once (in their definition) or have no references beyond their definition

Note: All private functions that were initially detected as potentially unused were found to actually be in use, either:
- In conditional compilation paths (platform-specific code)
- As static helper functions called within the same file
- Through function pointers or callbacks


## Unused Private Macros (6)

| Macro Name | File Location | Description |
|-----------|---------------|-------------|
| `NGHTTP2_PRIORITY_MASK` | lib/nghttp2_frame.h | Mask for priority value, defined but never used |
| `NGHTTP2_PRI_GROUP_ID_MASK` | lib/nghttp2_frame.h | Mask for priority group ID, defined but never used |
| `NGHTTP2_SETTINGS_ID_MASK` | lib/nghttp2_frame.h | Mask for settings ID, defined but never used |
| `SFPARSE_STATE_DICT` | lib/sfparse.c | Parser state constant, defined but only used in macros |
| `SFPARSE_STATE_ITEM` | lib/sfparse.c | Parser state constant, defined but only used in macros |
| `SFPARSE_STATE_LIST` | lib/sfparse.c | Parser state constant, defined but only used in macros |

## Unused Private Enums (2)

| Enum Name | File Location | Description |
|-----------|---------------|-------------|
| `NGHTTP2_ERR_CREDENTIAL_PENDING` | lib/nghttp2_int.h | Error code (-101), defined but never referenced |
| `NGHTTP2_TYPEMASK_NONE` | lib/nghttp2_session.h | Type mask value (0), defined but never referenced |

## Notes

- All symbols listed are **private** (not part of the public API in `lib/includes/nghttp2/`)
- These symbols have only one reference (their definition) in the entire codebase
- The SFPARSE_STATE_* macros are used indirectly through other macros, but the base constants themselves are not directly referenced
- All detected private functions were found to be in active use through various means (conditional compilation, static helpers, callbacks)

## Detailed Findings

### Macros
The unused macros fall into two categories:

1. **Frame header masks** (`NGHTTP2_PRIORITY_MASK`, `NGHTTP2_PRI_GROUP_ID_MASK`, `NGHTTP2_SETTINGS_ID_MASK`): These appear to be leftover definitions from earlier versions or reserved for future use.

2. **Parser state constants** (`SFPARSE_STATE_DICT`, `SFPARSE_STATE_ITEM`, `SFPARSE_STATE_LIST`): While these base constants are defined, they are only used to construct derived macros like `SFPARSE_STATE_LIST_AFTER`. The base constants themselves are never directly referenced.

### Enums
Both unused enum values appear to be reserved for specific features:

1. **NGHTTP2_ERR_CREDENTIAL_PENDING**: Error code -101, possibly reserved for future credential handling features
2. **NGHTTP2_TYPEMASK_NONE**: A zero-value type mask that may have been used historically but is no longer needed

## Recommendations

1. **Review each symbol** to determine if it should be removed or is kept for a specific reason (e.g., future use, compatibility)
2. **Consider adding comments** to explain why symbols are kept if they appear unused but serve a purpose
3. **Remove confirmed unused symbols** to reduce code complexity and maintenance burden
4. **Update documentation** if any symbols were intended for public use but are not actually exposed

## Re-running the Analysis

A Python script is provided to re-run this analysis:

```bash
python3 find_unused_symbols.py
```

This script can be used to verify that unused symbols have been removed or to check for new unused symbols in the future.
