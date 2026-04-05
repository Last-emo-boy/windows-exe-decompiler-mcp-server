# Ghidra Scripts

This directory contains custom Ghidra scripts used by the Rikune for automated binary analysis.

## Scripts

### ExtractFunctions.py

**Purpose**: Extracts function information from analyzed binaries and outputs as JSON.

**Category**: Analysis

**Description**: This script is executed as a post-analysis script by Ghidra Headless to extract comprehensive function information including:
- Function addresses and names
- Function sizes
- Calling conventions and signatures
- Caller and callee relationships
- Entry point and export status
- Thunk and external function detection

**Output Format**: JSON with the following structure:

```json
{
  "program_name": "sample.exe",
  "program_path": "/path/to/sample.exe",
  "function_count": 150,
  "functions": [
    {
      "address": "0x00401000",
      "name": "main",
      "size": 256,
      "is_thunk": false,
      "is_external": false,
      "calling_convention": "__cdecl",
      "signature": "int main(int argc, char** argv)",
      "callers": [
        {"address": "0x00401500", "name": "_start"}
      ],
      "caller_count": 1,
      "callees": [
        {"address": "0x00402000", "name": "printf"}
      ],
      "callee_count": 1,
      "is_entry_point": true,
      "is_exported": false
    }
  ]
}
```

**Usage**: This script is automatically invoked by the Decompiler Worker when running Ghidra Headless analysis:

```bash
analyzeHeadless <project_path> <project_name> \
  -import <sample_path> \
  -scriptPath <scripts_dir> \
  -postScript ExtractFunctions.py
```

**Requirements**:
- Ghidra 10.0 or higher
- Python 2.7 (Jython, included with Ghidra)

### ExtractFunctions.java

**Purpose**: Java fallback for function extraction when Python runtime/PyGhidra is unavailable.

**Category**: Analysis

**Description**: Produces the same JSON schema as `ExtractFunctions.py` and is used automatically by
the decompiler worker if Python post-scripts fail with PyGhidra availability errors.

## Adding Custom Scripts

To add custom Ghidra scripts:

1. Create a new `.py` file in this directory
2. Add the required Ghidra script metadata comments:
   ```python
   # @category <Category>
   # @description <Description>
   ```
3. Import required Ghidra modules
4. Implement your analysis logic
5. Output results (typically as JSON to stdout)

## Configuration

The scripts directory path is configured in the Ghidra configuration module (`src/ghidra-config.ts`). By default, it uses `./ghidra_scripts` relative to the project root.

You can override this by:
- Setting the `GHIDRA_SCRIPTS_DIR` environment variable
- Modifying the configuration in `src/config.ts`

## Troubleshooting

### Script Not Found

If Ghidra reports that a script cannot be found:
1. Verify the script exists in this directory
2. Check that the `-scriptPath` parameter points to this directory
3. Ensure the script has the correct file extension (`.py`)

### Script Execution Errors

If a script fails during execution:
1. Check the Ghidra Headless output for error messages
2. Verify the script syntax is correct
3. Ensure all required Ghidra modules are imported
4. Test the script manually in Ghidra GUI's Script Manager

### JSON Output Issues

If JSON output is malformed:
1. Ensure all string values are properly escaped
2. Check for print statements that might interfere with JSON output
3. Verify the script uses `json.dumps()` for serialization
4. Redirect error messages to stderr instead of stdout

## References

- [Ghidra Scripting Documentation](https://ghidra.re/ghidra_docs/api/ghidra/app/script/GhidraScript.html)
- [Ghidra Headless Analyzer](https://ghidra.re/ghidra_docs/analyzeHeadlessREADME.html)
- [Ghidra Python API](https://ghidra.re/ghidra_docs/api/)
