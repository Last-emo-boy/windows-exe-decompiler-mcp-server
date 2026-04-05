# Ghidra Headless Setup Guide

This guide explains how to install and configure Ghidra Headless for use with the Rikune.

## Prerequisites

- Java JDK 17 or higher
- At least 4GB of RAM available for Ghidra analysis
- Disk space: ~500MB for Ghidra installation + workspace for analysis projects

## Installation

### Option 1: Download from Official Website

1. Visit the [Ghidra Releases Page](https://github.com/NationalSecurityAgency/ghidra/releases)
2. Download the latest stable release (≥ 10.0)
3. Extract the archive to your preferred location:
   - **Linux/macOS**: `/opt/ghidra` or `~/ghidra`
   - **Windows**: `C:\ghidra` or `C:\Program Files\ghidra`

### Option 2: Package Manager (Linux)

**Ubuntu/Debian**:
```bash
# Install dependencies
sudo apt-get update
sudo apt-get install openjdk-17-jdk

# Download and extract Ghidra
wget https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_10.4_build/ghidra_10.4_PUBLIC_20230928.zip
unzip ghidra_10.4_PUBLIC_20230928.zip -d /opt/
sudo mv /opt/ghidra_10.4_PUBLIC /opt/ghidra
```

**Arch Linux**:
```bash
yay -S ghidra
```

### Option 3: Homebrew (macOS)

```bash
brew install --cask ghidra
```

## Configuration

### Environment Variable Setup

Set the `GHIDRA_INSTALL_DIR` environment variable to point to your Ghidra installation:

**Linux/macOS** (add to `~/.bashrc` or `~/.zshrc`):
```bash
export GHIDRA_INSTALL_DIR="/opt/ghidra"
```

**Windows** (PowerShell):
```powershell
[System.Environment]::SetEnvironmentVariable('GHIDRA_INSTALL_DIR', 'C:\ghidra', 'User')
```

**Windows** (Command Prompt):
```cmd
setx GHIDRA_INSTALL_DIR "C:\ghidra"
```

### Verify Installation

Run the following command to verify Ghidra is properly installed:

**Linux/macOS**:
```bash
$GHIDRA_INSTALL_DIR/support/analyzeHeadless -help
```

**Windows**:
```cmd
%GHIDRA_INSTALL_DIR%\support\analyzeHeadless.bat -help
```

You should see Ghidra's help output including version information.

## MCP Server Configuration

### Automatic Detection

The MCP Server will automatically detect Ghidra if:
1. `GHIDRA_INSTALL_DIR` environment variable is set, OR
2. Ghidra is installed in a common location:
   - `/opt/ghidra`
   - `/usr/local/ghidra`
   - `C:\Program Files\ghidra`
   - `C:\ghidra`
   - `~/ghidra`

### Manual Configuration

If automatic detection fails, you can manually configure Ghidra in the MCP Server config file:

**config.json**:
```json
{
  "workers": {
    "ghidra": {
      "enabled": true,
      "path": "/path/to/ghidra",
      "maxConcurrent": 4,
      "timeout": 300
    }
  }
}
```

### Configuration Options

- **enabled**: Enable/disable Ghidra worker (default: `false`)
- **path**: Path to Ghidra installation directory
- **maxConcurrent**: Maximum number of concurrent Ghidra analyses (default: `4`)
- **timeout**: Analysis timeout in seconds (default: `300`)

## Testing the Setup

### Test Script

Create a test script to verify Ghidra configuration:

```typescript
import { ghidraConfig } from './src/ghidra-config'

console.log('Ghidra Configuration:')
console.log('  Install Dir:', ghidraConfig.installDir)
console.log('  Analyze Headless:', ghidraConfig.analyzeHeadlessPath)
console.log('  Scripts Dir:', ghidraConfig.scriptsDir)
console.log('  Version:', ghidraConfig.version || 'Unknown')
console.log('  Valid:', ghidraConfig.isValid)
```

Run with:
```bash
npm run build
node -e "import('./dist/ghidra-config.js').then(m => console.log(m.ghidraConfig))"
```

### Test Analysis

Test Ghidra analysis with a sample binary:

```bash
# Using the MCP Server
npm run build
npm start

# In another terminal, use MCP client to test
# (Requires sample binary and MCP client setup)
```

## Troubleshooting

### Issue: "Ghidra installation not found"

**Solution**:
1. Verify `GHIDRA_INSTALL_DIR` is set correctly
2. Check that the path exists and contains Ghidra files
3. Ensure `support/analyzeHeadless` (or `.bat` on Windows) exists

### Issue: "analyzeHeadless script is not executable"

**Solution** (Linux/macOS):
```bash
chmod +x $GHIDRA_INSTALL_DIR/support/analyzeHeadless
```

### Issue: "Java not found" or "JAVA_HOME not set"

**Solution**:
1. Install Java JDK 17 or higher
2. Set `JAVA_HOME` environment variable:
   ```bash
   export JAVA_HOME=/path/to/jdk
   ```

### Issue: Analysis timeout

**Solution**:
1. Increase timeout in configuration:
   ```json
   {
     "workers": {
       "ghidra": {
         "timeout": 600
       }
     }
   }
   ```
2. Or set via environment variable:
   ```bash
   export GHIDRA_TIMEOUT=600
   ```

### Issue: Out of memory during analysis

**Solution**:
1. Increase Java heap size by editing `$GHIDRA_INSTALL_DIR/support/analyzeHeadless`:
   ```bash
   # Find the line with -Xmx and increase the value
   -Xmx4G  # Change to -Xmx8G or higher
   ```
2. Reduce concurrent analyses:
   ```json
   {
     "workers": {
       "ghidra": {
         "maxConcurrent": 2
       }
     }
   }
   ```

### Issue: Script not found

**Solution**:
1. Verify `ghidra_scripts/ExtractFunctions.py` exists
2. Check scripts directory path in logs
3. Ensure script has correct Ghidra metadata comments

## Performance Tuning

### Recommended Settings

For optimal performance:

```json
{
  "workers": {
    "ghidra": {
      "enabled": true,
      "maxConcurrent": 4,
      "timeout": 300
    }
  }
}
```

### Resource Requirements

| Sample Size | Recommended RAM | Typical Analysis Time |
|-------------|----------------|----------------------|
| < 1MB       | 2GB            | 10-30 seconds        |
| 1-5MB       | 4GB            | 30-120 seconds       |
| 5-10MB      | 6GB            | 2-5 minutes          |
| > 10MB      | 8GB+           | 5-15 minutes         |

### Concurrent Analysis

- **Low-end systems** (4GB RAM): `maxConcurrent: 1`
- **Mid-range systems** (8GB RAM): `maxConcurrent: 2`
- **High-end systems** (16GB+ RAM): `maxConcurrent: 4`

## Security Considerations

1. **Isolation**: Ghidra analysis runs in separate processes with no network access
2. **Workspace Isolation**: Each analysis uses a separate Ghidra project directory
3. **Timeout Protection**: Analyses are terminated if they exceed the timeout
4. **Resource Limits**: Concurrent analysis limits prevent resource exhaustion

## Advanced Configuration

### Custom Analysis Options

You can pass custom Ghidra analysis options via the API:

```typescript
{
  "sample_id": "sha256:abc123...",
  "options": {
    "analysisOptions": {
      "Decompiler Parameter ID": "true",
      "Stack": "true"
    }
  }
}
```

### Custom Scripts

Add custom Ghidra scripts to `ghidra_scripts/` directory. See `ghidra_scripts/README.md` for details.

## References

- [Ghidra Official Documentation](https://ghidra.re/)
- [Ghidra Headless Analyzer README](https://ghidra.re/ghidra_docs/analyzeHeadlessREADME.html)
- [Ghidra Installation Guide](https://ghidra.re/InstallationGuide.html)
- [Ghidra API Documentation](https://ghidra.re/ghidra_docs/api/)
