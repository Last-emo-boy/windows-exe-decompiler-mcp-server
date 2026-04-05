# Integration Tests

This directory contains integration tests that verify end-to-end functionality of the Rikune.

## Test Files

### triage-workflow.test.ts

Integration tests for the quick triage workflow (Task 9.3).

**Requirements Tested:**
- 15.3: Workflow completes within 5 minutes
- 26.7: Performance metrics are collected
- 15.2: Report format is correct
- 15.5: IOCs are detected

**Test Cases:**
1. **should complete triage workflow within 5 minutes** - Verifies the workflow meets the 5-minute performance requirement
2. **should generate complete report structure** - Validates the report format includes all required fields (summary, confidence, threat_level, iocs, evidence, recommendation)
3. **should detect suspicious strings in sample** - Tests IOC detection for URLs, IPs, file paths, and registry keys
4. **should handle multiple samples concurrently** - Verifies concurrent execution without interference
5. **should provide appropriate threat assessment** - Tests threat level calculation and confidence scoring
6. **should include performance metrics** - Validates metrics collection
7. **should handle partial tool failures gracefully** - Tests resilience when some analysis tools fail
8. **should cache results for repeated analysis** - Verifies caching improves performance on repeated runs

## Setup Requirements

### Prerequisites

1. **Node.js**: Version 18 or later (Note: Node.js 24 may have compatibility issues with better-sqlite3)
2. **Python**: Version 3.9 or later with required packages
3. **Build Tools**: Required for compiling native modules
   - Windows: Visual Studio Build Tools or Visual Studio with C++ development tools
   - Linux: gcc, g++, make
   - macOS: Xcode Command Line Tools

### Installing Dependencies

```bash
# Install Node.js dependencies
npm install

# Rebuild native modules (if needed)
npm rebuild better-sqlite3

# Install Python dependencies
cd workers
pip install -r requirements.txt
```

### Known Issues

#### better-sqlite3 Native Module

The `better-sqlite3` package requires native compilation. If you encounter errors like:

```
Could not locate the bindings file
```

This means the native module is not properly compiled. Solutions:

1. **Rebuild the module:**
   ```bash
   npm rebuild better-sqlite3
   ```

2. **Use a compatible Node.js version:**
   - Node.js 18 LTS is recommended
   - Node.js 24 may have compatibility issues

3. **Install build tools:**
   - Windows: Install Visual Studio Build Tools with C++ support
   - Ensure Python is available in PATH

4. **Use prebuilt binaries:**
   ```bash
   npm install --build-from-source=false
   ```

## Running Tests

### Run All Integration Tests

```bash
npm test -- tests/integration/
```

### Run Specific Test File

```bash
npm test -- tests/integration/triage-workflow.test.ts
```

### Run with Verbose Output

```bash
npm test -- tests/integration/triage-workflow.test.ts --verbose
```

### Run with Extended Timeout

Some integration tests may take several minutes to complete:

```bash
npm test -- tests/integration/triage-workflow.test.ts --testTimeout=600000
```

## Test Data

The integration tests create minimal PE files programmatically for testing. No external test samples are required.

### Minimal PE Structure

Tests use helper functions to create valid PE files:
- `createMinimalPE()`: Creates a basic valid PE file
- `createSuspiciousPE()`: Creates a PE with suspicious strings for IOC detection

## Performance Expectations

- **Triage workflow**: Should complete in < 5 minutes (Requirement 15.3)
- **Individual tools**: Vary based on sample size and complexity
- **Concurrent execution**: Multiple workflows can run simultaneously

## Troubleshooting

### Tests Timeout

If tests timeout, check:
1. Python worker is properly installed and accessible
2. YARA rules are available in `workers/yara_rules/`
3. System has sufficient resources (CPU, memory)

### Database Errors

If you see SQLite errors:
1. Ensure write permissions in test directories
2. Check that no other process is locking the database
3. Verify better-sqlite3 is properly installed

### Worker Communication Errors

If Python worker communication fails:
1. Verify Python is in PATH
2. Check that `workers/static_worker.py` is executable
3. Ensure all Python dependencies are installed

## CI/CD Considerations

For continuous integration:

1. **Pre-install native modules:**
   ```yaml
   - name: Install dependencies
     run: |
       npm ci
       npm rebuild better-sqlite3
   ```

2. **Use appropriate Node.js version:**
   ```yaml
   - uses: actions/setup-node@v3
     with:
       node-version: '18'
   ```

3. **Install Python dependencies:**
   ```yaml
   - uses: actions/setup-python@v4
     with:
       python-version: '3.9'
   - run: pip install -r workers/requirements.txt
   ```

4. **Set appropriate timeouts:**
   ```yaml
   - name: Run integration tests
     run: npm test -- tests/integration/ --testTimeout=600000
     timeout-minutes: 15
   ```

## Contributing

When adding new integration tests:

1. Follow the existing test structure
2. Use descriptive test names
3. Include requirement references in comments
4. Set appropriate timeouts for long-running tests
5. Clean up resources in `afterAll` hooks
6. Document any special setup requirements

## References

- Requirements: `.kiro/specs/rikune/requirements.md`
- Design: `.kiro/specs/rikune/design.md`
- Tasks: `.kiro/specs/rikune/tasks.md`
