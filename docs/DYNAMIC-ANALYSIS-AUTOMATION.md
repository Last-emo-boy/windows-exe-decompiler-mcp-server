# Dynamic Analysis Automation Guide

## Overview

The `workflow.dynamic.analyze` tool now supports automated Frida instrumentation via the `auto_frida` mode. This automation:

1. Analyzes static capabilities to identify suspicious behavior patterns
2. Generates targeted Frida scripts based on detected capabilities
3. Correlates runtime API traces back to specific functions
4. Provides confidence-scored function identification

## Usage

### Basic Usage

```typescript
// Start dynamic analysis with auto_frida mode
const result = await workflow.dynamic.analyze({
  sample_id: 'sha256:abc123...',
  stage: 'trace_capture',
  mode: 'auto_frida',  // Enable automation
  include_correlation: true,
})
```

### Stage Progression

The automated workflow follows these stages:

```
preflight → simulation → trace_capture → correlation → digest
```

**Stage Descriptions:**

1. **preflight**: Check Frida and dynamic analysis dependencies
2. **simulation**: Run safe behavioral simulation (no execution)
3. **trace_capture**: Generate and inject Frida scripts, collect traces
4. **correlation**: Correlate trace events to functions
5. **digest**: Generate compact behavioral summary

### Mode Comparison

| Mode | Execution | Automation | Use Case |
|------|-----------|------------|----------|
| `safe_simulation` | No | Full | Initial behavioral assessment |
| `auto_frida` | Yes (Frida) | Full | Automated deep analysis |
| `live_local` | Yes (Wine) | Manual | Manual dynamic analysis |

## Auto-generated Frida Scripts

The script generator creates targeted monitoring scripts based on detected capabilities:

### Supported Capabilities

- **process_injection**: Monitors `CreateRemoteThread`, `VirtualAllocEx`, `WriteProcessMemory`
- **crypto**: Monitors `CryptEncrypt`, `CryptDecrypt`, `CryptGenKey`
- **persistence**: Monitors registry and service operations
- **network**: Monitors HTTP and socket operations
- **file_operations**: Monitors file creation, modification, deletion

### Example Generated Script

```javascript
// Auto-generated Frida Script
// Capabilities: process_injection, crypto
// APIs monitored: 15

"use strict";

rpc.exports = {
  getTrace: function() {
    return "Trace data available via message events";
  }
};

// Process Injection Monitoring
const injectionApis = ['CreateRemoteThread', 'VirtualAllocEx', 'WriteProcessMemory'];
// ... monitoring code ...

// Crypto Operations Monitoring
const cryptoApis = ['CryptEncrypt', 'CryptDecrypt', 'CryptGenKey'];
// ... monitoring code ...
```

## Correlation Results

The correlation stage maps trace events to functions with confidence scores:

### Example Output

```json
{
  "sample_id": "sha256:abc123...",
  "stage": "correlation",
  "status": "ready",
  "behavior_summary": "Correlated 50 events to 5 functions",
  "capability_tags": ["crypto", "process_manipulation"],
  "correlated_functions": [
    {
      "address": "0x140001000",
      "name": "sub_140001000",
      "api_calls": 25,
      "confidence": 0.85,
      "evidence": ["Matched 25 API calls", "CryptEncrypt", "CryptDecrypt"]
    }
  ],
  "correlation_summary": {
    "uniqueApis": 10,
    "uniqueThreads": 2,
    "timeRangeMs": 1500,
    "topCapabilities": ["crypto", "process_manipulation"]
  }
}
```

### Confidence Scoring

Confidence scores are calculated based on:

- **API match count**: More matching API calls = higher confidence
- **Capability alignment**: Matches with static capabilities = higher confidence
- **Thread consistency**: Consistent thread patterns = higher confidence

Score ranges:
- `0.0-0.3`: Low confidence (few or no matches)
- `0.3-0.6`: Medium confidence (some matches)
- `0.6-0.95`: High confidence (strong matches)

## Error Handling

The automation includes graceful fallback:

```typescript
try {
  const result = await workflow.dynamic.analyze({
    sample_id: 'sha256:abc123...',
    mode: 'auto_frida',
  })
  
  if (result.data.status === 'partial') {
    // Automation failed, use manual mode
    console.log('Fallback to manual Frida instrumentation')
  }
} catch (error) {
  // Handle error
}
```

### Common Issues

| Issue | Cause | Resolution |
|-------|-------|------------|
| Auto Frida failed | Frida not available | Use `mode=safe_simulation` |
| Correlation failed | No function context | Proceed to digest with limited data |
| Script generation failed | No capabilities detected | Check static analysis results |

## Advanced Configuration

### Custom Script Templates

```typescript
const customTemplate = `
// Custom monitoring logic
console.log("Custom template");
`

const script = generateFridaScript(capabilities, {
  customTemplates: [customTemplate],
  maxApis: 100,
  includeStackTrace: true,
})
```

### Script Generation Options

```typescript
interface ScriptGenerationOptions {
  maxApis?: number              // Default: 50
  includeStackTrace?: boolean   // Default: false
  includeArgs?: boolean         // Default: true
  includeReturnValue?: boolean  // Default: true
  customTemplates?: string[]    // Default: []
}
```

## Integration with Other Workflows

### After Dynamic Analysis

```typescript
// Continue to summary
await workflow.summarize({
  sample_id: 'sha256:abc123...',
  through_stage: 'final',
})

// Or continue to reconstruction
await workflow.reconstruct({
  sample_id: 'sha256:abc123...',
  topk: 16,
})
```

### Using Correlation Results

The correlation results can be used to:

1. **Prioritize functions for reverse engineering**: Focus on high-confidence correlated functions
2. **Guide manual analysis**: Use capability tags to understand behavior
3. **Generate reports**: Include correlation summary in final reports

## Best Practices

1. **Start with safe_simulation**: Always run simulation first to understand baseline behavior
2. **Use auto_frida for deep analysis**: When simulation detects suspicious behavior
3. **Review correlation results**: High-confidence functions are good reverse engineering targets
4. **Combine with static analysis**: Use `static.capability.triage` results to validate dynamic findings

## Limitations

- **Anti-analysis evasion**: Samples with anti-Frida checks may fail injection
- **Custom APIs**: Auto-generated scripts focus on common Windows APIs
- **Multi-stage malware**: Current implementation handles single-stage analysis
- **Network monitoring**: Limited to local API calls, not actual network traffic

## Future Enhancements

- [ ] Support for custom script templates from users
- [ ] Multi-stage malware analysis (dropper → loader → payload)
- [ ] Integration with external threat intelligence
- [ ] Real-time trace visualization
- [ ] Automated IOC extraction from traces
