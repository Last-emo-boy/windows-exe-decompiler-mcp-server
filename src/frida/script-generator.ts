/**
 * Frida Script Generator
 * Tasks: dynamic-analysis-automation 1.1-1.4
 */

export interface ScriptGenerationOptions { maxApis?: number; includeStackTrace?: boolean; includeArgs?: boolean; includeReturnValue?: boolean; customTemplates?: string[] }
export interface CapabilityMatch { name: string; confidence: number; apis: string[] }

const SCRIPT_TEMPLATES: Record<string, string> = {
  process_injection: `
const injectionApis = ['CreateRemoteThread', 'VirtualAllocEx', 'WriteProcessMemory'];
injectionApis.forEach(apiName => {
  const addr = Module.findExportByName('kernel32.dll', apiName) || Module.findExportByName('ntdll.dll', apiName);
  if (addr) {
    Interceptor.attach(addr, {
      onEnter: function(args) {
        console.log(JSON.stringify({ type: 'injection', api: apiName, timestamp: Date.now(), thread_id: Process.getCurrentThreadId() }));
      }
    });
  }
});
`,
  crypto: `
const cryptoApis = ['CryptEncrypt', 'CryptDecrypt', 'CryptGenKey'];
cryptoApis.forEach(apiName => {
  const addr = Module.findExportByName('advapi32.dll', apiName);
  if (addr) {
    Interceptor.attach(addr, {
      onEnter: function(args) {
        console.log(JSON.stringify({ type: 'crypto', api: apiName, timestamp: Date.now() }));
      }
    });
  }
});
`,
  persistence: `
const persistenceApis = ['RegSetValueExW', 'RegCreateKeyExW', 'CreateServiceW'];
persistenceApis.forEach(apiName => {
  const addr = Module.findExportByName('advapi32.dll', apiName);
  if (addr) {
    Interceptor.attach(addr, {
      onEnter: function(args) {
        console.log(JSON.stringify({ type: 'persistence', api: apiName, timestamp: Date.now() }));
      }
    });
  }
});
`,
  network: `
const networkApis = ['InternetOpenW', 'InternetConnectW', 'HttpSendRequestW'];
networkApis.forEach(apiName => {
  const addr = Module.findExportByName('wininet.dll', apiName);
  if (addr) {
    Interceptor.attach(addr, {
      onEnter: function(args) {
        console.log(JSON.stringify({ type: 'network', api: apiName, timestamp: Date.now() }));
      }
    });
  }
});
`,
}

const CAPABILITY_TO_TEMPLATE: Record<string, string> = {
  'process_injection': 'process_injection', 'injection': 'process_injection',
  'crypto': 'crypto', 'cryptography': 'crypto',
  'persistence': 'persistence', 'registry': 'persistence', 'service': 'persistence',
  'network': 'network', 'http': 'network', 'c2': 'network', 'command_and_control': 'network',
}

export function generateFridaScript(capabilities: CapabilityMatch[], options: ScriptGenerationOptions = {}): string {
  const { maxApis = 50, customTemplates = [] } = options
  const templateNames = new Set<string>()
  const collectedApis = new Set<string>()
  
  for (const cap of capabilities) {
    if (cap.confidence < 0.5) continue
    const templateName = CAPABILITY_TO_TEMPLATE[cap.name]
    if (templateName) templateNames.add(templateName)
    for (const api of cap.apis) if (collectedApis.size < maxApis) collectedApis.add(api)
  }
  
  let script = `// Auto-generated Frida Script\n// Capabilities: ${Array.from(templateNames).join(', ')}\n// APIs monitored: ${collectedApis.size}\n\n"use strict";\n\nrpc.exports = { getTrace: function() { return "Trace data available via message events"; } };\n\n`
  
  const mergedTemplates = new Set<string>()
  for (const templateName of templateNames) if (SCRIPT_TEMPLATES[templateName]) mergedTemplates.add(SCRIPT_TEMPLATES[templateName])
  for (const customTemplate of customTemplates) mergedTemplates.add(customTemplate)
  
  script += Array.from(mergedTemplates).join('\n\n')
  script += `\n\nconsole.log("Frida script initialized. Monitoring ${collectedApis.size} APIs across ${templateNames.size} capabilities.");\n`
  
  return script
}

export function getAvailableTemplates(): string[] { return Object.keys(SCRIPT_TEMPLATES) }
export function getTemplate(name: string): string | undefined { return SCRIPT_TEMPLATES[name] }
export function addCustomTemplate(name: string, template: string): void { SCRIPT_TEMPLATES[name] = template }
