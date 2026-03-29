/**
 * MCP Server implementation
 * Implements the Model Context Protocol with JSON-RPC 2.0 message handling
 */

import { Server } from '@modelcontextprotocol/sdk/server/index.js'
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js'
import {
  CallToolRequestSchema,
  type CallToolResult,
  type ClientCapabilities,
  type CreateMessageRequest,
  type CreateMessageResult,
  type CreateMessageResultWithTools,
  GetPromptRequestSchema,
  type Implementation,
  ListPromptsRequestSchema,
  ListToolsRequestSchema,
  Prompt,
  Tool,
  TextContent,
} from '@modelcontextprotocol/sdk/types.js'
import { z } from 'zod'
import pino from 'pino'
import type { Config } from './config.js'
import type { WorkspaceManager } from './workspace-manager.js'
import type { DatabaseManager } from './database.js'
import type { PolicyGuard } from './policy-guard.js'
import type { StorageManager } from './storage/storage-manager.js'
import type {
  ToolDefinition,
  ToolArgs,
  ToolResult,
  WorkerResult,
  PromptDefinition,
  PromptArgs,
  PromptResult,
} from './types.js'
import { FileServer } from './api/file-server.js'
import { createSampleFinalizationService } from './sample-finalization.js'
import {
  buildToolNameMappings,
  rewriteToolReferencesInText,
  rewriteToolReferencesInValue,
  toTransportToolName,
} from './tool-name-normalization.js'

interface MCPServerDependencies {
  workspaceManager?: WorkspaceManager
  database?: DatabaseManager
  policyGuard?: PolicyGuard
  storageManager?: StorageManager
}

/**
 * Tool handler function type - can return either WorkerResult or ToolResult
 */
type ToolHandler = (args: ToolArgs) => Promise<WorkerResult | ToolResult>
type PromptHandler = (args: PromptArgs) => Promise<PromptResult>

/**
 * MCP Server class implementing the Model Context Protocol
 */
export class MCPServer {
  private server: Server
  private logger: pino.Logger
  private config: Config
  private tools: Map<string, ToolDefinition>
  private canonicalToolDefinitions: Map<string, ToolDefinition>
  private toolAliases: Map<string, string>
  private handlers: Map<string, ToolHandler>
  private prompts: Map<string, PromptDefinition>
  private promptHandlers: Map<string, PromptHandler>
  private httpFileServer: { stop: () => Promise<void> } | null = null
  private dependencies: MCPServerDependencies

  constructor(config: Config, dependencies: MCPServerDependencies = {}) {
    // Create logger that writes to stderr to avoid interfering with MCP protocol on stdout
    const destination = pino.destination({ dest: 2, sync: false }); // fd 2 = stderr

    this.config = config
    this.logger = pino({
      level: config.logging.level,
    }, destination)

    this.tools = new Map()
    this.canonicalToolDefinitions = new Map()
    this.toolAliases = new Map()
    this.handlers = new Map()
    this.prompts = new Map()
    this.promptHandlers = new Map()
    this.dependencies = dependencies

    // Initialize MCP SDK server
    this.server = new Server(
      {
        name: 'windows-exe-decompiler-mcp-server',
        version: '1.0.0-beta.1',
      },
      {
        capabilities: {
          tools: {},
          prompts: {},
        },
      }
    )

    this.setupHandlers()
    this.logger.info('MCP Server initialized')
  }

  /**
   * Setup MCP protocol handlers
   */
  private setupHandlers(): void {
    // Handle tools/list request
    this.server.setRequestHandler(ListToolsRequestSchema, async () => {
      this.logger.debug('Handling tools/list request')
      return {
        tools: await this.listTools(),
      }
    })

    this.server.setRequestHandler(ListPromptsRequestSchema, async () => {
      this.logger.debug('Handling prompts/list request')
      return {
        prompts: await this.listPrompts(),
      }
    })

    this.server.setRequestHandler(GetPromptRequestSchema, async (request) => {
      this.logger.debug({ prompt: request.params.name }, 'Handling prompts/get request')
      return (await this.getPrompt(request.params.name, request.params.arguments || {})) as any
    })

    // Handle tools/call request
    this.server.setRequestHandler(CallToolRequestSchema, async (request) => {
      this.logger.debug({ tool: request.params.name }, 'Handling tools/call request')
      const result = await this.callTool(request.params.name, request.params.arguments || {})
      return result
    })
  }

  /**
   * Register a tool with its definition and handler
   */
  public registerTool(definition: ToolDefinition, handler: ToolHandler): void {
    const canonicalName = definition.name
    const transportName = toTransportToolName(canonicalName)
    const existingTransport = this.tools.get(transportName)

    if (existingTransport && existingTransport.canonicalName !== canonicalName) {
      throw new Error(`Tool name collision while registering ${canonicalName} as ${transportName}`)
    }

    this.logger.info({ tool: canonicalName, transport_tool: transportName }, 'Registering tool')
    this.canonicalToolDefinitions.set(canonicalName, definition)
    this.tools.set(transportName, { ...definition, canonicalName, name: transportName })
    this.toolAliases.set(canonicalName, transportName)
    this.toolAliases.set(transportName, transportName)
    this.handlers.set(transportName, handler)
  }

  /**
   * Register a prompt with its definition and handler
   */
  public registerPrompt(definition: PromptDefinition, handler: PromptHandler): void {
    this.logger.info({ prompt: definition.name }, 'Registering prompt')
    this.prompts.set(definition.name, definition)
    this.promptHandlers.set(definition.name, handler)
  }

  public getToolDefinitions(): ToolDefinition[] {
    return Array.from(this.canonicalToolDefinitions.values())
  }

  public getToolDefinition(name: string): ToolDefinition | undefined {
    const transportName = this.resolveToolName(name)
    if (!transportName) {
      return undefined
    }

    const definition = this.tools.get(transportName)
    if (!definition) {
      return undefined
    }

    return this.canonicalToolDefinitions.get(definition.canonicalName || definition.name)
  }

  public getPromptDefinitions(): PromptDefinition[] {
    return Array.from(this.prompts.values())
  }

  public getPromptDefinition(name: string): PromptDefinition | undefined {
    return this.prompts.get(name)
  }

  /**
   * List all available tools (MCP protocol method)
   */
  public async listTools(): Promise<Tool[]> {
    const tools: Tool[] = []

    for (const [name, definition] of this.tools.entries()) {
      // Convert Zod schema to JSON Schema format for MCP protocol
      const inputSchema = this.zodToJsonSchema(definition.inputSchema)
      const outputSchema = definition.outputSchema
        ? this.zodToJsonSchema(definition.outputSchema)
        : undefined
      
      tools.push({
        name,
        description: definition.description,
        inputSchema: inputSchema as Tool['inputSchema'],
        ...(outputSchema ? { outputSchema: outputSchema as Tool['outputSchema'] } : {}),
      })
    }

    this.logger.debug({ count: tools.length }, 'Listed tools')
    return tools
  }

  /**
   * List all available prompts (MCP protocol method)
   */
  public async listPrompts(): Promise<Prompt[]> {
    const prompts: Prompt[] = []

    for (const [name, definition] of this.prompts.entries()) {
      prompts.push({
        name,
        title: definition.title,
        description: definition.description,
        arguments: definition.arguments?.map((item) => ({
          name: item.name,
          description: item.description,
          required: item.required,
        })),
      })
    }

    this.logger.debug({ count: prompts.length }, 'Listed prompts')
    return prompts
  }

  /**
   * Convert Zod schema to JSON Schema format
   * Basic implementation for common Zod types
   */
  private zodToJsonSchema(schema: z.ZodTypeAny): Record<string, unknown> {
    const converted = this.zodFieldToJsonSchema(schema)
    if (converted && typeof converted === 'object') {
      return converted
    }

    return { type: 'object', properties: {} }
  }

  /**
   * Determine whether a field is required in object schema.
   * Optional/default/catch wrappers should not be marked as required.
   */
  private isFieldRequired(schema: z.ZodTypeAny): boolean {
    if (schema instanceof z.ZodOptional) {
      return false
    }
    if (schema instanceof z.ZodDefault) {
      return false
    }
    if (schema instanceof z.ZodCatch) {
      return false
    }
    if (schema instanceof z.ZodEffects) {
      return this.isFieldRequired(schema._def.schema)
    }
    if (schema instanceof z.ZodNullable) {
      return this.isFieldRequired(schema._def.innerType)
    }
    if (schema instanceof z.ZodBranded) {
      return this.isFieldRequired(schema._def.type)
    }
    if (schema instanceof z.ZodReadonly) {
      return this.isFieldRequired(schema._def.innerType)
    }

    return true
  }

  /**
   * Attach schema description when available.
   */
  private withSchemaMetadata(
    jsonSchema: Record<string, unknown>,
    schema: z.ZodTypeAny
  ): Record<string, unknown> {
    const withDescription = schema.description
      ? {
          ...jsonSchema,
          description: schema.description,
        }
      : jsonSchema

    const guidance = this.getSchemaGuidance(schema)
    if (guidance.length === 0) {
      return withDescription
    }

    return {
      ...withDescription,
      'x-guidance': guidance,
    }
  }

  private getSchemaGuidance(schema: z.ZodTypeAny): string[] {
    if (schema instanceof z.ZodEffects && schema.description) {
      return [schema.description]
    }

    return []
  }

  private applyStringChecks(
    jsonSchema: Record<string, unknown>,
    schema: z.ZodString
  ): Record<string, unknown> {
    const checks = ((schema as any)._def?.checks || []) as Array<Record<string, unknown>>
    const result: Record<string, unknown> = { ...jsonSchema }

    for (const check of checks) {
      switch (check.kind) {
        case 'min':
          result.minLength = check.value
          break
        case 'max':
          result.maxLength = check.value
          break
        case 'email':
          result.format = 'email'
          break
        case 'url':
          result.format = 'uri'
          break
        case 'uuid':
          result.format = 'uuid'
          break
        case 'datetime':
          result.format = 'date-time'
          break
        case 'regex':
          if (check.regex instanceof RegExp) {
            result.pattern = check.regex.source
          }
          break
      }
    }

    return result
  }

  private applyNumberChecks(
    jsonSchema: Record<string, unknown>,
    schema: z.ZodNumber
  ): Record<string, unknown> {
    const checks = ((schema as any)._def?.checks || []) as Array<Record<string, unknown>>
    const result: Record<string, unknown> = { ...jsonSchema }

    for (const check of checks) {
      switch (check.kind) {
        case 'int':
          result.type = 'integer'
          break
        case 'min':
          if (check.inclusive === false) {
            result.exclusiveMinimum = check.value
          } else {
            result.minimum = check.value
          }
          break
        case 'max':
          if (check.inclusive === false) {
            result.exclusiveMaximum = check.value
          } else {
            result.maximum = check.value
          }
          break
        case 'multipleOf':
          result.multipleOf = check.value
          break
      }
    }

    return result
  }

  private applyArrayChecks(
    jsonSchema: Record<string, unknown>,
    schema: z.ZodArray<z.ZodTypeAny>
  ): Record<string, unknown> {
    const def = (schema as any)._def || {}
    return {
      ...jsonSchema,
      ...(def.minLength?.value !== undefined ? { minItems: def.minLength.value } : {}),
      ...(def.maxLength?.value !== undefined ? { maxItems: def.maxLength.value } : {}),
    }
  }

  private isNeverSchema(schema: z.ZodTypeAny): boolean {
    return schema instanceof z.ZodNever
  }

  private normalizeStructuredContent(
    structuredContent: Record<string, unknown> | undefined,
    outputSchema?: z.ZodTypeAny
  ): Record<string, unknown> | undefined {
    if (!structuredContent) {
      return undefined
    }

    if (!outputSchema) {
      return structuredContent
    }

    const parsed = outputSchema.safeParse(structuredContent)
    if (!parsed.success || !parsed.data || typeof parsed.data !== 'object' || Array.isArray(parsed.data)) {
      this.logger.warn(
        {
          issues: parsed.success ? undefined : parsed.error.issues,
        },
        'Structured content did not validate against output schema; omitting structuredContent'
      )
      return undefined
    }

    return parsed.data as Record<string, unknown>
  }

  /**
   * Convert Zod field schema to JSON Schema property
   */
  private zodFieldToJsonSchema(schema: z.ZodTypeAny): Record<string, unknown> {
    // Handle optional
    if (schema instanceof z.ZodOptional) {
      return this.withSchemaMetadata(this.zodFieldToJsonSchema(schema._def.innerType), schema)
    }

    // Handle nullable
    if (schema instanceof z.ZodNullable) {
      const innerSchema = this.zodFieldToJsonSchema(schema._def.innerType)
      return this.withSchemaMetadata({
        anyOf: [innerSchema, { type: 'null' }],
      }, schema)
    }

    // Handle defaults
    if (schema instanceof z.ZodDefault) {
      const innerSchema = this.zodFieldToJsonSchema(schema._def.innerType)
      try {
        return this.withSchemaMetadata({
          ...innerSchema,
          default: schema._def.defaultValue(),
        }, schema)
      } catch {
        return this.withSchemaMetadata(innerSchema, schema)
      }
    }

    // Handle catch fallback values
    if (schema instanceof z.ZodCatch) {
      return this.withSchemaMetadata(this.zodFieldToJsonSchema(schema._def.innerType), schema)
    }

    // Handle effects/transform wrappers
    if (schema instanceof z.ZodEffects) {
      return this.withSchemaMetadata(this.zodFieldToJsonSchema(schema._def.schema), schema)
    }

    // Handle branded types
    if (schema instanceof z.ZodBranded) {
      return this.withSchemaMetadata(this.zodFieldToJsonSchema(schema._def.type), schema)
    }

    // Handle readonly wrapper
    if (schema instanceof z.ZodReadonly) {
      return this.withSchemaMetadata(this.zodFieldToJsonSchema(schema._def.innerType), schema)
    }

    // Handle any/unknown
    if (schema instanceof z.ZodAny || schema instanceof z.ZodUnknown) {
      return this.withSchemaMetadata({}, schema)
    }

    // Handle string
    if (schema instanceof z.ZodString) {
      return this.withSchemaMetadata(this.applyStringChecks({ type: 'string' }, schema), schema)
    }

    // Handle number
    if (schema instanceof z.ZodNumber) {
      return this.withSchemaMetadata(this.applyNumberChecks({ type: 'number' }, schema), schema)
    }

    // Handle boolean
    if (schema instanceof z.ZodBoolean) {
      return this.withSchemaMetadata({ type: 'boolean' }, schema)
    }

    // Handle array
    if (schema instanceof z.ZodArray) {
      return this.withSchemaMetadata(
        this.applyArrayChecks(
          {
            type: 'array',
            items: this.zodFieldToJsonSchema(schema._def.type),
          },
          schema
        ),
        schema
      )
    }

    // Handle enum
    if (schema instanceof z.ZodEnum) {
      return this.withSchemaMetadata({
        type: 'string',
        enum: schema._def.values,
      }, schema)
    }

    // Handle literal
    if (schema instanceof z.ZodLiteral) {
      const literalValue = schema._def.value
      const literalType = literalValue === null ? 'null' : typeof literalValue
      return this.withSchemaMetadata({
        type: literalType,
        const: literalValue,
      }, schema)
    }

    // Handle object
    if (schema instanceof z.ZodObject) {
      const shape = schema.shape as Record<string, z.ZodTypeAny>
      const properties: Record<string, unknown> = {}
      const required: string[] = []

      for (const [key, fieldSchema] of Object.entries(shape)) {
        properties[key] = this.zodFieldToJsonSchema(fieldSchema)
        if (this.isFieldRequired(fieldSchema)) {
          required.push(key)
        }
      }

      const catchall = (schema as any)._def?.catchall as z.ZodTypeAny | undefined
      const unknownKeys = (schema as any)._def?.unknownKeys as string | undefined

      return this.withSchemaMetadata(
        {
          type: 'object',
          properties,
          ...(required.length > 0 ? { required } : {}),
          ...(
            catchall && !this.isNeverSchema(catchall)
              ? { additionalProperties: this.zodFieldToJsonSchema(catchall) }
              : unknownKeys === 'passthrough'
                ? { additionalProperties: true }
                : { additionalProperties: false }
          ),
        },
        schema
      )
    }

    // Handle union
    if (schema instanceof z.ZodUnion) {
      const options = schema._def.options as z.ZodTypeAny[]
      return this.withSchemaMetadata({
        anyOf: options.map((option) => this.zodFieldToJsonSchema(option)),
      }, schema)
    }

    // Handle discriminated union
    if (schema instanceof z.ZodDiscriminatedUnion) {
      const options = Array.from(schema.options.values()) as z.ZodTypeAny[]
      return this.withSchemaMetadata({
        anyOf: options.map((option) => this.zodFieldToJsonSchema(option)),
      }, schema)
    }

    // Handle record
    if (schema instanceof z.ZodRecord) {
      return this.withSchemaMetadata({
        type: 'object',
        additionalProperties: this.zodFieldToJsonSchema(schema._def.valueType),
      }, schema)
    }

    // Handle tuple
    if (schema instanceof z.ZodTuple) {
      return this.withSchemaMetadata({
        type: 'array',
        items: schema._def.items.map((item: z.ZodTypeAny) => this.zodFieldToJsonSchema(item)),
      }, schema)
    }

    // Default
    return this.withSchemaMetadata({ type: 'string' }, schema)
  }

  /**
   * Call a tool by name with arguments (MCP protocol method)
   */
  public async callTool(name: string, args: unknown): Promise<CallToolResult> {
    const startTime = Date.now()
    this.logger.info({ tool: name, args }, 'Calling tool')

    try {
      const resolvedName = this.resolveToolName(name)

      // Check if tool exists
      const definition = resolvedName ? this.tools.get(resolvedName) : undefined
      if (!definition) {
        throw new Error(`Tool not found: ${name}`)
      }

      // Validate input arguments
      const validatedArgs = this.validateArgs(definition.inputSchema, args)

      // Get handler
      const handler = this.handlers.get(resolvedName)
      if (!handler) {
        throw new Error(`Handler not found for tool: ${name}`)
      }

      // Execute handler
      const result = await handler(validatedArgs)

      const elapsed = Date.now() - startTime
      
      // Check if result is ToolResult or WorkerResult
      if ('content' in result) {
        // It's a ToolResult - use directly
        const structuredContent = this.normalizeStructuredContent(
          this.rewriteToolReferences(result.structuredContent),
          definition.outputSchema
        )
        this.logger.info({ tool: name, elapsed, isError: result.isError }, 'Tool execution completed')
        return {
          content: this.rewriteTextContentItems(result.content as TextContent[]) as any, // MCP SDK Content type
          structuredContent,
          isError: result.isError
        }
      } else {
        // It's a WorkerResult - convert to ToolResult
        this.logger.info({ tool: name, elapsed, ok: result.ok }, 'Tool execution completed')
        return this.workerResultToToolResult(result, definition.outputSchema)
      }
    } catch (error) {
      const elapsed = Date.now() - startTime
      this.logger.error({ tool: name, elapsed, error }, 'Tool execution failed')

      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify({
              ok: false,
              errors: [(error as Error).message],
            }),
          },
        ],
        isError: true,
      }
    }
  }

  /**
   * Resolve a prompt by name and arguments (MCP protocol method)
   */
  public async getPrompt(name: string, args: Record<string, unknown>): Promise<PromptResult> {
    const definition = this.prompts.get(name)
    if (!definition) {
      throw new Error(`Prompt not found: ${name}`)
    }

    const handler = this.promptHandlers.get(name)
    if (!handler) {
      throw new Error(`Handler not found for prompt: ${name}`)
    }

    const validatedArgs = this.validatePromptArgs(definition, args)
    return handler(validatedArgs)
  }

  private validatePromptArgs(
    definition: PromptDefinition,
    args: Record<string, unknown>
  ): PromptArgs {
    const validated: PromptArgs = {}
    const provided = args || {}

    for (const [key, value] of Object.entries(provided)) {
      if (value === undefined || value === null) {
        continue
      }
      validated[key] = String(value)
    }

    for (const item of definition.arguments || []) {
      if (item.required && (!validated[item.name] || validated[item.name].trim().length === 0)) {
        throw new Error(`Missing required prompt argument: ${item.name}`)
      }
    }

    return validated
  }

  /**
   * Validate tool arguments against schema
   * Provides clear error messages with field paths and validation details
   */
  private validateArgs(schema: z.ZodTypeAny, args: unknown): ToolArgs {
    try {
      return schema.parse(args) as ToolArgs
    } catch (error) {
      if (error instanceof z.ZodError) {
        // Build detailed validation error message
        const errorDetails = error.errors.map((e) => {
          const path = e.path.length > 0 ? e.path.join('.') : 'root'
          return `  - ${path}: ${e.message}`
        })

        // Generate example based on schema
        const example = this.generateSchemaExample(schema)
        const exampleStr = example ? `\n\nExample:\n${JSON.stringify(example, null, 2)}` : ''

        throw new Error(
          `Invalid arguments:\n${errorDetails.join('\n')}${exampleStr}`
        )
      }
      throw error
    }
  }

  /**
   * Generate an example object from a Zod schema
   * Helps users understand the expected input format
   */
  private generateSchemaExample(schema: z.ZodTypeAny): Record<string, unknown> | null {
    try {
      if (schema instanceof z.ZodEffects) {
        return this.generateSchemaExample(schema._def.schema)
      }
      if (schema instanceof z.ZodOptional || schema instanceof z.ZodNullable || schema instanceof z.ZodCatch) {
        return this.generateSchemaExample(schema._def.innerType)
      }
      if (schema instanceof z.ZodDefault) {
        return this.generateSchemaExample(schema._def.innerType)
      }
      if (schema instanceof z.ZodBranded) {
        return this.generateSchemaExample(schema._def.type)
      }
      if (schema instanceof z.ZodReadonly) {
        return this.generateSchemaExample(schema._def.innerType)
      }

      // Handle ZodObject
      if (schema instanceof z.ZodObject) {
        const shape = schema.shape as Record<string, z.ZodTypeAny>
        const example: Record<string, unknown> = {}

        for (const [key, fieldSchema] of Object.entries(shape)) {
          example[key] = this.generateFieldExample(fieldSchema)
        }

        return example
      }

      return null
    } catch {
      return null
    }
  }

  /**
   * Generate an example value for a specific field schema
   */
  private generateFieldExample(schema: z.ZodTypeAny): unknown {
    // Handle optional fields
    if (schema instanceof z.ZodOptional) {
      return this.generateFieldExample(schema._def.innerType)
    }

    // Handle nullable fields
    if (schema instanceof z.ZodNullable) {
      return this.generateFieldExample(schema._def.innerType)
    }

    // Handle default values
    if (schema instanceof z.ZodDefault) {
      return schema._def.defaultValue()
    }

    if (schema instanceof z.ZodCatch) {
      return this.generateFieldExample(schema._def.innerType)
    }

    if (schema instanceof z.ZodEffects) {
      return this.generateFieldExample(schema._def.schema)
    }

    if (schema instanceof z.ZodBranded) {
      return this.generateFieldExample(schema._def.type)
    }

    if (schema instanceof z.ZodReadonly) {
      return this.generateFieldExample(schema._def.innerType)
    }

    // Handle string
    if (schema instanceof z.ZodString) {
      return 'string'
    }

    // Handle number
    if (schema instanceof z.ZodNumber) {
      return 0
    }

    // Handle boolean
    if (schema instanceof z.ZodBoolean) {
      return true
    }

    // Handle array
    if (schema instanceof z.ZodArray) {
      const elementExample = this.generateFieldExample(schema._def.type)
      return [elementExample]
    }

    // Handle object
    if (schema instanceof z.ZodObject) {
      const shape = schema.shape as Record<string, z.ZodTypeAny>
      const example: Record<string, unknown> = {}
      for (const [key, fieldSchema] of Object.entries(shape)) {
        example[key] = this.generateFieldExample(fieldSchema)
      }
      return example
    }

    // Handle enum
    if (schema instanceof z.ZodEnum) {
      const values = schema._def.values as string[]
      return values[0]
    }

    // Handle literal
    if (schema instanceof z.ZodLiteral) {
      return schema._def.value
    }

    // Handle union
    if (schema instanceof z.ZodUnion) {
      const options = schema._def.options as z.ZodTypeAny[]
      return this.generateFieldExample(options[0])
    }

    // Default fallback
    return 'value'
  }

  /**
   * Convert worker result to MCP tool result
   */
  private workerResultToToolResult(result: WorkerResult, outputSchema?: z.ZodTypeAny): CallToolResult {
    const content: TextContent[] = []
    const structuredPayload = this.rewriteToolReferences<Record<string, unknown>>({
      ok: result.ok,
      ...(result.data !== undefined ? { data: result.data } : {}),
      ...(result.warnings !== undefined ? { warnings: result.warnings } : {}),
      ...(result.errors !== undefined ? { errors: result.errors } : {}),
      ...(result.artifacts !== undefined ? { artifacts: result.artifacts } : {}),
      ...(result.metrics !== undefined ? { metrics: result.metrics } : {}),
      ...(result.setup_actions !== undefined ? { setup_actions: result.setup_actions } : {}),
      ...(result.required_user_inputs !== undefined
        ? { required_user_inputs: result.required_user_inputs }
        : {}),
    })

    // Add text representation
    content.push({
      type: 'text',
      text: JSON.stringify(structuredPayload),
    })

    return {
      content,
      structuredContent: this.normalizeStructuredContent(structuredPayload, outputSchema),
      isError: !result.ok,
    }
  }

  /**
   * Start the MCP server with stdio transport
   */
  public async start(): Promise<void> {
    this.logger.info('Starting MCP Server with stdio transport')

    const transport = new StdioServerTransport()
    await this.server.connect(transport)

    this.logger.info('MCP Server started and listening on stdio')

    // Start HTTP File Server if enabled
    if (this.config.api?.enabled) {
      try {
        await this.startHttpFileServer()
      } catch (error) {
        this.logger.error('Failed to start HTTP File Server: ' + JSON.stringify(error))
      }
    }
  }

  /**
   * Start HTTP File Server
   */
  private async startHttpFileServer(): Promise<void> {
    const workspaceManager =
      this.dependencies.workspaceManager ||
      new (await import('./workspace-manager.js')).WorkspaceManager(this.config.workspace.root)
    const database =
      this.dependencies.database ||
      new (await import('./database.js')).DatabaseManager(this.config.database.path)
    const policyGuard =
      this.dependencies.policyGuard ||
      new (await import('./policy-guard.js')).PolicyGuard(this.config.logging.auditPath)
    const storageManager =
      this.dependencies.storageManager ||
      new (await import('./storage/storage-manager.js')).StorageManager({
        root: this.config.api.storageRoot,
        maxFileSize: this.config.api.maxFileSize,
        retentionDays: this.config.api.retentionDays,
      })

    await storageManager.initialize()

    const finalizationService = createSampleFinalizationService(
      workspaceManager,
      database,
      policyGuard
    )

    const fileServer = new FileServer(
      {
        port: this.config.api.port || 18080,
        apiKey: this.config.api.apiKey,
        maxFileSize: this.config.api.maxFileSize || 500 * 1024 * 1024,
      },
      {
        storageManager,
        database,
        workspaceManager,
        finalizationService,
      }
    )

    await fileServer.start()
    this.httpFileServer = fileServer
    this.logger.info(`HTTP File Server started on port ${fileServer.getPort()}`)
  }

  /**
   * Stop the MCP server
   */
  public async stop(): Promise<void> {
    this.logger.info('Stopping MCP Server')
    if (this.httpFileServer) {
      await this.httpFileServer.stop()
      this.httpFileServer = null
    }
    await this.server.close()
    this.logger.info('MCP Server stopped')
  }

  /**
   * Get server instance for testing
   */
  public getServer(): Server {
    return this.server
  }

  /**
   * Get connected client capabilities after MCP initialization.
   */
  public getClientCapabilities(): ClientCapabilities | undefined {
    return this.server.getClientCapabilities()
  }

  /**
   * Get connected client implementation info after MCP initialization.
   */
  public getClientVersion(): Implementation | undefined {
    return this.server.getClientVersion()
  }

  /**
   * Whether the connected MCP client advertised sampling support.
   */
  public supportsSampling(): boolean {
    return Boolean(this.getClientCapabilities()?.sampling)
  }

  /**
   * Request client-mediated MCP sampling from the connected client.
   */
  public async createMessage(
    params: CreateMessageRequest['params']
  ): Promise<CreateMessageResult | CreateMessageResultWithTools> {
    return this.server.createMessage(params)
  }

  /**
   * Get logger instance
   */
  public getLogger(): pino.Logger {
    return this.logger
  }

  private resolveToolName(name: string): string | undefined {
    return this.toolAliases.get(name)
  }

  private getToolNameMappings(): Array<[string, string]> {
    return buildToolNameMappings(this.canonicalToolDefinitions.keys())
  }

  private rewriteToolReferences<T>(value: T): T {
    return rewriteToolReferencesInValue(value, this.getToolNameMappings())
  }

  private rewriteTextContentItems(content: TextContent[]): TextContent[] {
    const mappings = this.getToolNameMappings()
    return content.map((item) => {
      if ('text' in item && typeof item.text === 'string') {
        return {
          ...item,
          text: rewriteToolReferencesInText(item.text, mappings),
        }
      }

      return item
    })
  }
}
