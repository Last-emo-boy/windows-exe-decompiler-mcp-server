/**
 * MCP Server implementation
 * Implements the Model Context Protocol with JSON-RPC 2.0 message handling
 */

import { Server } from '@modelcontextprotocol/sdk/server/index.js'
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js'
import {
  CallToolRequestSchema,
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
  CallToolResult,
  TextContent,
} from '@modelcontextprotocol/sdk/types.js'
import { z } from 'zod'
import pino from 'pino'
import type { Config } from './config.js'
import type {
  ToolDefinition,
  ToolArgs,
  ToolResult,
  WorkerResult,
  PromptDefinition,
  PromptArgs,
  PromptResult,
} from './types.js'

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
  private tools: Map<string, ToolDefinition>
  private handlers: Map<string, ToolHandler>
  private prompts: Map<string, PromptDefinition>
  private promptHandlers: Map<string, PromptHandler>

  constructor(config: Config) {
    // Create logger that writes to stderr to avoid interfering with MCP protocol on stdout
    const destination = pino.destination({ dest: 2, sync: false }); // fd 2 = stderr
    
    this.logger = pino({
      level: config.logging.level,
    }, destination)

    this.tools = new Map()
    this.handlers = new Map()
    this.prompts = new Map()
    this.promptHandlers = new Map()

    // Initialize MCP SDK server
    this.server = new Server(
      {
        name: 'windows-exe-decompiler-mcp-server',
        version: '0.1.2',
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
    this.logger.info({ tool: definition.name }, 'Registering tool')
    this.tools.set(definition.name, definition)
    this.handlers.set(definition.name, handler)
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
    return Array.from(this.tools.values())
  }

  public getToolDefinition(name: string): ToolDefinition | undefined {
    return this.tools.get(name)
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
      
      tools.push({
        name,
        description: definition.description,
        inputSchema: inputSchema as Tool['inputSchema'],
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
  private withDescription(
    jsonSchema: Record<string, unknown>,
    schema: z.ZodTypeAny
  ): Record<string, unknown> {
    if (schema.description) {
      return {
        ...jsonSchema,
        description: schema.description,
      }
    }
    return jsonSchema
  }

  /**
   * Convert Zod field schema to JSON Schema property
   */
  private zodFieldToJsonSchema(schema: z.ZodTypeAny): Record<string, unknown> {
    // Handle optional
    if (schema instanceof z.ZodOptional) {
      return this.zodFieldToJsonSchema(schema._def.innerType)
    }

    // Handle nullable
    if (schema instanceof z.ZodNullable) {
      const innerSchema = this.zodFieldToJsonSchema(schema._def.innerType)
      return this.withDescription({
        anyOf: [innerSchema, { type: 'null' }],
      }, schema)
    }

    // Handle defaults
    if (schema instanceof z.ZodDefault) {
      const innerSchema = this.zodFieldToJsonSchema(schema._def.innerType)
      try {
        return this.withDescription({
          ...innerSchema,
          default: schema._def.defaultValue(),
        }, schema)
      } catch {
        return this.withDescription(innerSchema, schema)
      }
    }

    // Handle catch fallback values
    if (schema instanceof z.ZodCatch) {
      return this.zodFieldToJsonSchema(schema._def.innerType)
    }

    // Handle effects/transform wrappers
    if (schema instanceof z.ZodEffects) {
      return this.zodFieldToJsonSchema(schema._def.schema)
    }

    // Handle branded types
    if (schema instanceof z.ZodBranded) {
      return this.zodFieldToJsonSchema(schema._def.type)
    }

    // Handle readonly wrapper
    if (schema instanceof z.ZodReadonly) {
      return this.zodFieldToJsonSchema(schema._def.innerType)
    }

    // Handle string
    if (schema instanceof z.ZodString) {
      return this.withDescription({ type: 'string' }, schema)
    }

    // Handle number
    if (schema instanceof z.ZodNumber) {
      return this.withDescription({ type: 'number' }, schema)
    }

    // Handle boolean
    if (schema instanceof z.ZodBoolean) {
      return this.withDescription({ type: 'boolean' }, schema)
    }

    // Handle array
    if (schema instanceof z.ZodArray) {
      return this.withDescription({
        type: 'array',
        items: this.zodFieldToJsonSchema(schema._def.type),
      }, schema)
    }

    // Handle enum
    if (schema instanceof z.ZodEnum) {
      return this.withDescription({
        type: 'string',
        enum: schema._def.values,
      }, schema)
    }

    // Handle literal
    if (schema instanceof z.ZodLiteral) {
      const literalValue = schema._def.value
      const literalType = literalValue === null ? 'null' : typeof literalValue
      return this.withDescription({
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

      return this.withDescription({
        type: 'object',
        properties,
        ...(required.length > 0 ? { required } : {}),
      }, schema)
    }

    // Handle union
    if (schema instanceof z.ZodUnion) {
      const options = schema._def.options as z.ZodTypeAny[]
      return this.withDescription({
        anyOf: options.map((option) => this.zodFieldToJsonSchema(option)),
      }, schema)
    }

    // Handle discriminated union
    if (schema instanceof z.ZodDiscriminatedUnion) {
      const options = Array.from(schema.options.values()) as z.ZodTypeAny[]
      return this.withDescription({
        anyOf: options.map((option) => this.zodFieldToJsonSchema(option)),
      }, schema)
    }

    // Handle record
    if (schema instanceof z.ZodRecord) {
      return this.withDescription({
        type: 'object',
        additionalProperties: this.zodFieldToJsonSchema(schema._def.valueType),
      }, schema)
    }

    // Handle tuple
    if (schema instanceof z.ZodTuple) {
      return this.withDescription({
        type: 'array',
        items: schema._def.items.map((item: z.ZodTypeAny) => this.zodFieldToJsonSchema(item)),
      }, schema)
    }

    // Default
    return this.withDescription({ type: 'string' }, schema)
  }

  /**
   * Call a tool by name with arguments (MCP protocol method)
   */
  public async callTool(name: string, args: unknown): Promise<CallToolResult> {
    const startTime = Date.now()
    this.logger.info({ tool: name, args }, 'Calling tool')

    try {
      // Check if tool exists
      const definition = this.tools.get(name)
      if (!definition) {
        throw new Error(`Tool not found: ${name}`)
      }

      // Validate input arguments
      const validatedArgs = this.validateArgs(definition.inputSchema, args)

      // Get handler
      const handler = this.handlers.get(name)
      if (!handler) {
        throw new Error(`Handler not found for tool: ${name}`)
      }

      // Execute handler
      const result = await handler(validatedArgs)

      const elapsed = Date.now() - startTime
      
      // Check if result is ToolResult or WorkerResult
      if ('content' in result) {
        // It's a ToolResult - use directly
        this.logger.info({ tool: name, elapsed, isError: result.isError }, 'Tool execution completed')
        return {
          content: result.content as any, // MCP SDK Content type
          isError: result.isError
        }
      } else {
        // It's a WorkerResult - convert to ToolResult
        this.logger.info({ tool: name, elapsed, ok: result.ok }, 'Tool execution completed')
        return this.workerResultToToolResult(result)
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
  private workerResultToToolResult(result: WorkerResult): CallToolResult {
    const content: TextContent[] = []

    // Add text representation
    content.push({
      type: 'text',
      text: JSON.stringify(
        {
          ok: result.ok,
          data: result.data,
          warnings: result.warnings,
          errors: result.errors,
          artifacts: result.artifacts,
          metrics: result.metrics,
        },
        null,
        2
      ),
    })

    return {
      content,
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
  }

  /**
   * Stop the MCP server
   */
  public async stop(): Promise<void> {
    this.logger.info('Stopping MCP Server')
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
}
