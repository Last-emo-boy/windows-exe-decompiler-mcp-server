/**
 * Visualization & Reporting Plugin
 *
 * HTML report generation, behavior timelines, and data-flow maps.
 */

import type { Plugin } from '../sdk.js'
import { reportHtmlGenerateToolDefinition, createReportHtmlGenerateHandler } from './tools/report-html-generate.js'
import { behaviorTimelineToolDefinition, createBehaviorTimelineHandler } from './tools/behavior-timeline.js'
import { dataFlowMapToolDefinition, createDataFlowMapHandler } from './tools/data-flow-map.js'

const visualizationPlugin: Plugin = {
  id: 'visualization',
  name: 'Visualization & Reporting',
  description: 'HTML report generation, behavior timelines, and data-flow maps',
  version: '1.0.0',
  register(server, deps) {
    server.registerTool(reportHtmlGenerateToolDefinition, createReportHtmlGenerateHandler(deps))
    server.registerTool(behaviorTimelineToolDefinition, createBehaviorTimelineHandler(deps))
    server.registerTool(dataFlowMapToolDefinition, createDataFlowMapHandler(deps))
    return ['report.html.generate', 'behavior.timeline', 'data_flow.map']
  },
}

export default visualizationPlugin
