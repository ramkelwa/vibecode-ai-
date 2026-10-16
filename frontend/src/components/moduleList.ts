// Module identifiers accepted by the backend APIs, in pipeline order.
// Kept in one module so the form and the detail view agree by construction.

export const WEBSITE_MODULES: string[] = [
  'url_validation',
  'dns_analysis',
  'tls_analysis',
  'http_headers',
  'cookie_analysis',
  'html_analysis',
  'js_discovery',
  'js_analysis',
  'api_discovery',
]

export const PROJECT_MODULES: string[] = ['dependency_audit', 'source_analysis']

export const STAGE_LABEL: Record<string, string> = {
  url_validation: 'URL & redirects',
  dns_analysis: 'DNS records',
  tls_analysis: 'TLS certificate',
  http_headers: 'HTTP headers',
  cookie_analysis: 'Cookies',
  html_analysis: 'HTML metadata',
  js_discovery: 'JS assets',
  js_analysis: 'JS analysis',
  api_discovery: 'API endpoints',
  dependency_audit: 'Dependency audit',
  source_analysis: 'Static source analysis',
  zap_dynamic: 'Dynamic scan (ZAP)',
}

export { STAGE_LABEL as STAGE_ORDER_KEYS }

export const STAGE_ORDER: string[] = [
  'url_validation',
  'dns_analysis',
  'tls_analysis',
  'http_headers',
  'cookie_analysis',
  'html_analysis',
  'js_discovery',
  'js_analysis',
  'api_discovery',
  'dependency_audit',
  'source_analysis',
  'zap_dynamic',
]
