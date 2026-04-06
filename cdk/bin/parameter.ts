/**
 * Deployment parameters.
 *
 * Edit this file to change settings.
 * OAuth secrets fall back to environment variables so they don't need to be committed.
 */

// ── AWS Account / Region ──
export const awsAccount = process.env.CDK_DEFAULT_ACCOUNT || process.env.AWS_ACCOUNT_ID
// AgentCore Gateway is available in us-east-1
export const region = 'us-east-1'

// ── Cognito ──
// Hosted UI domain prefix (must be globally unique across all AWS accounts)
export const cognitoDomainPrefix = 'remote-mcp-gateway'

// ── FGAC Gateway ──
export const fgacAdminStackName = 'LakeformationAdminStack'

// ── API Key Swap / Redash ──
export const deployRedash = true
export const redashUrl = ''
export const redashAdminUserId = 'tmae@amazon.com'

// ── GitHub 3LO ──
export const githubClientId = process.env.GITHUB_OAUTH_CLIENT_ID || ''
export const githubClientSecret = process.env.GITHUB_OAUTH_CLIENT_SECRET || ''

// ── Notion 3LO ──
export const notionClientId = process.env.NOTION_OAUTH_CLIENT_ID || ''
export const notionClientSecret = process.env.NOTION_OAUTH_CLIENT_SECRET || ''
