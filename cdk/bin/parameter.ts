/**
 * Deployment parameters.
 *
 * All configuration is validated with Zod at synth time.
 * OAuth secrets fall back to environment variables so they don't need to be committed.
 */
import { z } from 'zod'

const ParameterSchema = z.object({
  // ── AWS Account / Region ──
  awsAccount: z.string().min(1, 'Set CDK_DEFAULT_ACCOUNT or AWS_ACCOUNT_ID'),
  region: z.string().default('us-east-1'),

  // ── Cognito ──
  cognitoDomainPrefix: z.string().min(1),

  // ── Redash / API Key Swap ──
  deployRedash: z.boolean().default(true),
  redashUrl: z.string().optional(),

  // ── GitHub 3LO (optional) ──
  githubClientId: z.string().optional(),
  githubClientSecret: z.string().optional(),

  // ── Notion 3LO (optional) ──
  notionClientId: z.string().optional(),
  notionClientSecret: z.string().optional(),

  // ── Slack 3LO (optional) ──
  slackClientId: z.string().optional(),
  slackClientSecret: z.string().optional(),
}).refine(
  (p) => !p.githubClientId || p.githubClientSecret,
  { message: 'githubClientSecret is required when githubClientId is set' },
).refine(
  (p) => !p.notionClientId || p.notionClientSecret,
  { message: 'notionClientSecret is required when notionClientId is set' },
).refine(
  (p) => !p.slackClientId || p.slackClientSecret,
  { message: 'slackClientSecret is required when slackClientId is set' },
)

export type Parameters = z.infer<typeof ParameterSchema>

export const params: Parameters = ParameterSchema.parse({
  awsAccount: process.env.CDK_DEFAULT_ACCOUNT || process.env.AWS_ACCOUNT_ID || '',
  region: 'us-east-1',
  cognitoDomainPrefix: 'remote-mcp-gateway',
  deployRedash: true,
  redashUrl: undefined,
  githubClientId: process.env.GITHUB_OAUTH_CLIENT_ID || undefined,
  githubClientSecret: process.env.GITHUB_OAUTH_CLIENT_SECRET || undefined,
  notionClientId: process.env.NOTION_OAUTH_CLIENT_ID || undefined,
  notionClientSecret: process.env.NOTION_OAUTH_CLIENT_SECRET || undefined,
  slackClientId: process.env.SLACK_OAUTH_CLIENT_ID || undefined,
  slackClientSecret: process.env.SLACK_OAUTH_CLIENT_SECRET || undefined,
})
