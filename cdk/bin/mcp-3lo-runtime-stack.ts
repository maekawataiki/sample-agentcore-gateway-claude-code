#!/usr/bin/env node
import * as cdk from 'aws-cdk-lib'
import { CognitoStack } from '../lib/cognito-stack'
import { GatewayStack } from '../lib/gateway-stack'
import { FirebaseMcpRuntimeStack } from '../lib/firebase-mcp-runtime-stack'
import { params } from './parameter'

const app = new cdk.App()
const env = { account: params.awsAccount, region: params.region }

// ── Shared Cognito ──
const cognito = new CognitoStack(app, 'CognitoStack', {
  domainPrefix: params.cognitoDomainPrefix,
  env,
  description: 'Shared Cognito User Pool for AgentCore Gateway',
})

// ── Unified Gateway ──
new GatewayStack(app, 'GatewayStack', {
  discoveryUrl: cognito.discoveryUrl,
  cognitoClientId: cognito.appClientId,
  cognitoDomain: cognito.cognitoDomain,
  cognitoUserPoolId: cognito.userPoolId,
  githubClientId: params.githubClientId,
  githubClientSecret: params.githubClientSecret,
  notionClientId: params.notionClientId,
  notionClientSecret: params.notionClientSecret,
  slackClientId: params.slackClientId,
  slackClientSecret: params.slackClientSecret,
  datadogClientId: params.datadogClientId,
  datadogMcpHost: params.datadogMcpHost,
  githubBotPat: params.githubBotPat,
  firebaseRuntimeStackName: 'FirebaseMcpRuntimeStack',
  deployRedash: params.deployRedash,
  redashUrl: params.redashUrl,
  redashHostedZoneName: params.redashHostedZoneName,
  redashRecordName: params.redashRecordName,
  env,
  description: 'Unified MCP Gateway — GitHub, Notion, Redash via single endpoint',
})

new FirebaseMcpRuntimeStack(app, 'FirebaseMcpRuntimeStack', {
  discoveryUrl: cognito.discoveryUrl,
  cognitoClientId: cognito.appClientId,
  env,
  description: 'Independent Firebase CLI MCP endpoint backed by AgentCore Runtime',
})

app.synth()
