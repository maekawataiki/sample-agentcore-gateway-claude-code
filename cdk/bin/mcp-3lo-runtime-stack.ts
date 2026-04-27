#!/usr/bin/env node
import 'source-map-support/register'
import * as cdk from 'aws-cdk-lib'
import { CognitoStack } from '../lib/cognito-stack'
import { GatewayStack } from '../lib/gateway-stack'
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
  deployRedash: params.deployRedash,
  redashUrl: params.redashUrl,
  env,
  description: 'Unified MCP Gateway — GitHub, Notion, Redash via single endpoint',
})

app.synth()
