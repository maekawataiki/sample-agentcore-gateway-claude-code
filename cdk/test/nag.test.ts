import * as cdk from 'aws-cdk-lib'
import { Annotations, Match } from 'aws-cdk-lib/assertions'
import { AwsSolutionsChecks, NagSuppressions } from 'cdk-nag'
import { CognitoStack } from '../lib/cognito-stack'
import { GatewayStack } from '../lib/gateway-stack'

describe('cdk-nag AwsSolutions', () => {
  let app: cdk.App
  let cognitoStack: CognitoStack
  let gatewayStack: GatewayStack

  beforeAll(() => {
    app = new cdk.App()
    const env = { account: '123456789012', region: 'us-east-1' }

    cognitoStack = new CognitoStack(app, 'TestCognitoStack', {
      domainPrefix: 'test-remote-mcp',
      env,
    })

    gatewayStack = new GatewayStack(app, 'TestGatewayStack', {
      discoveryUrl: cognitoStack.discoveryUrl,
      cognitoClientId: cognitoStack.appClientId,
      cognitoDomain: cognitoStack.cognitoDomain,
      cognitoUserPoolId: cognitoStack.userPoolId,
      deployRedash: false,
      env,
    })

    // ════════════════════════════════════════════════════════════════════
    // Suppressions — each must have a documented reason
    // ════════════════════════════════════════════════════════════════════

    // --- Cognito ---

    NagSuppressions.addStackSuppressions(cognitoStack, [
      {
        id: 'AwsSolutions-COG2',
        reason: 'MFA is not required for this internal developer tool. Strong password policy (12+ chars, uppercase, lowercase, digits, symbols) is enforced.',
      },
      {
        id: 'AwsSolutions-COG3',
        reason: 'Cognito Advanced Security Mode incurs additional per-MAU cost. Not required for an internal developer tool with admin-only user provisioning.',
      },
    ])

    // --- Gateway Stack ---

    // IAM wildcard resources — AgentCore resource ARNs are dynamic
    NagSuppressions.addStackSuppressions(gatewayStack, [
      {
        id: 'AwsSolutions-IAM5',
        reason: 'AgentCore/SecretsManager/Lambda resource ARNs contain deploy-time generated IDs. Actions are scoped to specific operations, not wildcards.',
      },
    ])

    // AWS managed policies on Lambda/APIGW execution roles
    NagSuppressions.addStackSuppressions(gatewayStack, [
      {
        id: 'AwsSolutions-IAM4',
        reason: 'AWSLambdaBasicExecutionRole is the standard CDK-generated execution role for Lambda. It only grants CloudWatch Logs permissions.',
        appliesTo: ['Policy::arn:<AWS::Partition>:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole'],
      },
      {
        id: 'AwsSolutions-IAM4',
        reason: 'AmazonAPIGatewayPushToCloudWatchLogs is the standard CDK-generated role for REST API CloudWatch logging.',
        appliesTo: ['Policy::arn:<AWS::Partition>:iam::aws:policy/service-role/AmazonAPIGatewayPushToCloudWatchLogs'],
      },
    ])

    // Custom Resource framework Lambda runtime is managed by CDK
    NagSuppressions.addStackSuppressions(gatewayStack, [
      {
        id: 'AwsSolutions-L1',
        reason: 'Custom Resource framework and log retention Lambda runtimes are managed by CDK, not user code.',
      },
    ])

    // Session table — ephemeral data with 10-minute TTL, PITR unnecessary
    NagSuppressions.addStackSuppressions(gatewayStack, [
      {
        id: 'AwsSolutions-DDB3',
        reason: 'Session table holds ephemeral OAuth state data with 10-minute TTL. Point-in-time recovery adds no value for transient data.',
      },
    ])

    // Mock API (REST API) — test fallback deployed only when no Redash is configured
    NagSuppressions.addStackSuppressions(gatewayStack, [
      {
        id: 'AwsSolutions-APIG1',
        reason: 'Mock API Gateway is an internal test endpoint, not exposed to production traffic.',
      },
      {
        id: 'AwsSolutions-APIG2',
        reason: 'Mock API Gateway is an internal test fallback only deployed when deployRedash=false.',
      },
      {
        id: 'AwsSolutions-APIG3',
        reason: 'Mock API Gateway is an internal test endpoint — WAF is not required.',
      },
      {
        id: 'AwsSolutions-APIG4',
        reason: 'Mock API Gateway is an internal test endpoint. Authorization is handled by the AgentCore Gateway layer in front.',
      },
      {
        id: 'AwsSolutions-APIG6',
        reason: 'Mock API Gateway is an internal test endpoint. CloudWatch logging is not required.',
      },
      {
        id: 'AwsSolutions-COG4',
        reason: 'Mock API Gateway does not use Cognito authorizer. It is an internal backend called by AgentCore Gateway, not by end users.',
      },
    ])

    cdk.Aspects.of(app).add(new AwsSolutionsChecks({ verbose: true }))
  })

  test('CognitoStack has no unsuppressed errors', () => {
    const errors = Annotations.fromStack(cognitoStack).findError(
      '*',
      Match.stringLikeRegexp('AwsSolutions-.*'),
    )
    if (errors.length > 0) {
      console.log('CognitoStack errors:')
      errors.forEach((e) => console.log(`  ${e.id}: ${e.entry.data}`))
    }
    expect(errors).toHaveLength(0)
  })

  test('GatewayStack has no unsuppressed errors', () => {
    const errors = Annotations.fromStack(gatewayStack).findError(
      '*',
      Match.stringLikeRegexp('AwsSolutions-.*'),
    )
    if (errors.length > 0) {
      console.log('GatewayStack errors:')
      errors.forEach((e) => console.log(`  ${e.id}: ${e.entry.data}`))
    }
    expect(errors).toHaveLength(0)
  })

  test('CognitoStack warnings are reviewed', () => {
    const warnings = Annotations.fromStack(cognitoStack).findWarning(
      '*',
      Match.stringLikeRegexp('AwsSolutions-.*'),
    )
    if (warnings.length > 0) {
      console.log(`CognitoStack has ${warnings.length} warning(s):`)
      warnings.forEach((w) => console.log(`  ${w.id}: ${w.entry.data}`))
    }
  })

  test('GatewayStack warnings are reviewed', () => {
    const warnings = Annotations.fromStack(gatewayStack).findWarning(
      '*',
      Match.stringLikeRegexp('AwsSolutions-.*'),
    )
    if (warnings.length > 0) {
      console.log(`GatewayStack has ${warnings.length} warning(s):`)
      warnings.forEach((w) => console.log(`  ${w.id}: ${w.entry.data}`))
    }
  })
})
