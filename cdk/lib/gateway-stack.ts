/**
 * Unified Gateway Stack
 *
 * Single AgentCore Gateway with multiple targets + OAuth Proxy.
 * One Cognito login covers all MCP tools (GitHub, Notion, Redash).
 *
 * Architecture:
 *   Claude Code → HTTP API (OAuth Proxy) → AgentCore Gateway (CUSTOM_JWT)
 *     ├─ Target: GitHub  (OpenAPI + 3LO OAuth)
 *     ├─ Target: Notion  (OpenAPI + 3LO OAuth)
 *     └─ Target: Redash  (OpenAPI + API Key via REQUEST interceptor)
 */
import * as cdk from 'aws-cdk-lib'
import * as iam from 'aws-cdk-lib/aws-iam'
import * as lambda from 'aws-cdk-lib/aws-lambda'
import * as apigwv2 from 'aws-cdk-lib/aws-apigatewayv2'
import * as apigwv2integrations from 'aws-cdk-lib/aws-apigatewayv2-integrations'
import * as dynamodb from 'aws-cdk-lib/aws-dynamodb'
import * as bedrockagentcore from 'aws-cdk-lib/aws-bedrockagentcore'
import * as apigateway from 'aws-cdk-lib/aws-apigateway'
import * as logs from 'aws-cdk-lib/aws-logs'
import * as cr from 'aws-cdk-lib/custom-resources'
import * as fs from 'fs'
import * as path from 'path'
import { Construct } from 'constructs'
import { GitHubCredentialProviderConstruct, NotionCredentialProviderConstruct, SlackCredentialProviderConstruct } from './constructs-3lo'
import { ApiKeyInterceptorLambdaConstruct, RedashInstanceConstruct } from './constructs-apikey'
import { AdminTablesConstruct, CognitoAdminGroupConstruct, AdminApiConstruct, AdminFrontendConstruct } from './constructs-admin'
import { CognitoCallbackRegistration } from './constructs/cognito-callback-registration'

export interface GatewayStackProps extends cdk.StackProps {
  // ── Cognito ──
  readonly discoveryUrl: string
  readonly cognitoClientId: string
  readonly cognitoDomain: string
  readonly cognitoUserPoolId: string
  // ── GitHub 3LO (optional) ──
  readonly githubClientId?: string
  readonly githubClientSecret?: string
  // ── Notion 3LO (optional) ──
  readonly notionClientId?: string
  readonly notionClientSecret?: string
  // ── Slack 3LO (optional) ──
  readonly slackClientId?: string
  readonly slackClientSecret?: string
  // ── Redash / API Key Swap ──
  readonly deployRedash?: boolean
  readonly redashUrl?: string
}

export class GatewayStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props: GatewayStackProps) {
    super(scope, id, props)

    const hasGithub = !!(props.githubClientId && props.githubClientSecret)
    const hasNotion = !!(props.notionClientId && props.notionClientSecret)
    const hasSlack = !!(props.slackClientId && props.slackClientSecret)
    const useRedash = props.deployRedash || !!props.redashUrl

    // ══════════════════════════════════════════════════════════════════════
    // API Key Swap — DynamoDB + Interceptor + Backend
    // ══════════════════════════════════════════════════════════════════════

    // ── Admin Control Panel — Table + Cognito Group ──
    const adminTables = new AdminTablesConstruct(this, 'AdminTables')
    const adminGroup = new CognitoAdminGroupConstruct(this, 'AdminGroup', {
      userPoolId: props.cognitoUserPoolId,
    })

    const apiKeyInterceptor = new ApiKeyInterceptorLambdaConstruct(
      this, 'ApiKeyInterceptor', { adminTable: adminTables.table },
    )

    let redashBackendUrl: string
    if (props.deployRedash) {
      const redash = new RedashInstanceConstruct(this, 'Redash', {
        adminTable: adminTables.table,
      })
      redashBackendUrl = redash.redashUrl
      new cdk.CfnOutput(this, 'RedashUrl', { value: redash.redashUrl })
      new cdk.CfnOutput(this, 'RedashCredentialsSecret', {
        value: redash.credentialsSecretName,
        description: 'aws secretsmanager get-secret-value --secret-id <this> --query SecretString --output text',
      })
    } else if (props.redashUrl) {
      redashBackendUrl = props.redashUrl.replace(/\/$/, '')
    } else {
      // Mock API fallback
      const mockLambda = new lambda.Function(this, 'MockApi', {
        runtime: lambda.Runtime.PYTHON_3_13,
        handler: 'index.lambda_handler',
        code: lambda.Code.fromAsset(path.join(__dirname, '../lambda/mock_api')),
        architecture: lambda.Architecture.ARM_64,
        timeout: cdk.Duration.seconds(10),
      })
      const mockApi = new apigateway.LambdaRestApi(this, 'MockApiGw', {
        handler: mockLambda, proxy: true,
      })
      redashBackendUrl = mockApi.url.replace(/\/$/, '')
    }

    // ══════════════════════════════════════════════════════════════════════
    // Response Interceptor (passthrough for -32042 elicitation)
    // ══════════════════════════════════════════════════════════════════════

    const responseInterceptor = new lambda.Function(this, 'ResponseInterceptor', {
      functionName: `unified-gw-response-interceptor-${this.stackName}`,
      runtime: lambda.Runtime.PYTHON_3_13,
      handler: 'notion_elicitation_interceptor.lambda_handler',
      code: lambda.Code.fromAsset(path.join(__dirname, '../lambda'), {
        exclude: [
          'iam_request_interceptor', 'apikey_request_interceptor',
          'mock_api', 'mcp_oauth_proxy.py', 'boto3_layer', '*.zip',
        ],
      }),
      architecture: lambda.Architecture.ARM_64,
      timeout: cdk.Duration.seconds(10),
      description: 'Response interceptor — passthrough for -32042 elicitation',
      tracing: lambda.Tracing.ACTIVE,
      logRetention: logs.RetentionDays.THREE_MONTHS,
    })
    responseInterceptor.grantInvoke(
      new iam.ServicePrincipal('bedrock-agentcore.amazonaws.com'),
    )

    // ══════════════════════════════════════════════════════════════════════
    // Gateway
    // ══════════════════════════════════════════════════════════════════════

    const gatewayRole = new iam.Role(this, 'GatewayRole', {
      assumedBy: new iam.ServicePrincipal('bedrock-agentcore.amazonaws.com', {
        conditions: {
          StringEquals: { 'aws:SourceAccount': this.account },
          ArnLike: {
            'aws:SourceArn': `arn:aws:bedrock-agentcore:${this.region}:${this.account}:*`,
          },
        },
      }),
      inlinePolicies: {
        AgentCorePolicy: new iam.PolicyDocument({
          statements: [
            new iam.PolicyStatement({
              actions: [
                'bedrock-agentcore:InvokeGateway',
                'bedrock-agentcore:GetGateway',
                'bedrock-agentcore:GetGatewayTarget',
                'bedrock-agentcore:ListGatewayTargets',
                'bedrock-agentcore:GetOauth2CredentialProvider',
                'bedrock-agentcore:GetApiKeyCredentialProvider',
                'bedrock-agentcore:CompleteResourceTokenAuth',
                'bedrock-agentcore:GetResourceOauth2Token',
                'bedrock-agentcore:GetResourceApiKey',
                'bedrock-agentcore:GetWorkloadAccessToken',
                'bedrock-agentcore:GetWorkloadAccessTokenForJWT',
              ],
              resources: [`arn:aws:bedrock-agentcore:${this.region}:${this.account}:*`],
            }),
            new iam.PolicyStatement({
              actions: ['iam:PassRole'],
              resources: ['*'],
              conditions: {
                StringEquals: {
                  'iam:PassedToService': 'bedrock-agentcore.amazonaws.com',
                },
              },
            }),
            new iam.PolicyStatement({
              actions: ['secretsmanager:GetSecretValue'],
              resources: [`arn:aws:secretsmanager:${this.region}:${this.account}:secret:*`],
            }),
            new iam.PolicyStatement({
              actions: ['lambda:InvokeFunction'],
              resources: [`arn:aws:lambda:${this.region}:${this.account}:function:*`],
            }),
          ],
        }),
      },
    })

    const gateway = new bedrockagentcore.CfnGateway(this, 'Gateway', {
      name: `unified-gw-${this.stackName}`,
      roleArn: gatewayRole.roleArn,
      protocolType: 'MCP',
      protocolConfiguration: {
        mcp: { supportedVersions: ['2025-11-25'], searchType: 'SEMANTIC' },
      },
      authorizerType: 'CUSTOM_JWT',
      authorizerConfiguration: {
        customJwtAuthorizer: {
          discoveryUrl: props.discoveryUrl,
          allowedClients: [props.cognitoClientId],
        },
      },
      exceptionLevel: 'DEBUG',
      interceptorConfigurations: [
        {
          interceptor: { lambda: { arn: apiKeyInterceptor.requestInterceptor.functionArn } },
          interceptionPoints: ['REQUEST'],
          inputConfiguration: { passRequestHeaders: true },
        },
        {
          interceptor: { lambda: { arn: responseInterceptor.functionArn } },
          interceptionPoints: ['RESPONSE'],
        },
      ],
    })

    apiKeyInterceptor.requestInterceptor.grantInvoke(
      new iam.ServicePrincipal('bedrock-agentcore.amazonaws.com'),
    )

    // ══════════════════════════════════════════════════════════════════════
    // Targets
    // ══════════════════════════════════════════════════════════════════════

    // ── Redash / API Key Swap Target ──
    const apiKeyProviderName = `apikey-provider-${this.stackName}`
    const apiKeyProvider = new cr.AwsCustomResource(this, 'ApiKeyProvider', {
      onCreate: {
        service: 'bedrock-agentcore-control',
        action: 'CreateApiKeyCredentialProvider',
        parameters: {
          name: apiKeyProviderName,
          apiKey: 'Key placeholder-overridden-by-interceptor',
        },
        physicalResourceId: cr.PhysicalResourceId.fromResponse('credentialProviderArn'),
      },
      onUpdate: {
        service: 'bedrock-agentcore-control',
        action: 'UpdateApiKeyCredentialProvider',
        parameters: {
          name: apiKeyProviderName,
          apiKey: 'Key placeholder-overridden-by-interceptor',
        },
        physicalResourceId: cr.PhysicalResourceId.fromResponse('credentialProviderArn'),
      },
      onDelete: {
        service: 'bedrock-agentcore-control',
        action: 'DeleteApiKeyCredentialProvider',
        parameters: { name: apiKeyProviderName },
      },
      policy: cr.AwsCustomResourcePolicy.fromStatements([
        new iam.PolicyStatement({
          actions: [
            'bedrock-agentcore:CreateApiKeyCredentialProvider',
            'bedrock-agentcore:UpdateApiKeyCredentialProvider',
            'bedrock-agentcore:DeleteApiKeyCredentialProvider',
            'bedrock-agentcore:GetApiKeyCredentialProvider',
            // First-time provider creation implicitly creates the default token vault
            'bedrock-agentcore:CreateTokenVault',
            'bedrock-agentcore:GetTokenVault',
          ],
          resources: [`arn:aws:bedrock-agentcore:${this.region}:${this.account}:*`],
        }),
        new iam.PolicyStatement({
          actions: ['secretsmanager:CreateSecret', 'secretsmanager:DeleteSecret', 'secretsmanager:PutSecretValue'],
          resources: [`arn:aws:secretsmanager:${this.region}:${this.account}:secret:*`],
        }),
      ]),
      logRetention: logs.RetentionDays.THREE_MONTHS,
    })

    const redashSpec = fs.readFileSync(
      path.join(__dirname, '../openapi/redash-api.yaml'), 'utf-8',
    ).replace('${RedashUrl}', redashBackendUrl)

    new bedrockagentcore.CfnGatewayTarget(this, 'RedashTarget', {
      name: `redash-target-${this.stackName}`,
      gatewayIdentifier: gateway.attrGatewayIdentifier,
      targetConfiguration: {
        mcp: { openApiSchema: { inlinePayload: redashSpec } },
      },
      credentialProviderConfigurations: [{
        credentialProviderType: 'API_KEY',
        credentialProvider: {
          apiKeyCredentialProvider: {
            providerArn: apiKeyProvider.getResponseField('credentialProviderArn'),
            credentialParameterName: 'Authorization',
            credentialLocation: 'HEADER',
          },
        },
      }],
    })

    // ── GitHub Credential Provider ──
    // Target creation is handled by bin/sync-mcp-targets.sh (outside CDK)
    // because MCP server targets with Authorization Code grant require
    // interactive OAuth consent during creation — not possible via CFN.
    let githubProvider: GitHubCredentialProviderConstruct | undefined
    if (hasGithub) {
      githubProvider = new GitHubCredentialProviderConstruct(
        this, 'GitHubProvider', {
          uniqueId: 'github',
          clientId: props.githubClientId!,
          clientSecret: props.githubClientSecret!,
        },
      )
    }

    // ── Notion Credential Provider ──
    let notionProvider: NotionCredentialProviderConstruct | undefined
    if (hasNotion) {
      // Logical ID intentionally 'NotionCustomProvider' (not 'NotionProvider')
      // to force CFN to replace the resource when migrating from the built-in
      // NotionOauth2 vendor to CustomOauth2. Vendor type cannot be updated in-place.
      notionProvider = new NotionCredentialProviderConstruct(
        this, 'NotionCustomProvider', {
          uniqueId: 'notion',
          clientId: props.notionClientId!,
          clientSecret: props.notionClientSecret!,
        },
      )
    }

    // ── Slack Credential Provider ──
    // Created after httpApi because it needs the proxy URL for scope rewriting
    let slackProvider: SlackCredentialProviderConstruct | undefined

    // ══════════════════════════════════════════════════════════════════════
    // OAuth Proxy (HTTP API + Lambda + DynamoDB)
    // ══════════════════════════════════════════════════════════════════════

    const sessionTable = new dynamodb.Table(this, 'SessionTable', {
      tableName: `3lo-sessions-${this.stackName}`,
      partitionKey: { name: 'sessionUri', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      encryption: dynamodb.TableEncryption.AWS_MANAGED,
      timeToLiveAttribute: 'ttl',
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    })

    const proxyLambda = new lambda.Function(this, 'ProxyLambda', {
      functionName: `oauth-proxy-${this.stackName}`,
      runtime: lambda.Runtime.PYTHON_3_13,
      handler: 'mcp_oauth_proxy.lambda_handler',
      code: lambda.Code.fromAsset(path.join(__dirname, '../lambda'), {
        exclude: [
          'iam_request_interceptor', 'apikey_request_interceptor',
          'mock_api', 'boto3_layer', '*.zip',
        ],
      }),
      architecture: lambda.Architecture.ARM_64,
      timeout: cdk.Duration.seconds(60),
      memorySize: 256,
      description: 'Unified OAuth proxy — Cognito facade + MCP forwarding + 3LO callback',
      tracing: lambda.Tracing.ACTIVE,
      environment: {
        GATEWAY_URL: gateway.attrGatewayUrl,
        COGNITO_DOMAIN: props.cognitoDomain,
        COGNITO_CLIENT_ID: props.cognitoClientId,
        SESSION_TABLE_NAME: sessionTable.tableName,
      },
      logRetention: logs.RetentionDays.THREE_MONTHS,
    })
    proxyLambda.addToRolePolicy(new iam.PolicyStatement({
      actions: ['bedrock-agentcore:CompleteResourceTokenAuth'],
      resources: [`arn:aws:bedrock-agentcore:${this.region}:${this.account}:*`],
    }))
    // CompleteResourceTokenAuth internally reads the OAuth client secret from Secrets Manager
    proxyLambda.addToRolePolicy(new iam.PolicyStatement({
      actions: ['secretsmanager:GetSecretValue'],
      resources: [`arn:aws:secretsmanager:${this.region}:${this.account}:secret:*`],
    }))
    sessionTable.grantReadWriteData(proxyLambda)

    // No CORS preflight — MCP clients (Claude Code, VS Code) are not browsers.
    // The OAuth Proxy Lambda handles OPTIONS directly if needed.
    const httpApi = new apigwv2.HttpApi(this, 'ProxyApi', {
      apiName: 'unified-mcp-proxy',
      description: 'Unified MCP OAuth proxy for all Gateway targets',
    })
    const integration = new apigwv2integrations.HttpLambdaIntegration('Int', proxyLambda)
    httpApi.addRoutes({ path: '/{proxy+}', methods: [apigwv2.HttpMethod.ANY], integration })
    httpApi.addRoutes({ path: '/', methods: [apigwv2.HttpMethod.ANY], integration })

    // ── Slack Credential Provider (needs proxy URL for scope rewriting) ──
    if (hasSlack) {
      slackProvider = new SlackCredentialProviderConstruct(
        this, 'SlackProvider', {
          uniqueId: 'slack',
          clientId: props.slackClientId!,
          clientSecret: props.slackClientSecret!,
        },
      )
    }

    // ── HTTP API Access Logging ──
    const accessLogGroup = new logs.LogGroup(this, 'ProxyApiAccessLog', {
      logGroupName: `/aws/apigateway/unified-mcp-proxy-${this.stackName}`,
      retention: logs.RetentionDays.THREE_MONTHS,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    })
    const defaultStage = httpApi.defaultStage?.node.defaultChild as apigwv2.CfnStage
    defaultStage.accessLogSettings = {
      destinationArn: accessLogGroup.logGroupArn,
      format: JSON.stringify({
        requestId: '$context.requestId',
        ip: '$context.identity.sourceIp',
        caller: '$context.identity.caller',
        user: '$context.identity.user',
        requestTime: '$context.requestTime',
        httpMethod: '$context.httpMethod',
        path: '$context.path',
        status: '$context.status',
        protocol: '$context.protocol',
        responseLength: '$context.responseLength',
        latency: '$context.responseLatency',
        integrationLatency: '$context.integrationLatency',
        error: '$context.error.message',
      }),
    }

    // ── Register proxy callback URL with Cognito ──
    new CognitoCallbackRegistration(this, 'CallbackReg', {
      userPoolId: props.cognitoUserPoolId,
      clientId: props.cognitoClientId,
      callbackUrl: `${httpApi.apiEndpoint}/callback`,
    })

    // ══════════════════════════════════════════════════════════════════════
    // Admin Control Panel API
    // ══════════════════════════════════════════════════════════════════════

    const adminApi = new AdminApiConstruct(this, 'AdminApi', {
      cognitoUserPoolId: props.cognitoUserPoolId,
      adminGroupName: adminGroup.groupName,
      adminTable: adminTables.table,
    })

    // ══════════════════════════════════════════════════════════════════════
    // Admin Frontend (S3 + CloudFront)
    // ══════════════════════════════════════════════════════════════════════

    const adminFrontend = new AdminFrontendConstruct(this, 'AdminFrontend', {
      cognitoDomain: `https://${props.cognitoDomain}`,
      cognitoClientId: props.cognitoClientId,
      adminApiUrl: `${adminApi.apiUrl}admin/v1`,
    })

    // Register CloudFront URL as Cognito callback + logout URL
    new CognitoCallbackRegistration(this, 'AdminCallbackReg', {
      userPoolId: props.cognitoUserPoolId,
      clientId: props.cognitoClientId,
      callbackUrl: adminFrontend.distributionUrl,
    })

    // ══════════════════════════════════════════════════════════════════════
    // Outputs
    // ══════════════════════════════════════════════════════════════════════

    new cdk.CfnOutput(this, 'McpUrl', {
      value: `${httpApi.apiEndpoint}/mcp`,
      description: 'MCP URL for .mcp.json (single entry for all tools)',
    })
    new cdk.CfnOutput(this, 'GatewayId', {
      value: gateway.attrGatewayIdentifier,
    })
    new cdk.CfnOutput(this, 'GatewayUrl', {
      value: gateway.attrGatewayUrl,
    })
    new cdk.CfnOutput(this, 'AdminTableName', {
      value: adminTables.table.tableName,
    })
    new cdk.CfnOutput(this, 'ProxyUrl', {
      value: httpApi.apiEndpoint,
    })
    new cdk.CfnOutput(this, 'AdminApiUrl', {
      value: `${adminApi.apiUrl}admin/v1`,
      description: 'Admin API base URL (e.g. <this>/services, <this>/services/{name}/mappings)',
    })
    new cdk.CfnOutput(this, 'AdminPanelUrl', {
      value: adminFrontend.distributionUrl,
      description: 'Admin Panel URL (open in browser)',
    })
    // Credential provider callback URLs are not available in CFN outputs.
    // After deploy, retrieve them with:
    //   aws bedrock-agentcore-control get-oauth2-credential-provider --name <NAME> --query callbackUrl
    if (githubProvider) {
      new cdk.CfnOutput(this, 'GitHubCredentialProviderName', {
        value: githubProvider.credentialProviderName,
      })
      new cdk.CfnOutput(this, 'GitHubCredentialProviderArn', {
        value: githubProvider.credentialProviderArn,
      })
    }
    if (notionProvider) {
      new cdk.CfnOutput(this, 'NotionCredentialProviderName', {
        value: notionProvider.credentialProviderName,
      })
      new cdk.CfnOutput(this, 'NotionCredentialProviderArn', {
        value: notionProvider.credentialProviderArn,
      })
    }
    if (slackProvider) {
      new cdk.CfnOutput(this, 'SlackCredentialProviderName', {
        value: slackProvider.credentialProviderName,
      })
      new cdk.CfnOutput(this, 'SlackCredentialProviderArn', {
        value: slackProvider.credentialProviderArn,
      })
    }
  }
}
