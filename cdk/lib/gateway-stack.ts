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
import { GitHubCredentialProviderConstruct, NotionCredentialProviderConstruct } from './constructs-3lo'
import { ApiKeyMappingTableConstruct, ApiKeyInterceptorLambdaConstruct, RedashInstanceConstruct } from './constructs-apikey'
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
  // ── Redash / API Key Swap ──
  readonly deployRedash?: boolean
  readonly redashUrl?: string
  readonly redashAdminUserId?: string
}

export class GatewayStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props: GatewayStackProps) {
    super(scope, id, props)

    const hasGithub = !!(props.githubClientId && props.githubClientSecret)
    const hasNotion = !!(props.notionClientId && props.notionClientSecret)
    const useRedash = props.deployRedash || !!props.redashUrl

    // ══════════════════════════════════════════════════════════════════════
    // API Key Swap — DynamoDB + Interceptor + Backend
    // ══════════════════════════════════════════════════════════════════════

    const apiKeyTable = new ApiKeyMappingTableConstruct(this, 'ApiKeyTable')
    const apiKeyInterceptor = new ApiKeyInterceptorLambdaConstruct(
      this, 'ApiKeyInterceptor', { apiKeyTable: apiKeyTable.table },
    )

    let redashBackendUrl: string
    if (props.deployRedash) {
      const redash = new RedashInstanceConstruct(this, 'Redash', {
        apiKeyTable: apiKeyTable.table,
        adminUserId: props.redashAdminUserId || 'admin',
      })
      redashBackendUrl = redash.redashUrl
      new cdk.CfnOutput(this, 'RedashUrl', { value: redash.redashUrl })
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
          statements: [new iam.PolicyStatement({
            actions: [
              'bedrock-agentcore:*', 'bedrock:*', 'agent-credential-provider:*',
              'iam:PassRole', 'secretsmanager:GetSecretValue', 'lambda:InvokeFunction',
            ],
            resources: ['*'],
          })],
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
          apiKey: 'placeholder-key-overridden-by-interceptor',
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
          actions: ['bedrock-agentcore:*', 'secretsmanager:*'],
          resources: ['*'],
        }),
      ]),
      logRetention: logs.RetentionDays.ONE_WEEK,
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
            credentialParameterName: 'X-API-Key',
            credentialLocation: 'HEADER',
          },
        },
      }],
    })

    // ── GitHub Target ──
    let githubProvider: GitHubCredentialProviderConstruct | undefined
    if (hasGithub) {
      githubProvider = new GitHubCredentialProviderConstruct(
        this, 'GitHubProvider', {
          uniqueId: 'github',
          clientId: props.githubClientId!,
          clientSecret: props.githubClientSecret!,
        },
      )
      const githubSpec = fs.readFileSync(
        path.join(__dirname, '../openapi/github-api.yaml'), 'utf-8',
      )
      new bedrockagentcore.CfnGatewayTarget(this, 'GitHubTarget', {
        name: `github-target-${this.stackName}`,
        gatewayIdentifier: gateway.attrGatewayIdentifier,
        targetConfiguration: {
          mcp: { openApiSchema: { inlinePayload: githubSpec } },
        },
        credentialProviderConfigurations: [{
          credentialProviderType: 'OAUTH',
          credentialProvider: {
            oauthCredentialProvider: {
              providerArn: githubProvider.credentialProviderArn,
              grantType: 'AUTHORIZATION_CODE',
              defaultReturnUrl: 'https://placeholder.example.com/3lo-callback',
              scopes: ['repo', 'read:org', 'read:user', 'user:email'],
            },
          },
        }],
      })
    }

    // ── Notion Target ──
    let notionProvider: NotionCredentialProviderConstruct | undefined
    if (hasNotion) {
      notionProvider = new NotionCredentialProviderConstruct(
        this, 'NotionProvider', {
          uniqueId: 'notion',
          clientId: props.notionClientId!,
          clientSecret: props.notionClientSecret!,
        },
      )
      const notionSpec = fs.readFileSync(
        path.join(__dirname, '../openapi/notion-api.yaml'), 'utf-8',
      )
      new bedrockagentcore.CfnGatewayTarget(this, 'NotionTarget', {
        name: `notion-target-${this.stackName}`,
        gatewayIdentifier: gateway.attrGatewayIdentifier,
        targetConfiguration: {
          mcp: { openApiSchema: { inlinePayload: notionSpec } },
        },
        credentialProviderConfigurations: [{
          credentialProviderType: 'OAUTH',
          credentialProvider: {
            oauthCredentialProvider: {
              providerArn: notionProvider.credentialProviderArn,
              grantType: 'AUTHORIZATION_CODE',
              defaultReturnUrl: 'https://placeholder.example.com/3lo-callback',
              scopes: [],
            },
          },
        }],
      })
    }

    // ══════════════════════════════════════════════════════════════════════
    // OAuth Proxy (HTTP API + Lambda + DynamoDB)
    // ══════════════════════════════════════════════════════════════════════

    const sessionTable = new dynamodb.Table(this, 'SessionTable', {
      tableName: `3lo-sessions-${this.stackName}`,
      partitionKey: { name: 'sessionUri', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
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
      environment: {
        GATEWAY_URL: gateway.attrGatewayUrl,
        COGNITO_DOMAIN: props.cognitoDomain,
        COGNITO_CLIENT_ID: props.cognitoClientId,
        SESSION_TABLE_NAME: sessionTable.tableName,
      },
      logRetention: logs.RetentionDays.ONE_WEEK,
    })
    proxyLambda.addToRolePolicy(new iam.PolicyStatement({
      actions: ['bedrock-agentcore:CompleteResourceTokenAuth', 'secretsmanager:GetSecretValue'],
      resources: ['*'],
    }))
    sessionTable.grantReadWriteData(proxyLambda)

    const httpApi = new apigwv2.HttpApi(this, 'ProxyApi', {
      apiName: 'unified-mcp-proxy',
      description: 'Unified MCP OAuth proxy for all Gateway targets',
      corsPreflight: {
        allowOrigins: ['*'],
        allowMethods: [apigwv2.CorsHttpMethod.ANY],
        allowHeaders: ['Content-Type', 'Authorization', 'Mcp-Protocol-Version', 'Mcp-Session-Id'],
      },
    })
    const integration = new apigwv2integrations.HttpLambdaIntegration('Int', proxyLambda)
    httpApi.addRoutes({ path: '/{proxy+}', methods: [apigwv2.HttpMethod.ANY], integration })
    httpApi.addRoutes({ path: '/', methods: [apigwv2.HttpMethod.ANY], integration })

    // ── Register proxy callback URL with Cognito ──
    new CognitoCallbackRegistration(this, 'CallbackReg', {
      userPoolId: props.cognitoUserPoolId,
      clientId: props.cognitoClientId,
      callbackUrl: `${httpApi.apiEndpoint}/callback`,
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
    new cdk.CfnOutput(this, 'ApiKeyTableName', {
      value: apiKeyTable.table.tableName,
    })
    new cdk.CfnOutput(this, 'ProxyUrl', {
      value: httpApi.apiEndpoint,
    })
    // Credential provider callback URLs are not available in CFN outputs.
    // After deploy, retrieve them with:
    //   aws bedrock-agentcore-control get-oauth2-credential-provider --name <NAME> --query callbackUrl
    if (githubProvider) {
      new cdk.CfnOutput(this, 'GitHubCredentialProviderName', {
        value: githubProvider.credentialProviderName,
        description: 'Run: aws bedrock-agentcore-control get-oauth2-credential-provider --name <this> --query callbackUrl',
      })
    }
    if (notionProvider) {
      new cdk.CfnOutput(this, 'NotionCredentialProviderName', {
        value: notionProvider.credentialProviderName,
        description: 'Run: aws bedrock-agentcore-control get-oauth2-credential-provider --name <this> --query callbackUrl',
      })
    }
  }
}
