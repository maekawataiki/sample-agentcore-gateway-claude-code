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
import { HttpIamAuthorizer } from 'aws-cdk-lib/aws-apigatewayv2-authorizers'
import * as dynamodb from 'aws-cdk-lib/aws-dynamodb'
import * as bedrockagentcore from 'aws-cdk-lib/aws-bedrockagentcore'
import * as secretsmanager from 'aws-cdk-lib/aws-secretsmanager'
import * as apigateway from 'aws-cdk-lib/aws-apigateway'
import * as logs from 'aws-cdk-lib/aws-logs'
import * as cr from 'aws-cdk-lib/custom-resources'
import * as s3assets from 'aws-cdk-lib/aws-s3-assets'
import * as fs from 'fs'
import * as os from 'os'
import * as path from 'path'
import * as yaml from 'js-yaml'
import { Construct } from 'constructs'
import { GitHubCredentialProviderConstruct, NotionCredentialProviderConstruct, SlackCredentialProviderConstruct, DatadogCredentialProviderConstruct } from './constructs-3lo'
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
  // ── Datadog 3LO (optional) ──
  readonly datadogClientId?: string
  /** MCP host for the Datadog site. Default: "mcp.datadoghq.com" (US1). AP1: "mcp.ap1.datadoghq.com" */
  readonly datadogMcpHost?: string
  // ── GitHub bot (PAT-injection proxy, optional) ──
  /** GitHub bot PAT. When set, the github-bot target + IAM-protected proxy route are deployed. */
  readonly githubBotPat?: string
  // ── Redash / API Key Swap ──
  readonly deployRedash?: boolean
  readonly redashUrl?: string
  /** Public Route53 zone hosting the Redash record (only required when deployRedash=true) */
  readonly redashHostedZoneName?: string
  /** FQDN for the Redash internal ALB (only required when deployRedash=true) */
  readonly redashRecordName?: string
}

export class GatewayStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props: GatewayStackProps) {
    super(scope, id, props)

    const hasGithub = !!(props.githubClientId && props.githubClientSecret)
    const hasNotion = !!(props.notionClientId && props.notionClientSecret)
    const hasSlack = !!(props.slackClientId && props.slackClientSecret)
    const hasDatadog = !!props.datadogClientId
    const hasGithubBot = !!props.githubBotPat
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
    let redashInstance: RedashInstanceConstruct | undefined
    if (props.deployRedash) {
      if (!props.redashHostedZoneName || !props.redashRecordName) {
        throw new Error('redashHostedZoneName and redashRecordName are required when deployRedash=true')
      }
      redashInstance = new RedashInstanceConstruct(this, 'Redash', {
        adminTable: adminTables.table,
        hostedZoneName: props.redashHostedZoneName,
        recordName: props.redashRecordName,
      })
      redashBackendUrl = redashInstance.redashUrl
      new cdk.CfnOutput(this, 'RedashUrl', { value: redashInstance.redashUrl })
      new cdk.CfnOutput(this, 'RedashCredentialsSecret', {
        value: redashInstance.credentialsSecretName,
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
            // Required for VPC-egress targets (privateEndpoint.managedVpcResource).
            // AgentCore validates and provisions VPC Lattice ENIs using these.
            new iam.PolicyStatement({
              actions: [
                'ec2:DescribeVpcs',
                'ec2:DescribeSubnets',
                'ec2:DescribeSecurityGroups',
                'ec2:DescribeNetworkInterfaces',
                'ec2:CreateNetworkInterface',
                'ec2:DeleteNetworkInterface',
                'ec2:AssignPrivateIpAddresses',
                'ec2:UnassignPrivateIpAddresses',
              ],
              resources: ['*'],
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

    // AgentCore only accepts JSON for openApiSchema — convert YAML at synth time.
    const redashSpecYaml = fs.readFileSync(
      path.join(__dirname, '../openapi/redash-api.yaml'), 'utf-8',
    ).replace('${RedashUrl}', redashBackendUrl)
    const redashSpec = JSON.stringify(yaml.load(redashSpecYaml))

    // Upload the rendered JSON spec as an S3 asset. The bedrock-agentcore
    // CFN resource doesn't yet support `privateEndpoint`, so we drive the
    // target via the control-plane API directly (AwsCustomResource). That
    // route's CFN event payload is capped at 4KB, which the ~10KB spec blows
    // through — hence the S3 reference.
    const renderedSpecDir = path.join(os.tmpdir(), `redash-spec-${this.stackName}`)
    fs.mkdirSync(renderedSpecDir, { recursive: true })
    const renderedSpecPath = path.join(renderedSpecDir, 'redash-api.json')
    fs.writeFileSync(renderedSpecPath, redashSpec)
    const redashSpecAsset = new s3assets.Asset(this, 'RedashSpecAsset', {
      path: renderedSpecPath,
    })
    redashSpecAsset.grantRead(gatewayRole)

    const redashTargetName = `redash-target-vpc3-${this.stackName}`
    const redashTargetParameters: { [k: string]: any } = {
      gatewayIdentifier: gateway.attrGatewayIdentifier,
      name: redashTargetName,
      targetConfiguration: {
        mcp: {
          openApiSchema: {
            s3: {
              uri: redashSpecAsset.s3ObjectUrl,
              bucketOwnerAccountId: this.account,
            },
          },
        },
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
    }
    if (redashInstance) {
      redashTargetParameters.privateEndpoint = {
        managedVpcResource: {
          vpcIdentifier: redashInstance.vpc.vpcId,
          subnetIds: redashInstance.privateSubnets.map(s => s.subnetId),
          securityGroupIds: [redashInstance.gatewayEgressSg.securityGroupId],
          endpointIpAddressType: 'IPV4',
        },
      }
    }

    const redashTarget = new cr.AwsCustomResource(this, 'RedashTargetVpc3', {
      onCreate: {
        service: 'bedrock-agentcore-control',
        action: 'CreateGatewayTarget',
        parameters: redashTargetParameters,
        physicalResourceId: cr.PhysicalResourceId.fromResponse('targetId'),
      },
      onUpdate: {
        service: 'bedrock-agentcore-control',
        action: 'UpdateGatewayTarget',
        parameters: {
          ...redashTargetParameters,
          targetId: new cr.PhysicalResourceIdReference(),
        },
        physicalResourceId: cr.PhysicalResourceId.fromResponse('targetId'),
      },
      onDelete: {
        service: 'bedrock-agentcore-control',
        action: 'DeleteGatewayTarget',
        parameters: {
          gatewayIdentifier: gateway.attrGatewayIdentifier,
          targetId: new cr.PhysicalResourceIdReference(),
        },
        // If create failed, physicalResourceId falls back to the Lambda log
        // stream id, which violates the targetId regex. Swallow the resulting
        // ValidationException so rollback can proceed. Also tolerate already-
        // deleted targets on stack tear-down.
        ignoreErrorCodesMatching: 'ValidationException|ResourceNotFoundException',
      },
      policy: cr.AwsCustomResourcePolicy.fromStatements([
        new iam.PolicyStatement({
          actions: [
            'bedrock-agentcore:CreateGatewayTarget',
            'bedrock-agentcore:UpdateGatewayTarget',
            'bedrock-agentcore:DeleteGatewayTarget',
            'bedrock-agentcore:GetGatewayTarget',
            // Internally invoked by Create/Update for targets with privateEndpoint
            'bedrock-agentcore:SynchronizeGatewayTargets',
          ],
          resources: [`arn:aws:bedrock-agentcore:${this.region}:${this.account}:*`],
        }),
        new iam.PolicyStatement({
          actions: ['iam:PassRole'],
          resources: [gatewayRole.roleArn],
          conditions: {
            StringEquals: { 'iam:PassedToService': 'bedrock-agentcore.amazonaws.com' },
          },
        }),
        // CreateGatewayTarget validates the S3 OpenAPI reference at call time
        // using the caller's credentials, so the CR lambda needs read access.
        new iam.PolicyStatement({
          actions: ['s3:GetObject'],
          resources: [redashSpecAsset.bucket.arnForObjects(redashSpecAsset.s3ObjectKey)],
        }),
        // CreateGatewayTarget with privateEndpoint provisions VPC Lattice
        // ENIs as the caller. Grant the full set required upfront.
        new iam.PolicyStatement({
          actions: [
            'ec2:DescribeVpcs',
            'ec2:DescribeSubnets',
            'ec2:DescribeSecurityGroups',
            'ec2:DescribeNetworkInterfaces',
            'ec2:CreateNetworkInterface',
            'ec2:DeleteNetworkInterface',
            'ec2:ModifyNetworkInterfaceAttribute',
            'ec2:AssignPrivateIpAddresses',
            'ec2:UnassignPrivateIpAddresses',
            'ec2:CreateTags',
          ],
          resources: ['*'],
        }),
        new iam.PolicyStatement({
          actions: [
            'vpc-lattice:CreateResourceConfiguration',
            'vpc-lattice:UpdateResourceConfiguration',
            'vpc-lattice:DeleteResourceConfiguration',
            'vpc-lattice:GetResourceConfiguration',
            'vpc-lattice:ListResourceConfigurations',
            'vpc-lattice:CreateServiceNetworkResourceAssociation',
            'vpc-lattice:DeleteServiceNetworkResourceAssociation',
            'vpc-lattice:GetServiceNetworkResourceAssociation',
          ],
          resources: ['*'],
        }),
        // AgentCore creates AWSServiceRoleForBedrockAgentCoreGatewayNetwork on
        // first use of a VPC-egress target. Allow only that specific SLR.
        new iam.PolicyStatement({
          actions: ['iam:CreateServiceLinkedRole'],
          resources: [
            `arn:aws:iam::${this.account}:role/aws-service-role/bedrock-agentcore.amazonaws.com/AWSServiceRoleForBedrockAgentCoreGatewayNetwork`,
          ],
        }),
      ]),
      // The privateEndpoint field was added after the SDK bundled in the Lambda
      // runtime — install the latest SDK at invocation time so it's recognised.
      installLatestAwsSdk: true,
      logRetention: logs.RetentionDays.THREE_MONTHS,
    })
    redashTarget.node.addDependency(redashSpecAsset)

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

    // ── Datadog Credential Provider ──
    // Created after httpApi so tokenEndpointOverride can reference httpApi.apiEndpoint.
    let datadogProvider: DatadogCredentialProviderConstruct | undefined

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

    // ── GitHub bot PAT secret (machine-to-machine GitHub MCP access) ──
    // Seeded at deploy from the GITHUB_BOT_PAT parameter (same env-var flow as
    // the OAuth client secrets), so no post-deploy put-secret-value is needed.
    // The proxy reads it at runtime and injects `Authorization: Bearer <PAT>`
    // on the IAM-protected /github-mcp route. Rotate by updating GITHUB_BOT_PAT
    // and redeploying.
    let githubBotPatSecret: secretsmanager.Secret | undefined
    if (hasGithubBot) {
      githubBotPatSecret = new secretsmanager.Secret(this, 'GitHubBotPat', {
        secretName: `github-bot-pat-${this.stackName}`,
        secretStringValue: cdk.SecretValue.unsafePlainText(props.githubBotPat ?? ''),
        description: 'GitHub bot PAT used by the /github-mcp proxy route',
      })
    }

    const proxyEnvironment: { [k: string]: string } = {
      GATEWAY_URL: gateway.attrGatewayUrl,
      COGNITO_DOMAIN: props.cognitoDomain,
      COGNITO_CLIENT_ID: props.cognitoClientId,
      SESSION_TABLE_NAME: sessionTable.tableName,
    }
    if (githubBotPatSecret) {
      proxyEnvironment.GITHUB_BOT_PAT_SECRET_ARN = githubBotPatSecret.secretArn
    }
    if (hasDatadog) {
      const ddMcpHost = props.datadogMcpHost ?? 'mcp.datadoghq.com'
      proxyEnvironment.DATADOG_TOKEN_ENDPOINT = `https://${ddMcpHost}/api/unstable/mcp-server/token`
      proxyEnvironment.DATADOG_AUTHORIZE_ENDPOINT = `https://${ddMcpHost}/api/unstable/mcp-server/authorize`
    }

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
      environment: proxyEnvironment,
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
    // /github-mcp injects a shared bot PAT, so it must only be reachable by the
    // gateway itself (SigV4 via its service role), never directly. Protect it
    // with IAM auth; all other routes (OAuth flow, /mcp) stay public.
    const iamAuthorizer = new HttpIamAuthorizer()
    httpApi.addRoutes({ path: '/github-mcp', methods: [apigwv2.HttpMethod.ANY], integration, authorizer: iamAuthorizer })
    httpApi.addRoutes({ path: '/github-mcp/{proxy+}', methods: [apigwv2.HttpMethod.ANY], integration, authorizer: iamAuthorizer })
    httpApi.addRoutes({ path: '/{proxy+}', methods: [apigwv2.HttpMethod.ANY], integration })
    httpApi.addRoutes({ path: '/', methods: [apigwv2.HttpMethod.ANY], integration })

    // Let the gateway service role invoke the IAM-protected /github-mcp routes
    // (github-bot target uses GATEWAY_IAM_ROLE / SigV4 outbound auth).
    if (hasGithubBot) {
      gatewayRole.addToPolicy(new iam.PolicyStatement({
        actions: ['execute-api:Invoke'],
        resources: [`arn:aws:execute-api:${this.region}:${this.account}:${httpApi.apiId}/*/*/github-mcp*`],
      }))
    }

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

    // ── Datadog Credential Provider (needs proxy URL for token relay) ──
    if (hasDatadog) {
      datadogProvider = new DatadogCredentialProviderConstruct(
        this, 'DatadogProvider', {
          uniqueId: 'datadog',
          clientId: props.datadogClientId!,
          mcpHost: props.datadogMcpHost,
          tokenEndpointOverride: `${httpApi.apiEndpoint}/datadog-token`,
          issuerOverride: httpApi.apiEndpoint,
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
    if (githubBotPatSecret) {
      new cdk.CfnOutput(this, 'GitHubBotPatSecretArn', {
        value: githubBotPatSecret.secretArn,
        description: 'Bot PAT secret (seeded at deploy from GITHUB_BOT_PAT)',
      })
    }
    if (datadogProvider) {
      new cdk.CfnOutput(this, 'DatadogCredentialProviderName', {
        value: datadogProvider.credentialProviderName,
      })
      new cdk.CfnOutput(this, 'DatadogCredentialProviderArn', {
        value: datadogProvider.credentialProviderArn,
      })
    }
  }
}
