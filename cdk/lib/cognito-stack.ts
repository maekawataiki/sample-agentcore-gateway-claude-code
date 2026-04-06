/**
 * Shared Cognito Stack (us-east-1) for AgentCore Gateway CUSTOM_JWT authentication.
 *
 * All gateway stacks (FGAC, ApiKeySwap, GitHub/Notion 3LO) use this Cognito
 * User Pool for inbound authentication.
 */
import * as cdk from 'aws-cdk-lib'
import * as cognito from 'aws-cdk-lib/aws-cognito'
import { Construct } from 'constructs'

export interface CognitoStackProps extends cdk.StackProps {
  /** Cognito Hosted UI domain prefix (must be globally unique) */
  readonly domainPrefix: string
  /**
   * Localhost callback ports used by Claude Code MCP OAuth.
   * Callback URLs are generated for both 127.0.0.1 and localhost.
   * @default [9090, 9091, 9092, 9093]
   */
  readonly callbackPorts?: number[]
}

export class CognitoStack extends cdk.Stack {
  public readonly userPool: cognito.UserPool
  public readonly appClient: cognito.UserPoolClient
  public readonly userPoolId: string
  public readonly appClientId: string
  public readonly cognitoDomain: string
  public readonly discoveryUrl: string

  constructor(scope: Construct, id: string, props: CognitoStackProps) {
    super(scope, id, props)

    const ports = props.callbackPorts ?? [9090, 9091, 9092, 9093]

    // ── User Pool ──
    this.userPool = new cognito.UserPool(this, 'UserPool', {
      userPoolName: 'remote-mcp-users',
      selfSignUpEnabled: false,
      signInAliases: { email: true },
      standardAttributes: {
        email: { required: true, mutable: false },
      },
      passwordPolicy: {
        minLength: 12,
        requireLowercase: true,
        requireUppercase: true,
        requireDigits: true,
        requireSymbols: true,
      },
      accountRecovery: cognito.AccountRecovery.EMAIL_ONLY,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    })

    // ── Hosted UI Domain ──
    this.userPool.addDomain('Domain', {
      cognitoDomain: { domainPrefix: props.domainPrefix },
    })
    this.cognitoDomain = `${props.domainPrefix}.auth.${this.region}.amazoncognito.com`

    // ── Localhost callback URLs ──
    const callbackUrls: string[] = []
    for (const port of ports) {
      for (const host of ['http://127.0.0.1', 'http://localhost']) {
        callbackUrls.push(`${host}:${port}`)
        callbackUrls.push(`${host}:${port}/callback`)
        callbackUrls.push(`${host}:${port}/oauth/callback`)
      }
    }

    // ── App Client (public, PKCE) ──
    this.appClient = this.userPool.addClient('AppClient', {
      userPoolClientName: 'remote-mcp-claude-code',
      generateSecret: false,
      authFlows: { userSrp: true },
      oAuth: {
        flows: { authorizationCodeGrant: true },
        // All standard OIDC scopes — AgentCore Gateway direct access requests
        // all scopes from Cognito's OIDC discovery (including phone)
        scopes: [
          cognito.OAuthScope.OPENID,
          cognito.OAuthScope.EMAIL,
          cognito.OAuthScope.PROFILE,
          cognito.OAuthScope.PHONE,
        ],
        callbackUrls,
      },
      supportedIdentityProviders: [
        cognito.UserPoolClientIdentityProvider.COGNITO,
      ],
      idTokenValidity: cdk.Duration.hours(1),
      accessTokenValidity: cdk.Duration.hours(1),
      refreshTokenValidity: cdk.Duration.days(30),
      enableTokenRevocation: true,
    })

    this.userPoolId = this.userPool.userPoolId
    this.appClientId = this.appClient.userPoolClientId
    this.discoveryUrl = `https://cognito-idp.${this.region}.amazonaws.com/${this.userPoolId}/.well-known/openid-configuration`

    // ── Outputs ──
    new cdk.CfnOutput(this, 'UserPoolId', { value: this.userPoolId })
    new cdk.CfnOutput(this, 'AppClientId', { value: this.appClientId })
    new cdk.CfnOutput(this, 'CognitoDomain', { value: this.cognitoDomain })
    new cdk.CfnOutput(this, 'DiscoveryUrl', { value: this.discoveryUrl })
  }
}
