import * as cdk from "aws-cdk-lib";
import * as iam from "aws-cdk-lib/aws-iam";
import * as cr from "aws-cdk-lib/custom-resources";
import * as logs from "aws-cdk-lib/aws-logs";
import { Construct } from "constructs";

export interface DatadogCredentialProviderProps {
  readonly uniqueId: string;
  readonly clientId: string;
  /**
   * Datadog site hostname for the MCP server (e.g. "mcp.ap1.datadoghq.com").
   * Defaults to "mcp.datadoghq.com" (US1).
   * AP1: "mcp.ap1.datadoghq.com"
   * EU1: "mcp.eu1.datadoghq.com"
   */
  readonly mcpHost?: string;
  /**
   * Override the token endpoint URL. Used to point to the proxy's
   * /datadog-token relay so client_secret is stripped before forwarding
   * to Datadog (Datadog is a public client, PKCE-only).
   */
  readonly tokenEndpointOverride?: string;
  /**
   * Override the issuer value in authorizationServerMetadata. AgentCore
   * requires issuer domain == tokenEndpoint domain. When tokenEndpointOverride
   * is a CDK token (e.g. httpApi.apiEndpoint + path), pass the origin here
   * directly to avoid calling new URL() on an unresolved token at synth time.
   */
  readonly issuerOverride?: string;
}

/**
 * Datadog MCP Credential Provider Construct
 *
 * Datadog MCP is a public client (no client_secret from DCR); PKCE (S256) is mandatory.
 * AgentCore requires a non-empty clientSecret for client_secret_post — we pass "placeholder"
 * since Datadog's token endpoint ignores the secret when a valid PKCE code_verifier is present.
 *
 * Client must be registered via DCR against the site-specific registration endpoint:
 *   bin/register-datadog-dcr.sh --export   (update MCP_HOST in the script for non-US1 sites)
 */
export class DatadogCredentialProviderConstruct extends Construct {
  public readonly credentialProviderArn: string;
  public readonly credentialProviderName: string;
  public readonly oauth2ProviderResource: cr.AwsCustomResource;

  constructor(
    scope: Construct,
    id: string,
    props: DatadogCredentialProviderProps
  ) {
    super(scope, id);

    const { uniqueId, clientId } = props;
    const mcpHost = props.mcpHost ?? "mcp.datadoghq.com";
    const stack = cdk.Stack.of(this);

    const nameVersion = "v1";
    this.credentialProviderName = `datadog-mcp-${uniqueId}-${stack.stackName}-${nameVersion}`;

    const base = `https://${mcpHost}`;
    // Use the proxy relay endpoint if provided so the proxy can strip
    // client_secret before forwarding to Datadog (public client, PKCE-only).
    const tokenEndpoint = props.tokenEndpointOverride ?? `${base}/api/unstable/mcp-server/token`;
    // AgentCore requires issuer domain == tokenEndpoint domain for CustomOauth2.
    // When the proxy relay is used, issuerOverride must be set to the proxy origin
    // (e.g. httpApi.apiEndpoint) — CDK tokens can't be parsed by new URL() at synth time.
    const issuerOrigin = props.issuerOverride ?? base;
    const customOauth2ProviderConfig = {
      clientId,
      // AgentCore rejects empty/absent clientSecret for client_secret_post.
      // The /datadog-token relay strips it before forwarding to Datadog.
      clientSecret: "placeholder",
      oauthDiscovery: {
        authorizationServerMetadata: {
          issuer: issuerOrigin,
          // Route through the proxy so it can strip scope= before redirecting to
          // Datadog. Datadog MCP has scopes_supported:[] and rejects any scope value.
          authorizationEndpoint: props.issuerOverride
            ? `${props.issuerOverride}/datadog-authorize`
            : `${base}/api/unstable/mcp-server/authorize`,
          tokenEndpoint,
          tokenEndpointAuthMethods: ["client_secret_post"],
          responseTypes: ["code"],
        },
      },
    };

    const oauth2Provider = new cr.AwsCustomResource(
      this,
      "DatadogMcpOauth2Provider",
      {
        onCreate: {
          service: "bedrock-agentcore-control",
          action: "CreateOauth2CredentialProvider",
          parameters: {
            name: this.credentialProviderName,
            credentialProviderVendor: "CustomOauth2",
            oauth2ProviderConfigInput: { customOauth2ProviderConfig },
          },
          physicalResourceId: cr.PhysicalResourceId.of(this.credentialProviderName),
        },
        onUpdate: {
          service: "bedrock-agentcore-control",
          action: "UpdateOauth2CredentialProvider",
          parameters: {
            name: this.credentialProviderName,
            credentialProviderVendor: "CustomOauth2",
            oauth2ProviderConfigInput: { customOauth2ProviderConfig },
          },
          physicalResourceId: cr.PhysicalResourceId.of(this.credentialProviderName),
        },
        onDelete: {
          service: "bedrock-agentcore-control",
          action: "DeleteOauth2CredentialProvider",
          parameters: {
            name: this.credentialProviderName,
          },
        },
        policy: cr.AwsCustomResourcePolicy.fromStatements([
          new iam.PolicyStatement({
            actions: [
              "bedrock-agentcore:CreateOauth2CredentialProvider",
              "bedrock-agentcore:UpdateOauth2CredentialProvider",
              "bedrock-agentcore:DeleteOauth2CredentialProvider",
              "bedrock-agentcore:GetOauth2CredentialProvider",
              "bedrock-agentcore:CreateTokenVault",
              "bedrock-agentcore:GetTokenVault",
            ],
            resources: [`arn:aws:bedrock-agentcore:${stack.region}:${stack.account}:*`],
          }),
          new iam.PolicyStatement({
            actions: [
              "secretsmanager:CreateSecret",
              "secretsmanager:DeleteSecret",
              "secretsmanager:PutSecretValue",
            ],
            resources: [`arn:aws:secretsmanager:${stack.region}:${stack.account}:secret:*`],
          }),
        ]),
        logRetention: logs.RetentionDays.THREE_MONTHS,
      }
    );

    this.credentialProviderArn = `arn:aws:bedrock-agentcore:${stack.region}:${stack.account}:token-vault/default/oauth2credentialprovider/${this.credentialProviderName}`;
    this.oauth2ProviderResource = oauth2Provider;
  }
}
