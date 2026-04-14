import * as cdk from "aws-cdk-lib";
import * as iam from "aws-cdk-lib/aws-iam";
import * as cr from "aws-cdk-lib/custom-resources";
import * as logs from "aws-cdk-lib/aws-logs";
import { Construct } from "constructs";

export interface NotionCredentialProviderProps {
  /** Unique ID for resource naming */
  readonly uniqueId: string;
  /** Notion MCP OAuth Client ID (issued by mcp.notion.com via DCR) */
  readonly clientId: string;
  /** Notion MCP OAuth Client Secret (issued by mcp.notion.com via DCR) */
  readonly clientSecret: string;
}

/**
 * Notion Credential Provider Construct
 *
 * Creates an OAuth2 Credential Provider for Notion MCP (mcp.notion.com).
 *
 * Notion's MCP server is a separate OAuth 2.1 authorization server from
 * the Notion API (api.notion.com). The client credentials used here MUST
 * be issued by mcp.notion.com via Dynamic Client Registration (RFC 7591),
 * not from the Notion Developer Dashboard.
 *
 * The credential provider name is stable (no config hash) so that the
 * callback URL returned by AgentCore stays constant across credential
 * rotations. This is critical because the DCR-registered redirect_uri at
 * mcp.notion.com must match AgentCore's callback URL; rotating the
 * callback URL would invalidate the DCR registration.
 *
 * To rotate credentials:
 *   1. Keep the provider name stable
 *   2. Update clientId/clientSecret in parameter.ts
 *   3. cdk deploy triggers an in-place UpdateOauth2CredentialProvider
 *
 * To force a full replacement (e.g. after intentional DCR re-registration
 * with a new redirect_uri), bump `nameVersion`.
 */
export class NotionCredentialProviderConstruct extends Construct {
  public readonly credentialProviderArn: string;
  public readonly credentialProviderName: string;

  constructor(
    scope: Construct,
    id: string,
    props: NotionCredentialProviderProps
  ) {
    super(scope, id);

    const { uniqueId, clientId, clientSecret } = props;
    const stack = cdk.Stack.of(this);

    // Stable provider name. Bump `nameVersion` intentionally (e.g. "v2") to
    // force replacement and receive a fresh callback URL from AgentCore —
    // that in turn requires re-running DCR against mcp.notion.com.
    const nameVersion = "v1";
    this.credentialProviderName = `notion-mcp-${uniqueId}-${stack.stackName}-${nameVersion}`;

    const oauth2ProviderConfigInput = {
      customOauth2ProviderConfig: {
        clientId,
        clientSecret,
        oauthDiscovery: {
          authorizationServerMetadata: {
            issuer: "https://mcp.notion.com",
            authorizationEndpoint: "https://mcp.notion.com/authorize",
            tokenEndpoint: "https://mcp.notion.com/token",
            tokenEndpointAuthMethods: ["client_secret_basic"],
            responseTypes: ["code"],
          },
        },
      },
    };

    const oauth2Provider = new cr.AwsCustomResource(
      this,
      "NotionMcpOauth2Provider",
      {
        onCreate: {
          service: "bedrock-agentcore-control",
          action: "CreateOauth2CredentialProvider",
          parameters: {
            name: this.credentialProviderName,
            credentialProviderVendor: "CustomOauth2",
            oauth2ProviderConfigInput,
          },
          physicalResourceId: cr.PhysicalResourceId.of(this.credentialProviderName),
        },
        onUpdate: {
          service: "bedrock-agentcore-control",
          action: "UpdateOauth2CredentialProvider",
          parameters: {
            name: this.credentialProviderName,
            credentialProviderVendor: "CustomOauth2",
            oauth2ProviderConfigInput,
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

    // Construct the ARN deterministically instead of reading it from the API
    // response. UpdateOauth2CredentialProvider does not return
    // credentialProviderArn, which breaks AwsCustomResource.getResponseField
    // on every stack update. The ARN format is documented and stable:
    //   arn:aws:bedrock-agentcore:<region>:<account>:token-vault/default/oauth2credentialprovider/<name>
    this.credentialProviderArn = `arn:aws:bedrock-agentcore:${stack.region}:${stack.account}:token-vault/default/oauth2credentialprovider/${this.credentialProviderName}`;

    // Expose the underlying custom resource so callers can establish
    // explicit CloudFormation ordering if needed — the plain-string ARN
    // above carries no implicit dependency.
    this.oauth2ProviderResource = oauth2Provider;
  }

  public readonly oauth2ProviderResource!: cr.AwsCustomResource;
}
