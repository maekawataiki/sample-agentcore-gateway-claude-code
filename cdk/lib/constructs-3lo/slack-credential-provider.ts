import * as cdk from "aws-cdk-lib";
import * as iam from "aws-cdk-lib/aws-iam";
import * as cr from "aws-cdk-lib/custom-resources";
import * as logs from "aws-cdk-lib/aws-logs";
import { Construct } from "constructs";

export interface SlackCredentialProviderProps {
  readonly uniqueId: string;
  readonly clientId: string;
  readonly clientSecret: string;
}

/**
 * Slack Credential Provider Construct
 *
 * Slack MCP's AS metadata declares:
 *   authorization_endpoint: https://slack.com/oauth/v2_user/authorize
 *   token_endpoint: https://slack.com/api/oauth.v2.user.access
 *   token_endpoint_auth_methods_supported: ["client_secret_post"]
 *
 * The /oauth/v2_user/authorize endpoint treats the standard `scope` parameter
 * as User Token Scopes (no `user_scope` rewriting needed). This is different
 * from /oauth/v2/authorize which uses `scope` for Bot and `user_scope` for User.
 */
export class SlackCredentialProviderConstruct extends Construct {
  public readonly credentialProviderArn: string;
  public readonly credentialProviderName: string;
  public readonly oauth2ProviderResource: cr.AwsCustomResource;

  constructor(
    scope: Construct,
    id: string,
    props: SlackCredentialProviderProps
  ) {
    super(scope, id);

    const { uniqueId, clientId, clientSecret } = props;
    const stack = cdk.Stack.of(this);
    this.credentialProviderName = `slack-custom-${uniqueId}-${stack.stackName}`;

    const oauth2ProviderConfigInput = {
      customOauth2ProviderConfig: {
        clientId,
        clientSecret,
        oauthDiscovery: {
          authorizationServerMetadata: {
            issuer: "https://slack.com",
            authorizationEndpoint: "https://slack.com/oauth/v2_user/authorize",
            tokenEndpoint: "https://slack.com/api/oauth.v2.user.access",
            tokenEndpointAuthMethods: ["client_secret_post"],
            responseTypes: ["code"],
          },
        },
      },
    };

    const oauth2Provider = new cr.AwsCustomResource(
      this,
      "SlackOauth2Provider",
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

    this.credentialProviderArn = `arn:aws:bedrock-agentcore:${stack.region}:${stack.account}:token-vault/default/oauth2credentialprovider/${this.credentialProviderName}`;
    this.oauth2ProviderResource = oauth2Provider;
  }
}
