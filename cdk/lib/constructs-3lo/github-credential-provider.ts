import * as cdk from "aws-cdk-lib";
import * as iam from "aws-cdk-lib/aws-iam";
import * as cr from "aws-cdk-lib/custom-resources";
import * as logs from "aws-cdk-lib/aws-logs";
import { Construct } from "constructs";

export interface GitHubCredentialProviderProps {
  /** Unique ID for resource naming */
  readonly uniqueId: string;
  /** GitHub OAuth App Client ID */
  readonly clientId: string;
  /** GitHub OAuth App Client Secret */
  readonly clientSecret: string;
}

/**
 * GitHub Credential Provider Construct (for Gateway OpenAPI Target)
 *
 * Creates an OAuth2 Credential Provider for GitHub 3LO.
 * Uses customOauth2ProviderConfig with explicit GitHub OAuth endpoints.
 */
export class GitHubCredentialProviderConstruct extends Construct {
  public readonly credentialProviderArn: string;
  public readonly credentialProviderName: string;

  constructor(
    scope: Construct,
    id: string,
    props: GitHubCredentialProviderProps
  ) {
    super(scope, id);

    const { uniqueId, clientId, clientSecret } = props;
    const stack = cdk.Stack.of(this);
    this.credentialProviderName = `github-custom-oauth-${uniqueId}-${stack.stackName}`;

    const oauth2ProviderConfigInput = {
      customOauth2ProviderConfig: {
        clientId,
        clientSecret,
        oauthDiscovery: {
          authorizationServerMetadata: {
            issuer: "https://github.com",
            authorizationEndpoint: "https://github.com/login/oauth/authorize",
            tokenEndpoint: "https://github.com/login/oauth/access_token",
            tokenEndpointAuthMethods: ["client_secret_post"],
          },
        },
      },
    };

    const oauth2Provider = new cr.AwsCustomResource(
      this,
      "GitHubCredentialProvider",
      {
        onCreate: {
          service: "bedrock-agentcore-control",
          action: "CreateOauth2CredentialProvider",
          parameters: {
            name: this.credentialProviderName,
            credentialProviderVendor: "CustomOauth2",
            oauth2ProviderConfigInput,
          },
          physicalResourceId: cr.PhysicalResourceId.fromResponse(
            "credentialProviderArn"
          ),
        },
        onUpdate: {
          service: "bedrock-agentcore-control",
          action: "UpdateOauth2CredentialProvider",
          parameters: {
            name: this.credentialProviderName,
            credentialProviderVendor: "CustomOauth2",
            oauth2ProviderConfigInput,
          },
          physicalResourceId: cr.PhysicalResourceId.fromResponse(
            "credentialProviderArn"
          ),
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
            ],
            resources: [`arn:aws:bedrock-agentcore:${stack.region}:${stack.account}:*`],
          }),
          new iam.PolicyStatement({
            actions: ["secretsmanager:CreateSecret", "secretsmanager:DeleteSecret", "secretsmanager:PutSecretValue"],
            resources: [`arn:aws:secretsmanager:${stack.region}:${stack.account}:secret:*`],
          }),
        ]),
        logRetention: logs.RetentionDays.THREE_MONTHS,
      }
    );

    this.credentialProviderArn = oauth2Provider.getResponseField(
      "credentialProviderArn"
    );
  }
}
