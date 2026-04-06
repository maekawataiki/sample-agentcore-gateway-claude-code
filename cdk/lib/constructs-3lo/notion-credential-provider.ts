import * as cdk from "aws-cdk-lib";
import * as iam from "aws-cdk-lib/aws-iam";
import * as cr from "aws-cdk-lib/custom-resources";
import * as logs from "aws-cdk-lib/aws-logs";
import { Construct } from "constructs";

export interface NotionCredentialProviderProps {
  /** Unique ID for resource naming */
  readonly uniqueId: string;
  /** Notion OAuth Integration Client ID */
  readonly clientId: string;
  /** Notion OAuth Integration Client Secret */
  readonly clientSecret: string;
}

/**
 * Notion Resource Credential Provider Construct
 *
 * Creates a Resource Credential Provider for Notion OAuth 3LO.
 * Uses the built-in NotionOauth2 vendor which handles Notion's OAuth
 * specifics (token endpoint auth, grant type) automatically.
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
    this.credentialProviderName = `notion-oauth-${uniqueId}-${stack.stackName}`;

    const oauth2ProviderConfigInput = {
      includedOauth2ProviderConfig: {
        clientId,
        clientSecret,
      },
    };

    const oauth2Provider = new cr.AwsCustomResource(
      this,
      "NotionCustomOauth2Provider",
      {
        onCreate: {
          service: "bedrock-agentcore-control",
          action: "CreateOauth2CredentialProvider",
          parameters: {
            name: this.credentialProviderName,
            credentialProviderVendor: "NotionOauth2",
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
            credentialProviderVendor: "NotionOauth2",
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
            actions: ["bedrock-agentcore:*", "secretsmanager:*"],
            resources: ["*"],
          }),
        ]),
        logRetention: logs.RetentionDays.ONE_WEEK,
      }
    );

    this.credentialProviderArn = oauth2Provider.getResponseField(
      "credentialProviderArn"
    );
  }
}
