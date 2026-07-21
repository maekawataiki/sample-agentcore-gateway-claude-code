import * as cdk from 'aws-cdk-lib'
import * as ecrassets from 'aws-cdk-lib/aws-ecr-assets'
import * as iam from 'aws-cdk-lib/aws-iam'
import * as logs from 'aws-cdk-lib/aws-logs'
import * as bedrockagentcore from 'aws-cdk-lib/aws-bedrockagentcore'
import * as path from 'path'
import { Construct } from 'constructs'

export interface FirebaseMcpRuntimeStackProps extends cdk.StackProps {
  readonly discoveryUrl: string
  readonly cognitoClientId: string
}

/**
 * Hosts the stdio-only Firebase CLI MCP server behind an independent
 * AgentCore Runtime endpoint. Google credentials are exchanged through AWS
 * Workload Identity Federation; no service-account key is stored in AWS.
 */
export class FirebaseMcpRuntimeStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props: FirebaseMcpRuntimeStackProps) {
    super(scope, id, props)

    const gcpSaKeySecretArn = new cdk.CfnParameter(this, 'GcpSaKeySecretArn', {
      type: 'String',
      description: 'ARN of the Secrets Manager secret containing the GCP service account key JSON',
    })

    const image = new ecrassets.DockerImageAsset(this, 'FirebaseMcpImage', {
      directory: path.join(__dirname, '../runtime/firebase-mcp'),
      platform: ecrassets.Platform.LINUX_ARM64,
    })

    // Keep ECR permissions embedded in the Role resource. AgentCore validates
    // the container URI at Runtime creation, before detached IAM policies are
    // guaranteed to be attached.
    const runtimeRole = new iam.CfnRole(this, 'FirebaseMcpRuntimeRole', {
      assumeRolePolicyDocument: {
        Version: '2012-10-17',
        Statement: [{
          Effect: 'Allow',
          Principal: { Service: 'bedrock-agentcore.amazonaws.com' },
          Action: 'sts:AssumeRole',
          Condition: {
            StringEquals: { 'aws:SourceAccount': this.account },
            ArnLike: { 'aws:SourceArn': `arn:aws:bedrock-agentcore:${this.region}:${this.account}:runtime/*` },
          },
        }],
      },
      description: 'Execution role for the Firebase MCP AgentCore Runtime',
      policies: [{
        policyName: 'RuntimeImagePullAndLogs',
        policyDocument: {
          Version: '2012-10-17',
          Statement: [
            {
              Effect: 'Allow',
              Action: ['ecr:GetAuthorizationToken'],
              Resource: '*',
            },
            {
              Effect: 'Allow',
              Action: [
                'ecr:BatchCheckLayerAvailability',
                'ecr:BatchGetImage',
                'ecr:GetDownloadUrlForLayer',
              ],
              Resource: image.repository.repositoryArn,
            },
            {
              Effect: 'Allow',
              Action: ['logs:CreateLogStream', 'logs:PutLogEvents'],
              Resource: `arn:aws:logs:${this.region}:${this.account}:log-group:/aws/bedrock-agentcore/runtimes/*:log-stream:*`,
            },
            {
              Effect: 'Allow',
              Action: ['secretsmanager:GetSecretValue'],
              Resource: gcpSaKeySecretArn.valueAsString,
            },
          ],
        },
      }],
    })

    const runtime = new bedrockagentcore.CfnRuntime(this, 'FirebaseMcpRuntime', {
      agentRuntimeName: `firebase_mcp_${this.stackName}`.slice(0, 48),
      description: 'Firebase CLI MCP bridged from stdio through AWS-to-GCP Workload Identity Federation',
      agentRuntimeArtifact: { containerConfiguration: { containerUri: image.imageUri } },
      roleArn: runtimeRole.attrArn,
      protocolConfiguration: 'MCP',
      networkConfiguration: { networkMode: 'PUBLIC' },
      authorizerConfiguration: {
        customJwtAuthorizer: {
          discoveryUrl: props.discoveryUrl,
          allowedClients: [props.cognitoClientId],
        },
      },
      lifecycleConfiguration: {
        idleRuntimeSessionTimeout: 900,
        maxLifetime: 3600,
      },
      environmentVariables: {
        GCP_SA_KEY_SECRET_ARN: gcpSaKeySecretArn.valueAsString,
      },
      tags: {
        Service: 'firebase-mcp',
        Authentication: 'aws-gcp-wif',
      },
    })

    const endpoint = new bedrockagentcore.CfnRuntimeEndpoint(this, 'FirebaseMcpEndpoint', {
      name: `firebase_mcp_${this.stackName}`.slice(0, 48),
      description: 'Stable endpoint for the Firebase CLI MCP AgentCore Runtime',
      agentRuntimeId: runtime.attrAgentRuntimeId,
      agentRuntimeVersion: runtime.attrAgentRuntimeVersion,
      tags: {
        Service: 'firebase-mcp',
      },
    })

    new logs.CfnLogGroup(this, 'FirebaseMcpRuntimeLogGroup', {
      logGroupName: `/aws/bedrock-agentcore/runtimes/${runtime.attrAgentRuntimeId}-DEFAULT`,
      retentionInDays: 90,
    })

    new cdk.CfnOutput(this, 'FirebaseMcpRuntimeArn', {
      value: runtime.attrAgentRuntimeArn,
    })
    new cdk.CfnOutput(this, 'FirebaseMcpRuntimeId', {
      value: runtime.attrAgentRuntimeId,
    })
    new cdk.CfnOutput(this, 'FirebaseMcpRuntimeEndpointArn', {
      value: endpoint.attrAgentRuntimeEndpointArn,
      description: 'Stable AgentCore Runtime endpoint, separate from GatewayStack',
    })
  }
}
