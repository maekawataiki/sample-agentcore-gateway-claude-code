import * as cdk from "aws-cdk-lib";
import * as dynamodb from "aws-cdk-lib/aws-dynamodb";
import { Construct } from "constructs";

/**
 * DynamoDB table for user -> API key mapping.
 *
 * Schema:
 *   PK: userId (string) - Cognito username or sub
 *   Attributes: apiKey (string), headerName (string), serviceName (string)
 */
export class ApiKeyMappingTableConstruct extends Construct {
  public readonly table: dynamodb.Table;

  constructor(scope: Construct, id: string) {
    super(scope, id);

    this.table = new dynamodb.Table(this, "Table", {
      tableName: `apikey-mapping-${cdk.Stack.of(this).stackName}`,
      partitionKey: { name: "userId", type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      encryption: dynamodb.TableEncryption.AWS_MANAGED,
      pointInTimeRecoverySpecification: { pointInTimeRecoveryEnabled: true },
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });
  }
}
