import * as cdk from "aws-cdk-lib";
import * as dynamodb from "aws-cdk-lib/aws-dynamodb";
import { Construct } from "constructs";

/**
 * Single DynamoDB table for the admin control panel.
 *
 * Layout:
 *   PK = "SERVICES",        SK = <serviceName>           → service metadata
 *   PK = "SVC#<service>",   SK = "CLAIM#<key>#<value>"   → claim → API key mapping
 *
 * Access patterns:
 *   - Interceptor: BatchGetItem PK=SVC#<svc>, SK=CLAIM#<k>#<v> for each JWT claim candidate
 *   - Admin list services:   Query PK=SERVICES
 *   - Admin list mappings:   Query PK=SVC#<svc>
 *   - Admin CRUD mapping:    GetItem/PutItem/DeleteItem on single composite key
 */
export class AdminTablesConstruct extends Construct {
  public readonly table: dynamodb.Table;

  constructor(scope: Construct, id: string) {
    super(scope, id);

    const stack = cdk.Stack.of(this);
    const suffix = (stack.node.tryGetContext("tableSuffix") as string | undefined) ?? "v1";

    this.table = new dynamodb.Table(this, "Table", {
      tableName: `admin-${stack.stackName}-${suffix}`,
      partitionKey: { name: "PK", type: dynamodb.AttributeType.STRING },
      sortKey: { name: "SK", type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      encryption: dynamodb.TableEncryption.AWS_MANAGED,
      pointInTimeRecoverySpecification: { pointInTimeRecoveryEnabled: true },
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });
  }
}
