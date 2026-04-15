import * as cdk from "aws-cdk-lib";
import * as lambda from "aws-cdk-lib/aws-lambda";
import * as logs from "aws-cdk-lib/aws-logs";
import * as dynamodb from "aws-cdk-lib/aws-dynamodb";
import { Construct } from "constructs";
import * as path from "path";

export interface ApiKeyInterceptorLambdaConstructProps {
  readonly adminTable: dynamodb.Table;
  /**
   * Comma-separated list of JWT claim keys the interceptor is allowed to use
   * for key resolution (priority order: earliest first).
   * Default: "email,cognito:groups"
   */
  readonly allowedClaimKeys?: string;
}

/**
 * API Key Request Interceptor Lambda.
 *
 * Resolves API keys by matching JWT claims against the AdminTable:
 *   PK=SVC#<service>, SK=CLAIM#<claimKey>#<claimValue>
 *
 * One BatchGetItem per request regardless of how many claim candidates.
 */
export class ApiKeyInterceptorLambdaConstruct extends Construct {
  public readonly requestInterceptor: lambda.Function;

  constructor(
    scope: Construct,
    id: string,
    props: ApiKeyInterceptorLambdaConstructProps,
  ) {
    super(scope, id);

    this.requestInterceptor = new lambda.Function(this, "RequestInterceptor", {
      runtime: lambda.Runtime.PYTHON_3_13,
      handler: "index.lambda_handler",
      code: lambda.Code.fromAsset(
        path.join(__dirname, "../../lambda/apikey_request_interceptor"),
      ),
      architecture: lambda.Architecture.ARM_64,
      timeout: cdk.Duration.seconds(30),
      description: "API Key Request Interceptor — JWT claim → API key resolution",
      tracing: lambda.Tracing.ACTIVE,
      logRetention: logs.RetentionDays.THREE_MONTHS,
      environment: {
        ADMIN_TABLE_NAME: props.adminTable.tableName,
        ALLOWED_CLAIM_KEYS: props.allowedClaimKeys ?? "email,cognito:groups",
        REGION: cdk.Stack.of(this).region,
      },
    });

    props.adminTable.grantReadData(this.requestInterceptor);
  }
}
