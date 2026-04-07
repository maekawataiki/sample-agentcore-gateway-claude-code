import * as cdk from "aws-cdk-lib";
import * as lambda from "aws-cdk-lib/aws-lambda";
import * as logs from "aws-cdk-lib/aws-logs";
import * as dynamodb from "aws-cdk-lib/aws-dynamodb";
import { Construct } from "constructs";
import * as path from "path";

export interface ApiKeyInterceptorLambdaConstructProps {
  readonly apiKeyTable: dynamodb.Table;
}

/**
 * API Key Request Interceptor Lambda.
 *
 * Extracts user identity from JWT, looks up API key in DynamoDB,
 * and injects it as a request header for the backend service.
 */
export class ApiKeyInterceptorLambdaConstruct extends Construct {
  public readonly requestInterceptor: lambda.Function;

  constructor(
    scope: Construct,
    id: string,
    props: ApiKeyInterceptorLambdaConstructProps
  ) {
    super(scope, id);

    this.requestInterceptor = new lambda.Function(this, "RequestInterceptor", {
      runtime: lambda.Runtime.PYTHON_3_13,
      handler: "index.lambda_handler",
      code: lambda.Code.fromAsset(
        path.join(__dirname, "../../lambda/apikey_request_interceptor")
      ),
      architecture: lambda.Architecture.ARM_64,
      timeout: cdk.Duration.seconds(30),
      description: "API Key Request Interceptor - DynamoDB lookup + header injection",
      tracing: lambda.Tracing.ACTIVE,
      logRetention: logs.RetentionDays.THREE_MONTHS,
      environment: {
        APIKEY_TABLE_NAME: props.apiKeyTable.tableName,
        REGION: cdk.Stack.of(this).region,
      },
    });

    props.apiKeyTable.grantReadData(this.requestInterceptor);
  }
}
