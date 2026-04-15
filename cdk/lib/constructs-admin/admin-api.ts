import * as cdk from "aws-cdk-lib";
import * as apigateway from "aws-cdk-lib/aws-apigateway";
import * as cognito from "aws-cdk-lib/aws-cognito";
import * as dynamodb from "aws-cdk-lib/aws-dynamodb";
import * as lambda from "aws-cdk-lib/aws-lambda";
import * as logs from "aws-cdk-lib/aws-logs";
import * as path from "path";
import { Construct } from "constructs";

export interface AdminApiConstructProps {
  readonly cognitoUserPoolId: string;
  readonly adminGroupName: string;
  readonly adminTable: dynamodb.Table;
}

/**
 * Admin Control Panel REST API.
 *
 * REST API Gateway + Cognito Authorizer + Lambda handler.
 * Only users in the admin Cognito group (verified via cognito:groups claim)
 * can access these endpoints.
 */
export class AdminApiConstruct extends Construct {
  public readonly apiUrl: string;

  constructor(scope: Construct, id: string, props: AdminApiConstructProps) {
    super(scope, id);

    const stack = cdk.Stack.of(this);

    const handler = new lambda.Function(this, "Handler", {
      functionName: `admin-api-${stack.stackName}`,
      runtime: lambda.Runtime.PYTHON_3_13,
      handler: "handler.lambda_handler",
      code: lambda.Code.fromAsset(
        path.join(__dirname, "../../lambda/admin_api"),
      ),
      architecture: lambda.Architecture.ARM_64,
      timeout: cdk.Duration.seconds(30),
      memorySize: 256,
      description: "Admin Control Panel API — service + claim-mapping CRUD",
      tracing: lambda.Tracing.ACTIVE,
      logRetention: logs.RetentionDays.THREE_MONTHS,
      environment: {
        ADMIN_TABLE_NAME: props.adminTable.tableName,
        ADMIN_GROUP_NAME: props.adminGroupName,
      },
    });

    props.adminTable.grantReadWriteData(handler);

    // ── REST API with Cognito Authorizer ──
    const userPool = cognito.UserPool.fromUserPoolId(
      this,
      "UserPool",
      props.cognitoUserPoolId,
    );

    const authorizer = new apigateway.CognitoUserPoolsAuthorizer(
      this,
      "Authorizer",
      {
        cognitoUserPools: [userPool],
        identitySource: "method.request.header.Authorization",
      },
    );

    const api = new apigateway.RestApi(this, "Api", {
      restApiName: `admin-api-${stack.stackName}`,
      description: "Admin Control Panel for service + claim-mapping CRUD",
      deployOptions: {
        stageName: "prod",
        loggingLevel: apigateway.MethodLoggingLevel.INFO,
        dataTraceEnabled: false,
        tracingEnabled: true,
      },
      defaultMethodOptions: {
        authorizer,
        authorizationType: apigateway.AuthorizationType.COGNITO,
      },
      defaultCorsPreflightOptions: {
        allowOrigins: apigateway.Cors.ALL_ORIGINS,
        allowMethods: apigateway.Cors.ALL_METHODS,
        allowHeaders: ["Content-Type", "Authorization"],
      },
    });

    const admin = api.root.addResource("admin").addResource("v1");
    const integration = new apigateway.LambdaIntegration(handler);

    admin.addProxy({
      defaultIntegration: integration,
      anyMethod: true,
      defaultMethodOptions: {
        authorizer,
        authorizationType: apigateway.AuthorizationType.COGNITO,
      },
    });

    // Gateway-level error responses (e.g. Cognito authorizer 401/403) must
    // carry CORS headers too, otherwise the browser masks the real status.
    const corsResponseHeaders = {
      "gatewayresponse.header.Access-Control-Allow-Origin": "'*'",
      "gatewayresponse.header.Access-Control-Allow-Headers": "'Content-Type,Authorization'",
      "gatewayresponse.header.Access-Control-Allow-Methods": "'GET,POST,PUT,DELETE,OPTIONS'",
    };
    new apigateway.GatewayResponse(this, "Default4xx", {
      restApi: api,
      type: apigateway.ResponseType.DEFAULT_4XX,
      responseHeaders: corsResponseHeaders,
    });
    new apigateway.GatewayResponse(this, "Default5xx", {
      restApi: api,
      type: apigateway.ResponseType.DEFAULT_5XX,
      responseHeaders: corsResponseHeaders,
    });

    this.apiUrl = api.url;
  }
}
