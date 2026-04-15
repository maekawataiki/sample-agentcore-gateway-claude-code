/**
 * Custom Resource that creates an "admin" group in a Cognito User Pool.
 *
 * Used to gate access to the admin control panel API.
 * Only users in this group can call admin endpoints.
 */
import * as cdk from "aws-cdk-lib";
import * as iam from "aws-cdk-lib/aws-iam";
import * as lambda from "aws-cdk-lib/aws-lambda";
import { Construct } from "constructs";

export interface CognitoAdminGroupProps {
  readonly userPoolId: string;
  readonly groupName?: string;
}

export class CognitoAdminGroupConstruct extends Construct {
  public readonly groupName: string;

  constructor(scope: Construct, id: string, props: CognitoAdminGroupProps) {
    super(scope, id);

    this.groupName = props.groupName ?? "admin";
    const stack = cdk.Stack.of(this);

    const fn = new lambda.Function(this, "Fn", {
      runtime: lambda.Runtime.PYTHON_3_13,
      handler: "index.handler",
      architecture: lambda.Architecture.ARM_64,
      timeout: cdk.Duration.seconds(30),
      code: lambda.Code.fromInline(`
import json, boto3, urllib.request

cognito = boto3.client('cognito-idp')

def handler(event, context):
    props = event['ResourceProperties']
    pool_id = props['UserPoolId']
    group_name = props['GroupName']
    try:
        if event['RequestType'] in ('Create', 'Update'):
            try:
                cognito.create_group(
                    GroupName=group_name,
                    UserPoolId=pool_id,
                    Description='Admin group for control panel access',
                )
            except cognito.exceptions.GroupExistsException:
                pass  # already exists, idempotent
        elif event['RequestType'] == 'Delete':
            try:
                cognito.delete_group(GroupName=group_name, UserPoolId=pool_id)
            except cognito.exceptions.ResourceNotFoundException:
                pass  # already deleted
        _respond(event, context, 'SUCCESS')
    except Exception as e:
        print(f'Error: {e}')
        _respond(event, context, 'FAILED', str(e))

def _respond(event, context, status, reason=''):
    body = json.dumps({
        'Status': status,
        'Reason': reason or context.log_stream_name,
        'PhysicalResourceId': context.log_stream_name,
        'StackId': event['StackId'],
        'RequestId': event['RequestId'],
        'LogicalResourceId': event['LogicalResourceId'],
        'Data': {},
    }).encode()
    req = urllib.request.Request(event['ResponseURL'], data=body, method='PUT')
    req.add_header('Content-Type', '')
    urllib.request.urlopen(req)
`),
      initialPolicy: [
        new iam.PolicyStatement({
          actions: [
            "cognito-idp:CreateGroup",
            "cognito-idp:DeleteGroup",
          ],
          resources: [
            `arn:aws:cognito-idp:${stack.region}:${stack.account}:userpool/${props.userPoolId}`,
          ],
        }),
      ],
    });

    new cdk.CustomResource(this, "CR", {
      serviceToken: fn.functionArn,
      properties: {
        UserPoolId: props.userPoolId,
        GroupName: this.groupName,
      },
    });
  }
}
