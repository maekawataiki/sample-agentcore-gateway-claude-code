/**
 * Custom Resource that appends a callback URL to a Cognito App Client.
 *
 * Breaks the circular dependency between Cognito and proxy stacks:
 * the proxy stack doesn't know its URL until deploy time, but Cognito
 * needs the URL in its allowed callback list.
 */
import * as cdk from 'aws-cdk-lib'
import * as iam from 'aws-cdk-lib/aws-iam'
import * as lambda from 'aws-cdk-lib/aws-lambda'
import { Construct } from 'constructs'

export interface CognitoCallbackRegistrationProps {
  readonly userPoolId: string
  readonly clientId: string
  readonly callbackUrl: string
}

export class CognitoCallbackRegistration extends Construct {
  constructor(scope: Construct, id: string, props: CognitoCallbackRegistrationProps) {
    super(scope, id)

    const stack = cdk.Stack.of(this)

    const fn = new lambda.Function(this, 'Fn', {
      runtime: lambda.Runtime.PYTHON_3_13,
      handler: 'index.handler',
      architecture: lambda.Architecture.ARM_64,
      timeout: cdk.Duration.seconds(30),
      code: lambda.Code.fromInline(`
import json, boto3, urllib.request

cognito = boto3.client('cognito-idp')

def handler(event, context):
    props = event['ResourceProperties']
    pool_id, client_id = props['UserPoolId'], props['ClientId']
    callback_url = props['CallbackUrl']
    try:
        client = cognito.describe_user_pool_client(
            UserPoolId=pool_id, ClientId=client_id,
        )['UserPoolClient']
        urls = client.get('CallbackURLs', [])

        if event['RequestType'] in ('Create', 'Update'):
            if callback_url not in urls:
                urls.append(callback_url)
        elif event['RequestType'] == 'Delete':
            urls = [u for u in urls if u != callback_url]

        cognito.update_user_pool_client(
            UserPoolId=pool_id, ClientId=client_id, CallbackURLs=urls,
            AllowedOAuthFlows=client.get('AllowedOAuthFlows', []),
            AllowedOAuthScopes=client.get('AllowedOAuthScopes', []),
            AllowedOAuthFlowsUserPoolClient=client.get('AllowedOAuthFlowsUserPoolClient', False),
            SupportedIdentityProviders=client.get('SupportedIdentityProviders', []),
        )
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
          actions: ['cognito-idp:DescribeUserPoolClient', 'cognito-idp:UpdateUserPoolClient'],
          resources: [`arn:aws:cognito-idp:${stack.region}:${stack.account}:userpool/${props.userPoolId}`],
        }),
      ],
    })

    new cdk.CustomResource(this, 'CR', {
      serviceToken: fn.functionArn,
      properties: {
        UserPoolId: props.userPoolId,
        ClientId: props.clientId,
        CallbackUrl: props.callbackUrl,
      },
    })
  }
}
