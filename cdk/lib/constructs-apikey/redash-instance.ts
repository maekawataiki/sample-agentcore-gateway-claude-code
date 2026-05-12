import * as cdk from "aws-cdk-lib";
import * as ec2 from "aws-cdk-lib/aws-ec2";
import * as iam from "aws-cdk-lib/aws-iam";
import * as dynamodb from "aws-cdk-lib/aws-dynamodb";
import * as elbv2 from "aws-cdk-lib/aws-elasticloadbalancingv2";
import * as targets from "aws-cdk-lib/aws-elasticloadbalancingv2-targets";
import * as acm from "aws-cdk-lib/aws-certificatemanager";
import * as route53 from "aws-cdk-lib/aws-route53";
import * as r53targets from "aws-cdk-lib/aws-route53-targets";
import * as secretsmanager from "aws-cdk-lib/aws-secretsmanager";
import { Construct } from "constructs";

export interface RedashInstanceConstructProps {
  /** Admin DynamoDB table to write the service + default mapping into */
  readonly adminTable: dynamodb.Table;
  /** Public Route53 hosted zone (e.g. "chat.tmae-aws.com") used to issue the
   *  ACM cert and host the alias record. The record itself resolves to the
   *  internal ALB and is only routable from inside the VPC. */
  readonly hostedZoneName: string;
  /** FQDN for the Redash ALB (e.g. "redash.chat.tmae-aws.com") */
  readonly recordName: string;
}

/**
 * Deploys a Redash instance on EC2 with Docker Compose (Redash + PostgreSQL + Redis)
 * behind an internal HTTPS ALB. The ALB uses a public ACM cert so AgentCore
 * Gateway's VPC-egress target can validate it without needing a custom CA.
 *
 * On boot the UserData script:
 *   1. Installs Docker & Docker Compose
 *   2. Starts Redash (server, worker, scheduler) + PostgreSQL + Redis
 *   3. Runs /setup to create the admin user
 *   4. Creates a "Sample DB" data source (Redash's own PostgreSQL)
 *   5. Writes the Redash service entry + default API-key mapping into the admin table:
 *        PK=SERVICES,      SK=redash                 (service metadata)
 *        PK=SVC#redash,    SK=CLAIM#*#*              (default key, all users)
 */
export class RedashInstanceConstruct extends Construct {
  public readonly instance: ec2.Instance;
  /** HTTPS URL for the Redash API (https://<recordName>) */
  public readonly redashUrl: string;
  /** Secrets Manager secret name containing Redash credentials */
  public readonly credentialsSecretName: string;
  public readonly vpc: ec2.IVpc;
  /** Private subnets the Gateway VPC-egress endpoint should attach to */
  public readonly privateSubnets: ec2.ISubnet[];
  /** SG to attach to the Gateway VPC-egress ENIs. The ALB allows ingress
   *  on 443 from this SG. */
  public readonly gatewayEgressSg: ec2.SecurityGroup;

  constructor(
    scope: Construct,
    id: string,
    props: RedashInstanceConstructProps
  ) {
    super(scope, id);

    const stack = cdk.Stack.of(this);

    // ── VPC (private + public subnets with NAT Gateway) ──
    this.vpc = new ec2.Vpc(this, "Vpc", {
      maxAzs: 2,
      natGateways: 1,
      subnetConfiguration: [
        {
          name: "Public",
          subnetType: ec2.SubnetType.PUBLIC,
          cidrMask: 24,
        },
        {
          name: "Private",
          subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS,
          cidrMask: 24,
        },
      ],
    });
    this.privateSubnets = this.vpc.selectSubnets({
      subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS,
    }).subnets;

    // ── Security Groups ──
    // Attached to the AgentCore Gateway VPC-egress ENIs (created by VPC Lattice).
    this.gatewayEgressSg = new ec2.SecurityGroup(this, "GatewayEgressSG", {
      vpc: this.vpc,
      description: "AgentCore Gateway VPC-egress ENIs for Redash",
      allowAllOutbound: true,
    });

    // ALB SG — accepts HTTPS only from the Gateway egress SG.
    const albSg = new ec2.SecurityGroup(this, "AlbSG", {
      vpc: this.vpc,
      description: "Internal ALB for Redash - HTTPS from AgentCore Gateway",
      allowAllOutbound: true,
    });
    albSg.addIngressRule(this.gatewayEgressSg, ec2.Port.tcp(443), "HTTPS from Gateway egress");

    // EC2 SG — accepts Redash traffic only from the ALB.
    const sg = new ec2.SecurityGroup(this, "SG", {
      vpc: this.vpc,
      description: "Redash instance - allow port 5000 from ALB only",
      allowAllOutbound: true,
    });
    sg.addIngressRule(albSg, ec2.Port.tcp(5000), "Redash HTTP from ALB");

    // ── IAM Role ──
    const role = new iam.Role(this, "Role", {
      assumedBy: new iam.ServicePrincipal("ec2.amazonaws.com"),
      managedPolicies: [
        iam.ManagedPolicy.fromAwsManagedPolicyName(
          "AmazonSSMManagedInstanceCore"
        ),
      ],
    });
    props.adminTable.grantWriteData(role);

    // ── Secrets Manager for Redash credentials ──
    const redashSecret = new secretsmanager.Secret(this, "RedashSecret", {
      secretName: `redash-credentials-${stack.stackName}`,
      description: "Redash admin credentials (generated at EC2 boot time)",
    });
    redashSecret.grantWrite(role);

    // ── UserData ──
    const userData = ec2.UserData.forLinux();
    userData.addCommands(
      "set -ex",

      // Install Docker
      "yum update -y",
      "yum install -y docker jq aws-cli",
      "systemctl enable docker && systemctl start docker",

      // Install Docker Compose
      'ARCH=$(uname -m)',
      'curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-linux-${ARCH}" -o /usr/local/bin/docker-compose',
      "chmod +x /usr/local/bin/docker-compose",

      // Generate random secrets at boot time
      'PG_PASSWORD=$(tr -dc "A-Za-z0-9" < /dev/urandom | head -c 32)',
      'COOKIE_SECRET=$(tr -dc "A-Za-z0-9" < /dev/urandom | head -c 48)',
      'SECRET_KEY=$(tr -dc "A-Za-z0-9" < /dev/urandom | head -c 48)',
      'ADMIN_PASSWORD=$(tr -dc "A-Za-z0-9!@#$" < /dev/urandom | head -c 24)',

      // Create docker-compose.yml
      "mkdir -p /opt/redash",
      `cat > /opt/redash/docker-compose.yml << COMPOSEFILE
version: "3"
services:
  server:
    image: redash/redash:10.1.0.b50633
    depends_on: [postgres, redis]
    ports: ["5000:5000"]
    environment:
      REDASH_DATABASE_URL: "postgresql://postgres:$PG_PASSWORD@postgres/postgres"
      REDASH_REDIS_URL: "redis://redis:6379/0"
      REDASH_COOKIE_SECRET: "$COOKIE_SECRET"
      REDASH_SECRET_KEY: "$SECRET_KEY"
      REDASH_WEB_WORKERS: 2
    command: server
    restart: always
  scheduler:
    image: redash/redash:10.1.0.b50633
    depends_on: [server]
    environment:
      REDASH_DATABASE_URL: "postgresql://postgres:$PG_PASSWORD@postgres/postgres"
      REDASH_REDIS_URL: "redis://redis:6379/0"
    command: scheduler
    restart: always
  worker:
    image: redash/redash:10.1.0.b50633
    depends_on: [server]
    environment:
      REDASH_DATABASE_URL: "postgresql://postgres:$PG_PASSWORD@postgres/postgres"
      REDASH_REDIS_URL: "redis://redis:6379/0"
      QUEUES: "queries,scheduled_queries,celery"
      WORKERS_COUNT: 2
    command: worker
    restart: always
  redis:
    image: redis:7-alpine
    restart: always
  postgres:
    image: postgres:15-alpine
    environment:
      POSTGRES_PASSWORD: $PG_PASSWORD
      POSTGRES_DB: postgres
    volumes: [postgres-data:/var/lib/postgresql/data]
    restart: always
volumes:
  postgres-data:
COMPOSEFILE`,

      // Start Redash
      "cd /opt/redash",
      "/usr/local/bin/docker-compose run --rm server create_db",
      "/usr/local/bin/docker-compose up -d",

      // Wait for server to be ready
      `for i in $(seq 1 90); do
  if curl -sf http://localhost:5000/ping >/dev/null 2>&1; then
    echo "Redash is ready"
    break
  fi
  echo "Waiting for Redash... ($i/90)"
  sleep 5
done`,

      // Setup admin user (password generated at boot)
      `curl -s -c /tmp/cookies.txt \\
  -H "Content-Type: application/json" \\
  -d '{"name":"Admin","email":"admin@redash.local","password":"'"$ADMIN_PASSWORD"'","org_name":"Default"}' \\
  http://localhost:5000/setup`,

      // Login to get session
      `curl -s -b /tmp/cookies.txt -c /tmp/cookies.txt \\
  -H "Content-Type: application/json" \\
  -d '{"email":"admin@redash.local","password":"'"$ADMIN_PASSWORD"'"}' \\
  http://localhost:5000/api/session`,

      // Get API key
      `API_KEY=$(curl -s -b /tmp/cookies.txt http://localhost:5000/api/users/1 | jq -r '.api_key')`,

      // Create data source (Redash's own PostgreSQL for demo queries)
      `curl -s -H "Authorization: Key $API_KEY" \\
  -H "Content-Type: application/json" \\
  -d '{"name":"Sample DB","type":"pg","options":{"host":"postgres","port":5432,"dbname":"postgres","user":"postgres","password":"'"$PG_PASSWORD"'"}}' \\
  http://localhost:5000/api/data_sources`,

      // Register Redash service in the admin table
      `aws dynamodb put-item \\
  --table-name "${props.adminTable.tableName}" \\
  --item '{"PK":{"S":"SERVICES"},"SK":{"S":"redash"},"displayName":{"S":"Redash"},"targetPrefix":{"S":"redash-target-"},"defaultHeaderName":{"S":"Authorization"},"defaultHeaderPrefix":{"S":"Key "},"isActive":{"BOOL":true}}' \\
  --region "${stack.region}"`,

      // Write default API-key mapping (all users, claim key=*, value=*)
      `aws dynamodb put-item \\
  --table-name "${props.adminTable.tableName}" \\
  --item '{"PK":{"S":"SVC#redash"},"SK":{"S":"CLAIM#*#*"},"claimKey":{"S":"*"},"claimValue":{"S":"*"},"serviceName":{"S":"redash"},"apiKey":{"S":"Key '"$API_KEY"'"},"headerName":{"S":"Authorization"}}' \\
  --region "${stack.region}"`,

      // Store credentials in Secrets Manager
      `aws secretsmanager put-secret-value \\
  --secret-id "${redashSecret.secretName}" \\
  --secret-string "$(jq -n \\
    --arg admin_email "admin@redash.local" \\
    --arg admin_password "$ADMIN_PASSWORD" \\
    --arg pg_password "$PG_PASSWORD" \\
    --arg api_key "$API_KEY" \\
    '{admin_email: $admin_email, admin_password: $admin_password, pg_password: $pg_password, api_key: $api_key}')" \\
  --region "${stack.region}"`,

      // Clean up sensitive temp files
      'rm -f /tmp/cookies.txt',
      'echo "Redash setup complete"'
    );

    // ── EC2 Instance (in private subnet) ──
    this.instance = new ec2.Instance(this, "Instance", {
      vpc: this.vpc,
      vpcSubnets: { subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS },
      instanceType: ec2.InstanceType.of(
        ec2.InstanceClass.T3,
        ec2.InstanceSize.MEDIUM
      ),
      machineImage: ec2.MachineImage.latestAmazonLinux2023({
        cpuType: ec2.AmazonLinuxCpuType.X86_64,
      }),
      securityGroup: sg,
      role,
      userData,
      associatePublicIpAddress: false,
      requireImdsv2: true,
      blockDevices: [
        {
          deviceName: "/dev/xvda",
          volume: ec2.BlockDeviceVolume.ebs(30, {
            volumeType: ec2.EbsDeviceVolumeType.GP3,
            encrypted: true,
          }),
        },
      ],
    });

    cdk.Tags.of(this.instance).add("Name", `redash-${stack.stackName}`);

    // ── Route53 + ACM ──
    const hostedZone = route53.HostedZone.fromLookup(this, "HostedZone", {
      domainName: props.hostedZoneName,
    });

    const certificate = new acm.Certificate(this, "Certificate", {
      domainName: props.recordName,
      validation: acm.CertificateValidation.fromDns(hostedZone),
    });

    // ── Internal Application Load Balancer ──
    const alb = new elbv2.ApplicationLoadBalancer(this, "Alb", {
      vpc: this.vpc,
      internetFacing: false,
      vpcSubnets: { subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS },
      securityGroup: albSg,
    });

    const targetGroup = new elbv2.ApplicationTargetGroup(this, "TargetGroup", {
      vpc: this.vpc,
      port: 5000,
      protocol: elbv2.ApplicationProtocol.HTTP,
      targets: [new targets.InstanceTarget(this.instance, 5000)],
      healthCheck: {
        protocol: elbv2.Protocol.HTTP,
        path: "/ping",
        port: "5000",
      },
    });

    alb.addListener("HttpsListener", {
      port: 443,
      protocol: elbv2.ApplicationProtocol.HTTPS,
      certificates: [certificate],
      defaultTargetGroups: [targetGroup],
    });

    new route53.ARecord(this, "AliasRecord", {
      zone: hostedZone,
      recordName: props.recordName,
      target: route53.RecordTarget.fromAlias(
        new r53targets.LoadBalancerTarget(alb),
      ),
    });

    this.redashUrl = `https://${props.recordName}`;
    this.credentialsSecretName = redashSecret.secretName;
  }
}
