import * as cdk from "aws-cdk-lib";
import * as cloudfront from "aws-cdk-lib/aws-cloudfront";
import * as origins from "aws-cdk-lib/aws-cloudfront-origins";
import * as iam from "aws-cdk-lib/aws-iam";
import * as s3 from "aws-cdk-lib/aws-s3";
import * as s3deploy from "aws-cdk-lib/aws-s3-deployment";
import * as path from "path";
import { Construct } from "constructs";
import { NagSuppressions } from "cdk-nag";

export interface AdminFrontendConstructProps {
  readonly cognitoDomain: string;
  readonly cognitoClientId: string;
  readonly adminApiUrl: string;
}

/**
 * Admin Panel frontend — S3 + CloudFront.
 *
 * Deploys the built React SPA and generates a runtime config.js
 * with Cognito/API settings injected at deploy time.
 */
export class AdminFrontendConstruct extends Construct {
  public readonly distributionUrl: string;
  public readonly distribution: cloudfront.Distribution;

  constructor(scope: Construct, id: string, props: AdminFrontendConstructProps) {
    super(scope, id);

    // ── S3 Bucket for SPA ──
    const bucket = new s3.Bucket(this, "Bucket", {
      encryption: s3.BucketEncryption.S3_MANAGED,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      enforceSSL: true,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      autoDeleteObjects: true,
    });

    // ── CloudFront Distribution ──
    const oai = new cloudfront.OriginAccessIdentity(this, "OAI");
    bucket.grantRead(oai);

    this.distribution = new cloudfront.Distribution(this, "Distribution", {
      defaultBehavior: {
        origin: new origins.S3Origin(bucket, { originAccessIdentity: oai }),
        viewerProtocolPolicy: cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
      },
      defaultRootObject: "index.html",
      minimumProtocolVersion: cloudfront.SecurityPolicyProtocol.TLS_V1_2_2021,
      // SPA: return index.html for all 404s (client-side routing)
      errorResponses: [
        {
          httpStatus: 403,
          responseHttpStatus: 200,
          responsePagePath: "/index.html",
        },
        {
          httpStatus: 404,
          responseHttpStatus: 200,
          responsePagePath: "/index.html",
        },
      ],
    });

    this.distributionUrl = `https://${this.distribution.distributionDomainName}`;

    // ── Deploy built SPA assets + runtime config.js in a single deployment ──
    // Single BucketDeployment avoids ordering/prune races between two deployments.
    // The placeholder in frontend/public/config.js is for local dev only and is
    // excluded from the asset so Source.data wins deterministically.
    new s3deploy.BucketDeployment(this, "DeployApp", {
      sources: [
        s3deploy.Source.asset(path.join(__dirname, "../../../frontend/dist"), {
          exclude: ["config.js"],
        }),
        s3deploy.Source.data(
          "config.js",
          `window.__CONFIG__ = ${JSON.stringify({
            cognitoDomain: props.cognitoDomain,
            cognitoClientId: props.cognitoClientId,
            adminApiUrl: props.adminApiUrl,
            redirectUri: this.distributionUrl,
          }, null, 2)};`,
        ),
      ],
      destinationBucket: bucket,
      distribution: this.distribution,
      distributionPaths: ["/*"],
    });

    // ── cdk-nag suppressions for admin panel static hosting ──
    NagSuppressions.addResourceSuppressions(
      bucket,
      [
        {
          id: "AwsSolutions-S1",
          reason: "Admin panel static assets bucket — access logging not required for internal tool",
        },
      ],
    );
    NagSuppressions.addResourceSuppressions(
      this.distribution,
      [
        {
          id: "AwsSolutions-CFR3",
          reason: "Admin panel CloudFront — access logging not required for internal tool",
        },
        {
          id: "AwsSolutions-CFR4",
          reason: "Using default CloudFront certificate with TLS 1.2 minimum; custom domain/cert not needed for internal tool",
        },
        {
          id: "AwsSolutions-CFR7",
          reason: "Using OAI for S3 access; OAC migration deferred — OAI provides equivalent access restriction",
        },
      ],
    );
  }
}
