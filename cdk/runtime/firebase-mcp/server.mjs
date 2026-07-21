import { createServer } from "node:http";
import { writeFile, mkdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);

// Load the esbuild bundle of firebase-tools MCP
const { FirebaseMcpServer } = require("./firebase-mcp-bundle.cjs");

// GCP SA key is stored in Secrets Manager
const GCP_SA_KEY_SECRET_ARN = process.env.GCP_SA_KEY_SECRET_ARN;
if (!GCP_SA_KEY_SECRET_ARN) {
  throw new Error("GCP_SA_KEY_SECRET_ARN must be configured");
}

// Fetch GCP service account key from Secrets Manager using IMDS credentials + SigV4
async function fetchSecretValue(secretArn) {
  const https = await import("node:https");
  const http = await import("node:http");
  const crypto = await import("node:crypto");

  // Get AWS credentials from IMDS
  const imdsToken = await new Promise((resolve, reject) => {
    const req = http.default.request("http://169.254.169.254/latest/api/token", {
      method: "PUT",
      headers: { "X-aws-ec2-metadata-token-ttl-seconds": "21600" },
      timeout: 3000,
    }, (res) => { let d = ""; res.on("data", c => d += c); res.on("end", () => resolve(d)); });
    req.on("error", reject);
    req.on("timeout", () => { req.destroy(); reject(new Error("IMDS timeout")); });
    req.end();
  });

  const roleName = await httpGet(http.default,
    "http://169.254.169.254/latest/meta-data/iam/security-credentials",
    { "X-aws-ec2-metadata-token": imdsToken });

  const credsJson = await httpGet(http.default,
    `http://169.254.169.254/latest/meta-data/iam/security-credentials/${roleName.trim()}`,
    { "X-aws-ec2-metadata-token": imdsToken });
  const creds = JSON.parse(credsJson);

  // Sign request to Secrets Manager
  const region = process.env.AWS_REGION || "us-east-1";
  const host = `secretsmanager.${region}.amazonaws.com`;
  const body = JSON.stringify({ SecretId: secretArn });
  const now = new Date();
  const amzDate = now.toISOString().replace(/[:-]|\.\d{3}/g, "");
  const dateStamp = amzDate.slice(0, 8);
  const bodyHash = crypto.default.createHash("sha256").update(body).digest("hex");

  const headers = {
    "content-type": "application/x-amz-json-1.1",
    "host": host,
    "x-amz-date": amzDate,
    "x-amz-target": "secretsmanager.GetSecretValue",
  };
  if (creds.Token) headers["x-amz-security-token"] = creds.Token;

  const sortedKeys = Object.keys(headers).sort();
  const signedHeaders = sortedKeys.join(";");
  const canonicalHeaders = sortedKeys.map(k => `${k}:${headers[k]}\n`).join("");
  const canonicalRequest = `POST\n/\n\n${canonicalHeaders}\n${signedHeaders}\n${bodyHash}`;
  const credScope = `${dateStamp}/${region}/secretsmanager/aws4_request`;
  const stringToSign = `AWS4-HMAC-SHA256\n${amzDate}\n${credScope}\n${crypto.default.createHash("sha256").update(canonicalRequest).digest("hex")}`;

  const hmac = (key, data) => crypto.default.createHmac("sha256", key).update(data).digest();
  const signingKey = hmac(hmac(hmac(hmac(`AWS4${creds.SecretAccessKey}`, dateStamp), region), "secretsmanager"), "aws4_request");
  const signature = crypto.default.createHmac("sha256", signingKey).update(stringToSign).digest("hex");

  headers["authorization"] = `AWS4-HMAC-SHA256 Credential=${creds.AccessKeyId}/${credScope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;

  const result = await new Promise((resolve, reject) => {
    const req = https.default.request({ hostname: host, path: "/", method: "POST", headers, timeout: 10000 },
      (res) => { let d = ""; res.on("data", c => d += c); res.on("end", () => resolve({ status: res.statusCode, body: d })); });
    req.on("error", reject);
    req.on("timeout", () => { req.destroy(); reject(new Error("timeout")); });
    req.write(body);
    req.end();
  });

  if (result.status !== 200) {
    throw new Error(`Secrets Manager returned ${result.status}: ${result.body.slice(0, 200)}`);
  }
  return JSON.parse(result.body).SecretString;
}

function httpGet(http, url, headers) {
  return new Promise((resolve, reject) => {
    const req = http.get(url, { headers, timeout: 5000 }, (res) => {
      let d = "";
      res.on("data", (c) => d += c);
      res.on("end", () => resolve(d));
    });
    req.on("error", reject);
    req.on("timeout", () => { req.destroy(); reject(new Error("timeout")); });
  });
}

// Write GCP SA key to disk for GOOGLE_APPLICATION_CREDENTIALS
const credDir = join(tmpdir(), `firebase-mcp-${process.pid}`);
const credPath = join(credDir, "gcp-credentials.json");
await mkdir(credDir, { recursive: true });

const saKey = await fetchSecretValue(GCP_SA_KEY_SECRET_ARN);
await writeFile(credPath, saKey, { mode: 0o600 });
process.env.GOOGLE_APPLICATION_CREDENTIALS = credPath;

console.log(JSON.stringify({ event: "gcp_sa_key_loaded", path: credPath }));

// Set default Firebase project from SA key or env var
const defaultProjectId = process.env.GCP_PROJECT_ID || (() => {
  try { return JSON.parse(saKey).project_id; } catch { return undefined; }
})();

if (defaultProjectId) {
  // Write .firebaserc so Firebase CLI auto-detects the project
  const firebaseRc = JSON.stringify({ projects: { default: defaultProjectId } });
  await writeFile(join("/app", ".firebaserc"), firebaseRc);
  console.log(JSON.stringify({ event: "default_project_set", projectId: defaultProjectId }));
}

/**
 * Fully stateless MCP Runtime.
 * Each HTTP request is handled as an independent JSON-RPC call directly
 * against a FirebaseMcpServer instance.
 */

const mcpServer = new FirebaseMcpServer({
  activeFeatures: [],
  enabledTools: [],
  projectRoot: undefined,
});
mcpServer._ready = true;

const httpServer = createServer(async (req, res) => {
  if (req.method === "GET" && req.url === "/ping") {
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ status: "ok" }));
    return;
  }

  const chunks = [];
  for await (const chunk of req) chunks.push(chunk);
  const bodyStr = Buffer.concat(chunks).toString();

  // Per-request GCP credentials injection via X-Gcp-Credentials header
  // If present, write to a temp file and override GOOGLE_APPLICATION_CREDENTIALS
  // for this request. Fallback to shared SA key.
  const perRequestCreds = req.headers["x-gcp-credentials"];
  let perRequestCredPath = null;
  if (perRequestCreds) {
    try {
      const decoded = Buffer.from(perRequestCreds, "base64").toString("utf8");
      // Validate it's valid JSON with expected fields
      const parsed = JSON.parse(decoded);
      if (parsed.type === "service_account" && parsed.private_key) {
        perRequestCredPath = join(tmpdir(), `firebase-mcp-req-${Date.now()}.json`);
        await writeFile(perRequestCredPath, decoded, { mode: 0o600 });
        process.env.GOOGLE_APPLICATION_CREDENTIALS = perRequestCredPath;
      }
    } catch (e) {
      console.error(JSON.stringify({ event: "per_request_creds_error", error: String(e) }));
    }
  } else {
    // Use shared SA key
    process.env.GOOGLE_APPLICATION_CREDENTIALS = credPath;
  }

  try {
    const request = JSON.parse(bodyStr);
    const method = request.method;
    const params = request.params || {};
    const id = request.id;

    let result;

    if (method === "initialize") {
      result = {
        protocolVersion: "2025-11-25",
        capabilities: { tools: { listChanged: true }, logging: {}, prompts: { listChanged: true }, resources: {} },
        serverInfo: { name: "firebase", version: "0.3.0" },
      };
    } else if (method === "notifications/initialized" || method?.startsWith("notifications/")) {
      res.writeHead(202, { "content-type": "application/json" });
      res.end("");
      return;
    } else if (method === "tools/list") {
      result = await mcpServer.mcpListTools({ params });
    } else if (method === "tools/call") {
      result = await mcpServer.mcpCallTool({ params });
    } else if (method === "prompts/list") {
      result = await mcpServer.mcpListPrompts({ params });
    } else if (method === "prompts/get") {
      result = await mcpServer.mcpGetPrompt({ params });
    } else if (method === "resources/list") {
      result = await mcpServer.mcpListResources({ params });
    } else if (method === "resources/templates/list") {
      result = await mcpServer.mcpListResourceTemplates({ params });
    } else if (method === "resources/read") {
      result = await mcpServer.mcpReadResource({ params });
    } else {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ jsonrpc: "2.0", id, error: { code: -32601, message: `Method not found: ${method}` } }));
      return;
    }

    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ jsonrpc: "2.0", id, result }));
  } catch (error) {
    console.error(JSON.stringify({ event: "request_error", error: String(error), stack: error.stack }));
    const id = (() => { try { return JSON.parse(bodyStr).id; } catch { return null; } })();
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ jsonrpc: "2.0", id, error: { code: -32603, message: error.message } }));
  } finally {
    // Cleanup per-request credential file and restore shared SA key
    if (perRequestCredPath) {
      await rm(perRequestCredPath, { force: true }).catch(() => {});
      process.env.GOOGLE_APPLICATION_CREDENTIALS = credPath;
    }
  }
});

for (const signal of ["SIGINT", "SIGTERM"]) {
  process.on(signal, async () => {
    await rm(credDir, { recursive: true, force: true }).catch(() => {});
    process.exit(0);
  });
}

httpServer.listen(Number(process.env.PORT ?? "8000"), "0.0.0.0", () => {
  console.log(JSON.stringify({
    event: "firebase_mcp_runtime_started",
    port: process.env.PORT ?? "8000",
    mode: "stateless-direct-sa-key",
  }));
});
