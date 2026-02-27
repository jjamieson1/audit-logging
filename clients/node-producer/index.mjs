import { createAuditLogger } from "../node-lib/index.mjs";

const endpoint = process.env.AUDIT_LOG_URL || "http://localhost:8080/v1/logs";
const appName = process.env.AUDIT_APP_NAME || "node-producer";

const client = createAuditLogger({ endpoint });
const response = await client.writeLog({
  app: appName,
  level: "INFO",
  message: "example log from Node producer",
  metadata: {
    service: appName,
    emittedAt: new Date().toISOString(),
    traceId: "trace-node-123"
  }
});

console.log(`log accepted: ${JSON.stringify(response)}`);
