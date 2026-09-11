import { readFile } from "node:fs/promises";
import https from "node:https";

let createReadClient;
try {
  ({ createReadClient } = await import("../../web/generated/read-api.ts"));
} catch {
  process.stderr.write("CLIENT_IMPORT_FAILED\n");
  process.exit(1);
}

const required = (name) => {
  const value = process.env[name];
  if (!value) throw new Error(`missing ${name}`);
  return value;
};

const baseURL = required("VSK_CONSOLE_TEST_BASE_URL");
const certificate = await readFile(required("VSK_CONSOLE_TEST_CERTIFICATE"));
const assertion = required("VSK_CONSOLE_TEST_ASSERTION");
const cookie = required("VSK_CONSOLE_TEST_COOKIE");

const transport = (input, init = {}) => new Promise((resolve, reject) => {
  const target = new URL(String(input), baseURL);
  const headers = new Headers(init.headers);
  headers.set("Host", "console.example");
  headers.set("Origin", "https://console.example");
  headers.set("Cf-Access-Jwt-Assertion", assertion);
  headers.set("Cookie", cookie);
  headers.set("Sec-Fetch-Site", "same-origin");
  headers.set("Sec-Fetch-Mode", "cors");
  headers.set("Sec-Fetch-Dest", "empty");
  const request = https.request(target, {
    method: init.method ?? "GET",
    headers: Object.fromEntries(headers.entries()),
    ca: certificate,
  }, (response) => {
    const chunks = [];
    response.on("data", (chunk) => chunks.push(chunk));
    response.on("end", () => {
      const responseHeaders = new Headers();
      for (const [name, value] of Object.entries(response.headers)) {
        for (const item of Array.isArray(value) ? value : [value]) {
          if (item !== undefined) responseHeaders.append(name, item);
        }
      }
      resolve(new Response(Buffer.concat(chunks), { status: response.statusCode, headers: responseHeaders }));
    });
  });
  request.on("error", reject);
  if (init.signal) {
    init.signal.addEventListener("abort", () => request.destroy(init.signal.reason), { once: true });
  }
  request.end();
});

try {
  const result = await createReadClient(transport).getSummary();
  process.stdout.write(`${JSON.stringify(result.data)}\n`);
} catch {
  process.stderr.write("CLIENT_REQUEST_FAILED\n");
  process.exit(1);
}
