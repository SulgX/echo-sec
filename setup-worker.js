import { renderSetupPage } from "./setup-ui.js";

const SECURITY_HEADERS = {
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "Referrer-Policy": "strict-origin-when-cross-origin",
  "Content-Type": "application/json; charset=utf-8"
};

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    if (request.method === "GET" && (url.pathname === "/" || url.pathname === "/setup")) {
      return new Response(renderSetupPage(), {
        headers: { "Content-Type": "text/html; charset=utf-8" }
      });
    }

    if (request.method === "POST" && url.pathname === "/api/setup") {
      try {
        const body = await request.json();
        const { accountId, cfToken, botToken, botUsername, repoUrl, adminPassword } = body;

        if (!accountId || !cfToken || !botToken || !repoUrl || !adminPassword) {
          return jsonResponse({ success: false, error: "تمامی فیلدها الزامی هستند." }, 400);
        }

        let baseRepoUrl = repoUrl.trim();
        if (!baseRepoUrl.endsWith("/")) baseRepoUrl += "/";

        const log = [];

        log.push("Fetching source code from GitHub...");
        const fetchFile = async (fileName) => {
          const url = baseRepoUrl + fileName;
          const res = await fetch(url);
          if (!res.ok) throw new Error(`عدم دسترسی به ${fileName} از آدرس: ${url} (کد خطا: ${res.status})`);
          return await res.text();
        };

        const workerCode = await fetchFile("worker.js");
        const adminUiCode = await fetchFile("admin-ui.js");
        const i18nCode = await fetchFile("i18n.js");
        const migrationSql = await fetchFile("migration.sql");

        log.push("Creating D1 Database...");
        const d1Name = `echosec-db-${Math.floor(Math.random() * 10000)}`;
        const d1Res = await cfApi(accountId, cfToken, `/d1/database`, {
          method: "POST",
          body: JSON.stringify({ name: d1Name })
        });
        if (!d1Res.success) throw new Error("خطا در ساخت D1: " + JSON.stringify(d1Res.errors));
        const dbId = d1Res.result.uuid;

        log.push("Creating KV Namespace...");
        const kvName = `echosec-cache-${Math.floor(Math.random() * 10000)}`;
        const kvRes = await cfApi(accountId, cfToken, `/storage/kv/namespaces`, {
          method: "POST",
          body: JSON.stringify({ title: kvName })
        });
        if (!kvRes.success) throw new Error("خطا در ساخت KV: " + JSON.stringify(kvRes.errors));
        const kvId = kvRes.result.id;

        log.push("Executing SQL Migrations on D1...");
        const sqlRes = await cfApi(accountId, cfToken, `/d1/database/${dbId}/query`, {
          method: "POST",
          body: JSON.stringify({ sql: migrationSql })
        });
        if (!sqlRes.success) throw new Error("خطا در اجرای SQL: " + JSON.stringify(sqlRes.errors));

        log.push("Generating Secrets...");
        const sessionSecret = generateRandomString(32);
        const webhookSecret = generateRandomString(32);
        const workerName = `echosec-bot-${Math.floor(Math.random() * 10000)}`;
        const subdomain = env.CF_SUBDOMAIN || getSubdomainFromUrl(url);
        const finalWorkerUrl = `https://${workerName}.${subdomain}.workers.dev`;

        log.push("Deploying Main Worker (ES Modules)...");
        const metadata = {
          main_module: "worker.js",
          compatibility_date: "2024-10-01",
          compatibility_flags: ["nodejs_compat"],
          bindings: [
            { type: "d1", name: "DB", id: dbId },
            { type: "kv_namespace", name: "CACHE", id: kvId },
            { type: "plain_text", name: "BOT_USERNAME", text: botUsername || "EchoSecBot" },
            { type: "plain_text", name: "DEFAULT_LANG", text: "fa" },
            { type: "plain_text", name: "BIND_SESSION_IP", text: "1" }
          ]
        };

        const formData = new FormData();
        formData.append("metadata", JSON.stringify(metadata));
        formData.append("worker.js", new Blob([workerCode], { type: "application/javascript+module" }), "worker.js");
        formData.append("admin-ui.js", new Blob([adminUiCode], { type: "application/javascript+module" }), "admin-ui.js");
        formData.append("i18n.js", new Blob([i18nCode], { type: "application/javascript+module" }), "i18n.js");

        const deployRes = await fetch(`https://api.cloudflare.com/client/v4/accounts/${accountId}/workers/scripts/${workerName}`, {
          method: "PUT",
          headers: { "Authorization": `Bearer ${cfToken}` },
          body: formData
        });
        const deployData = await deployRes.json();
        if (!deployData.success) throw new Error("خطا در دیپلوی ورکر: " + JSON.stringify(deployData.errors));

        log.push("Setting Secrets on Deployed Worker...");
        const secretsPayload = [
          { name: "BOT_TOKEN", text: botToken, type: "secret_text" },
          { name: "ADMIN_PASSWORD", text: adminPassword, type: "secret_text" },
          { name: "SESSION_SECRET", text: sessionSecret, type: "secret_text" },
          { name: "WEBHOOK_SECRET", text: webhookSecret, type: "secret_text" }
        ];
        const secretsRes = await cfApi(accountId, cfToken, `/workers/scripts/${workerName}/secrets`, {
          method: "PUT",
          body: JSON.stringify(secretsPayload)
        });
        if (!secretsRes.success) throw new Error("خطا در تنظیم Secrets: " + JSON.stringify(secretsRes.errors));

        log.push("Setting Telegram Webhook...");
        const tgUrl = `https://api.telegram.org/bot${botToken}/setWebhook?url=${finalWorkerUrl}/webhook&secret_token=${webhookSecret}&drop_pending_updates=true`;
        const tgRes = await fetch(tgUrl);
        const tgData = await tgRes.json();
        if (!tgData.ok) throw new Error("خطا در ست کردن وبهوک تلگرام: " + tgData.description);

        log.push("Setup completed successfully!");

        return jsonResponse({
          success: true,
          dashboardUrl: `${finalWorkerUrl}/admin/login`,
          logs: log
        });

      } catch (err) {
        console.error("Setup Error:", err);
        return jsonResponse({ success: false, error: err.message }, 500);
      }
    }

    return new Response("Not Found", { status: 404 });
  }
};

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: SECURITY_HEADERS
  });
}

async function cfApi(accountId, token, path, options = {}) {
  const url = `https://api.cloudflare.com/client/v4/accounts/${accountId}${path}`;
  const headers = {
    "Authorization": `Bearer ${token}`,
    "Content-Type": "application/json"
  };
  const response = await fetch(url, { ...options, headers });
  return await response.json();
}

function generateRandomString(length) {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  const bytes = crypto.getRandomValues(new Uint8Array(length));
  return Array.from(bytes, b => chars[b % chars.length]).join("");
}

function getSubdomainFromUrl(url) {
  const parts = url.hostname.split(".");
  return parts.length > 2 ? parts[1] : "workers";
}
