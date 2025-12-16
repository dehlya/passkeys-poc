const { test, expect } = require("@playwright/test");
const { spawn } = require("child_process");
const http = require("http");

const BASE_URL = "http://localhost:5000";

let serverProc;

function waitForHttp(url, timeoutMs = 30000) {
  const start = Date.now();

  return new Promise((resolve, reject) => {
    const tick = () => {
      if (Date.now() - start > timeoutMs) {
        return reject(new Error(`Server not responding at ${url} after ${timeoutMs}ms`));
      }

      const req = http.get(url, (res) => {
        // any HTTP response means the server is up
        res.resume();
        resolve();
      });

      req.on("error", () => setTimeout(tick, 300));
      req.end();
    };

    tick();
  });
}

test.beforeAll(async () => {
  // Start Flask
  const isWin = process.platform === "win32";

  serverProc = spawn(
    isWin ? "py" : "python3",
    isWin ? ["-3.11", "src/app.py"] : ["src/app.py"],
    {
      env: {
        ...process.env,
        RP_ID: "localhost",
        ORIGIN: "http://localhost:5000",
      },
      stdio: "inherit",
    }
  );

  // If Flask crashes early, fail fast
  serverProc.on("exit", (code) => {
    if (code !== 0) {
      console.error(`Flask exited early with code ${code}`);
    }
  });

  await waitForHttp(BASE_URL, 45000);
});

test.afterAll(async () => {
  if (serverProc && !serverProc.killed) {
    // Windows-friendly shutdown
    serverProc.kill("SIGTERM");
  }
});

test("WebAuthn: register + login using virtual authenticator (Chromium)", async ({ browser }) => {
  const context = await browser.newContext();
  const page = await context.newPage();

  // Virtual authenticator (Chromium only)
  const client = await context.newCDPSession(page);
  await client.send("WebAuthn.enable");
  await client.send("WebAuthn.addVirtualAuthenticator", {
    options: {
      protocol: "ctap2",
      transport: "internal",
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      automaticPresenceSimulation: true,
    },
  });

  await page.goto(BASE_URL, { waitUntil: "domcontentloaded" });

  // TODO: put your exact clicks/assertions here
  // Example placeholder:
  await expect(page.locator("body")).toBeVisible();

  await context.close();
});
