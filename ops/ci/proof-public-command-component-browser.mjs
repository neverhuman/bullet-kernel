#!/usr/bin/env node
// Browser half of the packaged public-command COMPONENT proof. It projects
// Kernel truth only; it creates no command outcome or authority.
import assert from "node:assert/strict";
import { open } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);

function required(name) {
  const value = process.env[name];
  if (value === undefined || value === "") throw new Error(`${name} is required`);
  return value;
}

async function publish(file, value) {
  const handle = await open(file, "wx", 0o600);
  try {
    await handle.writeFile(`${JSON.stringify(value)}\n`);
    await handle.sync();
  } finally {
    await handle.close();
  }
}

async function text(locator) {
  await locator.waitFor({ state: "visible" });
  return (await locator.textContent())?.trim() ?? "";
}

function exactUnknown(status, expected) {
  assert.equal(status.id, expected.id);
  assert.equal(status.kind, "run_demo");
  assert.equal(status.payload_digest, expected.payload_digest);
  assert.equal(status.status, "UNKNOWN");
  assert.deepEqual(status.result, {
    code: "COMPONENT_PROOF_NOT_TRANSACTION_ELIGIBLE",
    command_id: expected.id,
    detail: "A retained component receipt is not complete transaction evidence.",
    evidence_class: "COMPONENT_PROOF",
    independent_evidence_eligible: false,
    receipt_digest: expected.receipt_digest,
    repair: "Run the signed Candidate-to-observation transaction with independent identities.",
    request_digest: expected.payload_digest,
    signing_trust: "UNSIGNED_FIXTURE",
    transaction_gate_eligible: false,
  });
}

const origin = required("BULLET_PUBLIC_ORIGIN");
const bootstrap = required("BULLET_PUBLIC_BOOTSTRAP");
const readyPath = required("BULLET_PUBLIC_BROWSER_READY");
const resultPath = required("BULLET_PUBLIC_BROWSER_RESULT");
const toolRoot = required("BULLET_PLAYWRIGHT_ROOT");
const portalRoot = required("BULLET_PORTAL_BUNDLE_ROOT");
const envelope = JSON.parse(required("BULLET_PUBLIC_COMMAND_ENVELOPE"));
const timeoutMs = Number(process.env.BULLET_PUBLIC_BROWSER_TIMEOUT_MS ?? "900000");
assert.match(origin, /^http:\/\/127\.0\.0\.1:[1-9][0-9]{0,4}$/u);
assert.match(bootstrap, /^boot_[0-9a-f]{64}$/u);
assert.match(portalRoot, /^blake3:[0-9a-f]{64}$/u);
assert.ok(Number.isSafeInteger(timeoutMs) && timeoutMs >= 10_000 && timeoutMs <= 900_000);
assert.deepEqual(Object.keys(envelope).sort(), ["idempotency_key", "kind", "payload"]);
assert.equal(envelope.kind, "run_demo");
assert.deepEqual(envelope.payload, {});

const { chromium } = require(path.join(toolRoot, "node_modules", "playwright"));
let browser;
try {
  browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({ baseURL: origin });
  const page = await context.newPage();
  page.setDefaultTimeout(Math.min(timeoutMs, 30_000));

  await page.goto(`${origin}/#/shift-brief`);
  assert.equal(await text(page.getByRole("heading", { name: "Shift Brief" })), "Shift Brief");
  const briefBeforeRow = page.getByTestId("brief-row-control-tower").filter({ hasText: "PROJECTION_SNAPSHOT" });
  await briefBeforeRow.waitFor({ state: "visible" });
  const briefBefore = await text(briefBeforeRow);
  assert.match(briefBefore, /Control Tower/u);
  assert.match(briefBefore, /PROJECTION_SNAPSHOT/u);
  assert.equal(await page.getByTestId("shift-brief").locator(".verified").count(), 0);

  await page.goto(`${origin}/#/control-tower`);
  await page.getByLabel("One-time bootstrap token").fill(bootstrap);
  await page.getByRole("button", { name: "Authenticate local session" }).click();
  await page.getByTestId("auth-state").waitFor({ state: "visible" });

  let replaced = 0;
  await page.route("**/api/v1/commands", async (route) => {
    if (route.request().method() === "POST") {
      replaced += 1;
      await route.continue({ postData: JSON.stringify(envelope) });
    } else {
      await route.continue();
    }
  });
  const admissionResponse = page.waitForResponse(
    (response) => response.request().method() === "POST" && response.url().endsWith("/api/v1/commands"),
  );
  await page.getByRole("button", { name: "Submit durable demo command" }).click();
  const admissionHttp = await admissionResponse;
  assert.equal(admissionHttp.status(), 202);
  const admission = await admissionHttp.json();
  assert.match(admission.id, /^cmd_[0-9a-f]{64}$/u);
  assert.match(admission.payload_digest, /^[0-9a-f]{64}$/u);
  assert.equal(admission.status, "PENDING");
  assert.equal(admission.kind, "run_demo");
  assert.equal(admission.result, null);
  assert.equal(await text(page.getByTestId("command-id")), admission.id);
  assert.match(await text(page.getByTestId("phase")), /PENDING/u);

  const duplicate = await page.evaluate(async (body) => {
    const csrf = globalThis.sessionStorage.getItem("bullet-farm.csrf.v1");
    const response = await fetch("/api/v1/commands", {
      method: "POST",
      credentials: "same-origin",
      headers: { "content-type": "application/json", "x-bullet-csrf": csrf ?? "" },
      body: JSON.stringify(body),
    });
    return { status: response.status, body: await response.json() };
  }, envelope);
  assert.equal(duplicate.status, 202);
  assert.deepEqual(duplicate.body, admission);
  assert.ok(replaced >= 2);
  await publish(readyPath, { envelope, admission, duplicate: duplicate.body, brief_before: briefBefore });

  page.setDefaultTimeout(timeoutMs);
  await page.getByTestId("phase").filter({ hasText: "UNKNOWN" }).waitFor({ state: "visible" });
  const finalStatus = await page.evaluate(async (commandId) => {
    const response = await fetch(`/api/v1/commands/${encodeURIComponent(commandId)}`, {
      credentials: "same-origin",
    });
    return { status: response.status, body: await response.json() };
  }, admission.id);
  assert.equal(finalStatus.status, 200);
  const receiptDigest = finalStatus.body?.result?.receipt_digest;
  assert.match(receiptDigest, /^[0-9a-f]{64}$/u);
  exactUnknown(finalStatus.body, { ...admission, receipt_digest: receiptDigest });

  const commandText = await text(page.getByTestId("command"));
  for (const expected of [admission.id, admission.payload_digest, receiptDigest,
    "COMPONENT_PROOF_NOT_TRANSACTION_ELIGIBLE", "UNSIGNED_FIXTURE", "UNKNOWN"]) {
    assert.ok(commandText.includes(expected), `command card omitted ${expected}`);
  }
  assert.equal(await page.getByTestId("command").locator(".verified").count(), 0);
  assert.equal(await page.getByTestId("phase").locator(".verified").count(), 0);
  assert.ok(!commandText.includes("APPLIED") && !commandText.includes("VERIFIED"));

  await page.goto(`${origin}/#/shift-brief`);
  const briefAfterRow = page.getByTestId("brief-row-control-tower").filter({ hasText: "PROJECTION_SNAPSHOT" });
  await briefAfterRow.waitFor({ state: "visible" });
  const briefAfter = await text(briefAfterRow);
  assert.match(briefAfter, /PROJECTION_SNAPSHOT/u);
  assert.equal(await page.getByTestId("shift-brief").locator(".verified").count(), 0);
  const health = await page.evaluate(async () => (await fetch("/health")).json());
  assert.equal(health.portal, portalRoot);
  await publish(resultPath, {
    schema_version: "bullet.public-command-browser-observation.v1",
    evidence_class: "COMPONENT_PROOF",
    signing_trust: "UNSIGNED_FIXTURE",
    transaction_gate_eligible: false,
    independent_evidence_eligible: false,
    release_gate_eligible: false,
    portal_bundle_root: portalRoot,
    envelope,
    admission,
    duplicate: duplicate.body,
    get: finalStatus.body,
    rendered_command: commandText,
    brief_before: briefBefore,
    brief_after: briefAfter,
  });
  process.stdout.write("PORTAL_UNKNOWN\n");
} finally {
  await browser?.close().catch(() => undefined);
}
