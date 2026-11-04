import { execFileSync } from "node:child_process";
import { appendFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { HubClient } from "@writerslogic/ai-agents-mcp/dist/client.js";
import { loadConfig } from "@writerslogic/ai-agents-mcp/dist/config.js";
import { AGENTS, decide, FAIL_ON, shouldFail, summary } from "./review.mjs";

const MAX_DIFF_BYTES = 900 * 1024;

function die(msg) {
  console.log(`::error::${msg}`);
  process.exit(1);
}

const agent = process.env.WL_AGENT?.trim() || "pre-merge-review";
const failOn = process.env.WL_FAIL_ON?.trim() || "block";
if (!AGENTS[agent]) die(`agent must be one of ${Object.keys(AGENTS).join(", ")}`);
if (!FAIL_ON.includes(failOn)) die(`fail-on must be one of ${FAIL_ON.join(", ")}`);

const cfg = loadConfig(process.env);
if (!cfg.apiKey && !cfg.wallet) die("Set api-key or wallet-private-key");

const baseRef = process.env.WL_BASE_REF?.trim() || process.env.GITHUB_BASE_REF?.trim();
if (!baseRef) die("No base-ref given and this is not a pull_request event");
if (!/^[\w./-]{1,200}$/.test(baseRef) || baseRef.startsWith("-")) die("base-ref has unsupported characters");

const git = (...args) => execFileSync("git", args, { encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
try {
  git("fetch", "--no-tags", "--depth=200", "origin", baseRef);
} catch {
  // Already present, or a local ref; the diff below reports a missing ref clearly.
}
let diff;
try {
  diff = git("diff", "--no-color", "--unified=3", `origin/${baseRef}...HEAD`);
} catch {
  die(`Could not diff against origin/${baseRef}; use actions/checkout with fetch-depth: 0`);
}
if (!diff.trim()) {
  console.log("No changes against the base; nothing to review.");
  process.exit(0);
}
if (Buffer.byteLength(diff) > MAX_DIFF_BYTES) die(`Diff is ${Buffer.byteLength(diff)} bytes; the review accepts up to ${MAX_DIFF_BYTES}`);

const spec = AGENTS[agent];
const url = new URL(spec.path, cfg.baseUrl).toString();
const outcome = await new HubClient(cfg).callAgent({ id: agent, url, priceUsdc: "see catalog" }, spec.body(diff));
if (outcome.isError) die(outcome.text.slice(0, 2000));

const envelope = JSON.parse(outcome.text);
const report = path.join(process.env.RUNNER_TEMP || ".", "writerslogic-review.json");
writeFileSync(report, outcome.text);
const decision = decide(agent, envelope.data);
const md = summary(agent, decision, envelope, new URL("/api/v1/verify-provenance", cfg.baseUrl).toString());
if (process.env.GITHUB_STEP_SUMMARY) appendFileSync(process.env.GITHUB_STEP_SUMMARY, `${md}\n`);
else console.log(md);
if (process.env.GITHUB_OUTPUT) appendFileSync(process.env.GITHUB_OUTPUT, `merge-approved=${decision.approved}\nreport=${report}\n`);
if (outcome.payment) console.log(`Paid ${outcome.payment.amountUsdc} USDC from ${outcome.payment.payer}`);
if (shouldFail(failOn, decision)) die(decision.approved ? "Unicode gate warned and fail-on is warn" : "Merge not approved; see the job summary");
