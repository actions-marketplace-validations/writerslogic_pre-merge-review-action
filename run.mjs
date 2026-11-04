import { execFileSync } from "node:child_process";
import { appendFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { HubClient } from "@writerslogic/ai-agents-mcp/dist/client.js";
import { loadConfig } from "@writerslogic/ai-agents-mcp/dist/config.js";
import { COLLECTORS, Skip } from "./collect.mjs";
import { AGENTS, decide, FAIL_ON, shouldFail, summary, validateOptions } from "./review.mjs";

const MAX_DIFF_BYTES = 900 * 1024;

function die(msg) {
  console.log(`::error::${msg}`);
  process.exit(1);
}

const e = (k) => process.env[k]?.trim() || "";
const agent = e("WL_AGENT") || "pre-merge-review";
const failOn = e("WL_FAIL_ON") || "block";
if (!AGENTS[agent]) die(`agent must be one of ${Object.keys(AGENTS).join(", ")}`);
if (!FAIL_ON.includes(failOn)) die(`fail-on must be one of ${FAIL_ON.join(", ")}`);

const opt = {
  sbomPath: e("WL_SBOM_PATH"), productName: e("WL_PRODUCT_NAME"), productVersion: e("WL_PRODUCT_VERSION"),
  awarenessTime: e("WL_AWARENESS_TIME"), fixAvailableAt: e("WL_FIX_AVAILABLE_AT"),
  includeSource: /^true$/i.test(e("WL_INCLUDE_SOURCE")), repoLicense: e("WL_REPO_LICENSE"), mode: e("WL_MODE"),
  models: e("WL_MODELS"), datasets: e("WL_DATASETS"), commercial: e("WL_COMMERCIAL"), distribution: e("WL_DISTRIBUTION"),
  fineTune: e("WL_FINE_TUNE"), monthlyActiveUsers: e("WL_MAU"), jurisdiction: e("WL_JURISDICTION"),
  bibPath: e("WL_BIB_PATH"), manuscriptPath: e("WL_MANUSCRIPT_PATH"), checkSupport: e("WL_CHECK_SUPPORT"),
};
const invalid = validateOptions(agent, opt);
if (invalid) die(invalid);

const cfg = loadConfig(process.env);
if (!cfg.apiKey && !cfg.wallet) die("Set api-key or wallet-private-key");

const spec = AGENTS[agent];
let body;
let notes = [];
if (spec.needsDiff) {
  const baseRef = e("WL_BASE_REF") || e("GITHUB_BASE_REF");
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
  body = spec.body(diff);
} else {
  try {
    const collected = COLLECTORS[agent](opt);
    notes = collected.notes;
    body = spec.build(collected.ctx, opt);
  } catch (err) {
    if (err instanceof Skip) {
      console.log(`::notice::${err.message}`);
      process.exit(0);
    }
    die(err instanceof Error ? err.message : String(err));
  }
}

const url = new URL(spec.path, cfg.baseUrl).toString();
const outcome = await new HubClient(cfg).callAgent({ id: agent, url, priceUsdc: "see catalog" }, body);
if (outcome.isError) die(outcome.text.slice(0, 2000));

const envelope = JSON.parse(outcome.text);
const report = path.join(process.env.RUNNER_TEMP || ".", `writerslogic-${agent}.json`);
writeFileSync(report, outcome.text);
const decision = decide(agent, envelope.data);
const md = summary(agent, decision, envelope, new URL("/api/v1/verify-provenance", cfg.baseUrl).toString(), notes);
if (process.env.GITHUB_STEP_SUMMARY) appendFileSync(process.env.GITHUB_STEP_SUMMARY, `${md}\n`);
else console.log(md);
if (process.env.GITHUB_OUTPUT) appendFileSync(process.env.GITHUB_OUTPUT, `merge-approved=${decision.approved}\nverdict=${decision.level}\nreport=${report}\n`);
if (outcome.payment) console.log(`Paid ${outcome.payment.amountUsdc} USDC from ${outcome.payment.payer}`);
if (shouldFail(failOn, decision)) die(decision.approved ? `${agent} reported warnings and fail-on is warn` : spec.needsDiff ? "Merge not approved; see the job summary" : `${agent} found blocking issues; see the job summary`);
