import assert from "node:assert/strict";
import { test } from "node:test";
import { AGENTS, decide, huggingFaceRefs, shouldFail, summary, validateOptions } from "./review.mjs";

const bundle = (mergeApproved, verdict) => ({
  mergeApproved,
  results: { "diff-gatekeeper": { mergeApproved, riskScore: 70, blockers: ["secret (aws) at a.ts:3"], securityFlaws: [{ severity: "high", file: "a|b.ts", description: "x <script>" }] }, "unicode-safety-gate": { verdict, verdictReason: "r", findings: [] } },
});

test("fail-on policy: block fails only unapproved, warn also fails Unicode warnings, never never fails", () => {
  for (const [failOn, approved, uni, expected] of [
    ["block", true, "warn", false], ["block", false, "pass", true],
    ["warn", true, "warn", true], ["warn", true, "pass", false],
    ["never", false, "block", false],
  ]) assert.equal(shouldFail(failOn, decide("pre-merge-review", bundle(approved, uni))), expected, `${failOn} ${approved} ${uni}`);
});

test("single-agent decisions", () => {
  assert.equal(decide("unicode-safety-gate", { verdict: "block" }).approved, false);
  assert.equal(decide("unicode-safety-gate", { verdict: "warn" }).approved, true);
  assert.equal(decide("diff-gatekeeper", { mergeApproved: true }).approved, true);
});

test("summary escapes table cells and names the verifier", () => {
  const md = summary("pre-merge-review", decide("pre-merge-review", bundle(false, "pass")), { _provenance: { credential: { issuer: "did:web:x" } } }, "https://hub/verify");
  assert.match(md, /a\\\|b\.ts/);
  assert.match(md, /x &lt;script&gt;/);
  assert.match(md, /https:\/\/hub\/verify/);
});

test("repository-agent decisions map verdicts to pass, warn and block", () => {
  const cases = [
    ["cra-exploit-clock", { verdict: "EXPLOITED_CANDIDATES_FOUND" }, "block"],
    ["cra-exploit-clock", { verdict: "INSUFFICIENT_EVIDENCE" }, "warn"],
    ["cra-exploit-clock", { verdict: "NO_EXPLOITED_EVIDENCE" }, "pass"],
    ["ai-bom-license-resolver", { verdict: "CONFLICT" }, "block"],
    ["ai-bom-license-resolver", { verdict: "UNDETERMINED" }, "warn"],
    ["ai-bom-license-resolver", { verdict: "ALLOWED" }, "pass"],
    ["dependency-advisor", { findings: [{ kind: "vulnerable", severity: "high" }] }, "block"],
    ["dependency-advisor", { findings: [{ kind: "stale", severity: "high" }, { kind: "vulnerable", severity: "low" }] }, "warn"],
    ["dependency-advisor", { findings: [] }, "pass"],
    ["reference-verifier", { priorityActions: [{ severity: "critical" }], summary: { flagged: 1 } }, "block"],
    ["reference-verifier", { priorityActions: [{ severity: "review" }], summary: { flagged: 1 } }, "warn"],
    ["reference-verifier", { priorityActions: [], summary: { flagged: 0 } }, "pass"],
  ];
  for (const [agent, data, level] of cases) {
    const d = decide(agent, data);
    assert.equal(d.level, level, `${agent} ${JSON.stringify(data)}`);
    assert.equal(shouldFail("block", d), level === "block");
    assert.equal(shouldFail("warn", d), level !== "pass");
    assert.equal(shouldFail("never", d), false);
  }
});

test("AI-BOM requires the facts that decide the verdict", () => {
  assert.match(validateOptions("ai-bom-license-resolver", { commercial: "", distribution: "api" }), /commercial/);
  assert.match(validateOptions("ai-bom-license-resolver", { commercial: "true", distribution: "" }), /distribution/);
  assert.equal(validateOptions("ai-bom-license-resolver", { commercial: "false", distribution: "on_prem" }), undefined);
  assert.match(validateOptions("cra-exploit-clock", { awarenessTime: "yesterday" }), /ISO 8601/);
});

test("Hugging Face references come from code and config, models and datasets apart", () => {
  const src = [
    'tok = AutoTokenizer.from_pretrained("meta-llama/Llama-3.1-8B")',
    'pipe = pipeline("text-generation", model="mistralai/Mistral-7B-v0.1")',
    'ds = load_dataset("allenai/c4")',
    "# see https://huggingface.co/datasets/allenai/c4 and https://huggingface.co/Qwen/Qwen2.5-7B",
    'x = AutoModel.from_pretrained("./local-dir")',
  ].join("\n");
  const r = huggingFaceRefs(src);
  assert.deepEqual(r.models, ["meta-llama/Llama-3.1-8B", "mistralai/Mistral-7B-v0.1", "Qwen/Qwen2.5-7B"]);
  assert.deepEqual(r.datasets, ["allenai/c4"]);
});

test("AI-BOM body carries the caller's use facts", () => {
  const body = AGENTS["ai-bom-license-resolver"].build({ models: ["a/b"], datasets: [] }, { commercial: "true", distribution: "api", fineTune: "", monthlyActiveUsers: "5000", jurisdiction: "de" });
  assert.deepEqual(body, { models: ["a/b"], uses: [{ id: "this-repo", commercial: true, distribution: "api", fine_tune: false, monthly_active_users: 5000, jurisdiction: "DE" }] });
});
