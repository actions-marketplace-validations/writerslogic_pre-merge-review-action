import assert from "node:assert/strict";
import { test } from "node:test";
import { decide, shouldFail, summary } from "./review.mjs";

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
