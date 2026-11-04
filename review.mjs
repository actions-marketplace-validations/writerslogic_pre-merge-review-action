/** Pure helpers for run.mjs, kept separate so they can be tested without git or the network. */

export const AGENTS = {
  "pre-merge-review": { path: "/api/v1/bundles/pre-merge-review", body: (diff) => ({ diff }) },
  "diff-gatekeeper": { path: "/api/v1/gatekeep-diff", body: (diff) => ({ gitDiff: diff }) },
  "unicode-safety-gate": { path: "/api/v1/unicode-safety-gate", body: (diff) => ({ diff }) },
};

export const FAIL_ON = ["block", "warn", "never"];

/** Merge decision and Unicode verdict from any of the three agents' response data. */
export function decide(agent, data) {
  const gate = agent === "pre-merge-review" ? data.results?.["diff-gatekeeper"] : agent === "diff-gatekeeper" ? data : undefined;
  const uni = agent === "pre-merge-review" ? data.results?.["unicode-safety-gate"] : agent === "unicode-safety-gate" ? data : undefined;
  const unicodeVerdict = uni?.verdict;
  const approved = agent === "pre-merge-review" ? data.mergeApproved === true : agent === "diff-gatekeeper" ? gate?.mergeApproved === true : unicodeVerdict !== "block";
  return { approved, unicodeVerdict, gate, uni };
}

export function shouldFail(failOn, { approved, unicodeVerdict }) {
  if (failOn === "never") return false;
  if (!approved) return true;
  return failOn === "warn" && unicodeVerdict === "warn";
}

const esc = (s) => String(s ?? "").replace(/[|<>]/g, (c) => ({ "|": "\\|", "<": "&lt;", ">": "&gt;" })[c]).replace(/\r?\n/g, " ");

/** Markdown for $GITHUB_STEP_SUMMARY. */
export function summary(agent, decision, envelope, verifyUrl) {
  const { approved, unicodeVerdict, gate, uni } = decision;
  const lines = [`## WritersLogic ${agent}: ${approved ? "approved" : "changes required"}`, ""];
  if (gate) {
    lines.push(`Risk score: ${gate.riskScore ?? "n/a"}/100`, "");
    const blockers = Array.isArray(gate.blockers) ? gate.blockers : [];
    for (const b of blockers.slice(0, 30)) lines.push(`- Blocker: ${esc(b)}`);
    if (blockers.length) lines.push("");
    const findings = [...(gate.securityFlaws ?? []), ...(gate.bugs ?? []), ...(gate.breakingChanges ?? [])].filter((f) => f && typeof f === "object");
    if (findings.length) {
      lines.push("| Severity | File | Finding |", "|---|---|---|");
      for (const f of findings.slice(0, 50)) lines.push(`| ${esc(f.severity)} | ${esc(f.file)} | ${esc(f.description)} |`);
      lines.push("");
    }
  }
  if (uni) {
    lines.push(`Unicode / Trojan Source gate: **${esc(unicodeVerdict)}** (${esc(uni.verdictReason)})`, "");
    const findings = Array.isArray(uni.findings) ? uni.findings : [];
    for (const f of findings.slice(0, 30)) lines.push(`- ${esc(f.severity)} ${esc(f.ruleId)} ${esc(f.ruleName)} at ${esc(f.path)}:${esc(f.line)}`);
    if (findings.length) lines.push("");
  }
  const id = envelope?._provenance?.credential?.id;
  lines.push(`Signed by the hub (${esc(envelope?._provenance?.credential?.issuer ?? "unknown issuer")})${id ? `, credential ${esc(id)}` : ""}. Verify the saved report free at ${verifyUrl}.`);
  return lines.join("\n");
}
