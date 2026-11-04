/** Reads repository files for the agents that work on the checkout rather than the PR diff. */
import { execFileSync } from "node:child_process";
import { readFileSync, statSync } from "node:fs";
import path from "node:path";
import { csv, huggingFaceRefs } from "./review.mjs";

const root = path.resolve(process.env.GITHUB_WORKSPACE || ".");

export class Skip extends Error {}

function tracked() {
  const out = execFileSync("git", ["ls-files", "-z"], { cwd: root, encoding: "utf8", maxBuffer: 256 * 1024 * 1024 });
  return out.split("\0").filter(Boolean);
}

/** Resolves a user-supplied path, refusing anything outside the checkout. */
function inside(p) {
  const abs = path.resolve(root, p);
  if (abs !== root && !abs.startsWith(root + path.sep)) throw new Error(`${p} is outside the repository checkout`);
  return abs;
}

const size = (abs) => { try { return statSync(abs).size; } catch { return -1; } };
const read = (abs) => readFileSync(abs, "utf8");

const SBOM_RE = /(?:^|\/)(?:[\w.-]*\.(?:cdx|spdx)\.json|(?:sbom|bom)(?:[\w.-]*)?\.json)$/i;

export function collectCra(opt) {
  const notes = [];
  let rel = opt.sbomPath;
  if (!rel) {
    const hits = tracked().filter((f) => SBOM_RE.test(f));
    if (!hits.length) throw new Error("No SBOM found (looked for *.cdx.json, *.spdx.json, sbom*.json, bom*.json). Generate one first, e.g. with anchore/sbom-action, and pass its path as sbom-path.");
    rel = hits[0];
    if (hits.length > 1) notes.push(`Several SBOMs found; used ${rel}. Set sbom-path to choose.`);
  }
  const abs = inside(rel);
  const n = size(abs);
  if (n < 0) throw new Error(`SBOM ${rel} not found`);
  if (n > 5_000_000) throw new Error(`SBOM ${rel} is ${n} bytes; the agent accepts up to 5 MB`);
  let sbom;
  try { sbom = JSON.parse(read(abs)); } catch { throw new Error(`SBOM ${rel} is not valid JSON`); }
  notes.push(`SBOM: ${rel}`);
  return { ctx: { sbom }, notes };
}

const MANIFEST_RE = /(?:^|\/)(?:package\.json|pyproject\.toml|Cargo\.toml|requirements[\w.-]*\.txt|package-lock\.json|npm-shrinkwrap\.json|yarn\.lock|pnpm-lock\.yaml|tsconfig\.json|jsconfig\.json|uv\.lock|poetry\.lock|Cargo\.lock)$/;
const LICENSE_RE = /^(?:LICENSE|LICENCE|COPYING)(?:\.(?:md|txt))?$/i;
const SOURCE_RE = /\.(?:[cm]?[jt]sx?|vue|svelte|astro|pyi?|rs)$/i;
const MAX_FILE_CHARS = 400_000;
const MAX_TOTAL = 6_000_000;

export function collectDependencies(opt) {
  const notes = [];
  const files = [];
  let total = 0;
  const skipped = [];
  const all = tracked();
  const add = (rel, cap) => {
    const abs = inside(rel);
    const n = size(abs);
    if (n < 0) return;
    if (n > cap || total + n > MAX_TOTAL) { skipped.push(rel); return; }
    const content = read(abs);
    if (content.length > MAX_FILE_CHARS) { skipped.push(rel); return; }
    files.push({ path: rel, content });
    total += n;
  };
  for (const rel of all.filter((f) => MANIFEST_RE.test(f) || LICENSE_RE.test(f))) add(rel, MAX_FILE_CHARS);
  if (!files.some((f) => !LICENSE_RE.test(f.path))) throw new Skip("No package.json, pyproject.toml, requirements*.txt or Cargo.toml found; nothing to review.");
  if (opt.includeSource) {
    const src = all.filter((f) => SOURCE_RE.test(f) && !/(?:^|\/)(?:node_modules|vendor|dist|build|target)\//.test(f));
    for (const rel of src.slice(0, 300)) add(rel, 200_000);
    if (src.length > 300) notes.push(`Uploaded the first 300 of ${src.length} source files; usage findings may be incomplete.`);
  } else {
    notes.push("Source files were not uploaded (include-source: false). The agent then sees no imports, treats every dependency as unused, and does not report advisories, deprecations or staleness for them. Set include-source: true for a full review.");
  }
  if (skipped.length) notes.push(`Skipped ${skipped.length} file(s) over the size limits: ${skipped.slice(0, 5).join(", ")}${skipped.length > 5 ? ", ..." : ""}`);
  notes.push(`Uploaded ${files.length} files (${total} bytes).`);
  return { ctx: { files }, notes };
}

const HF_SCAN_RE = /\.(?:py|ipynb|ya?ml|toml|json|[cm]?[jt]sx?|cfg|ini|sh|env\.example)$/i;
const HF_SKIP_RE = /(?:^|\/)(?:package-lock\.json|npm-shrinkwrap\.json|node_modules\/|vendor\/|dist\/)/;

export function collectAiBom(opt) {
  const notes = [];
  let models = csv(opt.models);
  let datasets = csv(opt.datasets);
  if (!models.length) {
    const found = { models: new Set(), datasets: new Set() };
    let scanned = 0;
    for (const rel of tracked().filter((f) => HF_SCAN_RE.test(f) && !HF_SKIP_RE.test(f)).slice(0, 5000)) {
      const abs = inside(rel);
      if (size(abs) > 1_000_000) continue;
      const refs = huggingFaceRefs(read(abs));
      refs.models.forEach((m) => found.models.add(m));
      refs.datasets.forEach((d) => found.datasets.add(d));
      scanned++;
    }
    models = [...found.models];
    if (!datasets.length) datasets = [...found.datasets];
    notes.push(`Scanned ${scanned} code and config files for Hugging Face references.`);
  }
  if (!models.length) throw new Skip("No Hugging Face model references found (from_pretrained, model=, repo_id=, huggingface.co/...). Set models to list them explicitly.");
  if (models.length > 10) { notes.push(`Found ${models.length} models; checked the first 10: ${models.slice(10).join(", ")} were not checked.`); models = models.slice(0, 10); }
  if (datasets.length > 10) { notes.push(`Found ${datasets.length} datasets; checked the first 10.`); datasets = datasets.slice(0, 10); }
  notes.push(`Models: ${models.join(", ")}${datasets.length ? `. Datasets: ${datasets.join(", ")}` : ""}`);
  return { ctx: { models, datasets }, notes };
}

export function collectReferences(opt) {
  const notes = [];
  const rels = csv(opt.bibPath);
  const bibs = rels.length ? rels : tracked().filter((f) => /\.bib$/i.test(f));
  if (!bibs.length) throw new Skip("No .bib file found; nothing to verify. Set bib-path to point at one.");
  let bibtex = "";
  const used = [];
  for (const rel of bibs) {
    const abs = inside(rel);
    if (size(abs) < 0) throw new Error(`${rel} not found`);
    const text = read(abs);
    if (bibtex.length + text.length > 400_000) { notes.push(`Stopped at 400 KB of BibTeX; not checked: ${bibs.slice(used.length).join(", ")}`); break; }
    bibtex += `${text}\n`;
    used.push(rel);
  }
  if (bibtex.trim().length < 10) throw new Skip("The .bib files are empty; nothing to verify.");
  notes.push(`BibTeX: ${used.join(", ")}`);
  let manuscript;
  if (opt.manuscriptPath) {
    const abs = inside(opt.manuscriptPath);
    if (size(abs) < 0) throw new Error(`${opt.manuscriptPath} not found`);
    manuscript = read(abs).slice(0, 400_000);
  }
  return { ctx: { bibtex, manuscript }, notes };
}

export const COLLECTORS = {
  "cra-exploit-clock": collectCra,
  "dependency-advisor": collectDependencies,
  "ai-bom-license-resolver": collectAiBom,
  "reference-verifier": collectReferences,
};
