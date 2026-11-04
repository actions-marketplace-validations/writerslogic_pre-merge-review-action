# WritersLogic Pre-merge Review (GitHub Action)

Reviews each pull request's diff with the WritersLogic agent hub and fails the check when the merge is unsafe:

- **pre-merge-review** (default, $0.60 per PR): the exploit gatekeeper (bug hunter, patch synthesizer, secret, dependency and SAST scans) plus the Unicode / Trojan Source gate.
- **diff-gatekeeper** ($0.50) or **unicode-safety-gate** ($0.25, deterministic, no model).

Every result is a signed provenance envelope (W3C VC from `did:web:agents.writerslogic.com`). The action saves it as `report`, which you can verify for free at `POST https://agents.writerslogic.com/api/v1/verify-provenance`.

```yaml
on: pull_request
jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }
      - uses: writerslogic/pre-merge-review-action@v1
        with:
          wallet-private-key: ${{ secrets.WL_WALLET_KEY }}   # USDC on Base; x402 pays per call, no gas
          max-usdc-per-call: "1.00"
          fail-on: block                                     # block | warn | never
```

Payment: either `wallet-private-key` (a dedicated wallet holding a little USDC on Base; each call is an x402 `exact` authorization capped by `max-usdc-per-call`) or `api-key` (a hub API key). Store both as secrets. Diffs over 900 KB are refused before any payment.

Outputs: `merge-approved` (`true`/`false`) and `report` (path of the signed JSON). The job summary lists blockers, findings and Unicode rule hits.
