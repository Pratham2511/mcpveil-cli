<!-- Thank you! Link the issue this addresses (`Fixes #NN`) — required for `good first issue` claims. -->

## Summary

What does this PR do, and why? One short paragraph plus the linked issue.

Fixes #NN

## Changes

- What changed (bullets; note any files that are generated vs. hand-written)

## Testing

What you ran and what it showed. Evidence beats description — paste the relevant output.

```bash
npm run lint && npm test
```

- [ ] `npm run lint` passes
- [ ] `npm test` passes (all files)
- If this touches detection/planning: scanned a fixture or a real server you own, and the result changed as intended

## Compatibility

MCPVeil's contracts, and whether this PR touches them (leave untouched unless the change is the point):

- JSON report schema `2.0` — changes must be **additive only**
- Exit codes `0 / 1 / 2 / 3`
- CLI flags and config precedence (flags > config file > defaults)
- Per-tool call budgets and request limits

If you touched any of these, explain why the change is backward-compatible (or why it needs a version bump).

## Checklist

- [ ] No new dependency added (or discussed first)
- [ ] Docs/CHANGELOG updated if user-facing
- [ ] No real credentials, tokens, or private data in code, tests, fixtures, or output — synthetic shapes only (e.g. `AKIAIOSFODNN7EXAMPLE`)
- [ ] No test weakened, skipped, or given a longer timeout to hide a failure

## AI assistance disclosure

All contributions are responsible contributions — whether written by hand, by an AI pair, or somewhere in between.

- [ ] **No AI assistance was used**, or
- [ ] AI assistance was used for: _(which parts — code, tests, docs)_. I have read, understand, and take full responsibility for every line of this contribution as if I wrote it myself.

AI-assisted contributions are welcome. Undisclosed or unreviewed AI-generated contributions are not: they will be asked to complete this section before review proceeds.
