# Team CI

Start with a disposable test server and restricted credentials. Store config,
reviewed expiring baselines and hashed snapshots in version control. Review
changes to those files like policy changes; a baseline must not become an
unreviewed way to hide risks. Separate logical IDs for read-only/admin accounts.

## npm CLI in any CI runner

```yaml
steps:
  - uses: actions/checkout@v7
  - uses: actions/setup-node@v7
    with: { node-version: '22', package-manager-cache: false }
  - run: npm ci
  - run: npm install --global mcpveil-cli@0.4.0 --ignore-scripts --engine-strict
  - run: >-
      mcpveil scan --stdio "node dist/test-server.js" --yes
      --format sarif --output report.sarif
      --baseline security/baseline.json --target-id staging-reader
  - uses: github/codeql-action/upload-sarif@v4
    if: always()
    with: { sarif_file: report.sarif }
```

Grant only `contents: read` and, if uploading, `security-events: write`.
Self-hosted scanners should isolate target code away from credentials, shared
runner files and network resources. Hosted runners are disposable machines but
an arbitrary stdio server still runs with the job's permissions. Use local
synthetic fixtures on forks; do not supply deployment secrets to untrusted PRs.

## Reusable action

Replace `owner/repository` below with this project's GitHub repository, then pin
an audited release commit SHA in production. The action installs the exact
`mcpveil-cli@0.4.0` release without lifecycle scripts and invokes its CLI through
argv, without interpolating target strings into a shell.

```yaml
- name: Security regression scan
  id: veil
  uses: owner/repository@v0.4.0
  env:
    MCP_TEST_TOKEN: ${{ secrets.MCP_TEST_TOKEN }}
  with:
    authorized: 'true'
    url: https://mcp.example.invalid/mcp
    bearer-env: MCP_TEST_TOKEN
    protocol: auto
    auth-policy: required
    check-origin: 'true'
    baseline: security/baseline.json
    target-id: staging-reader
- uses: github/codeql-action/upload-sarif@v4
  if: always() && steps.veil.outputs.sarif != ''
  with:
    sarif_file: ${{ steps.veil.outputs.sarif }}
```

Use either `stdio` or `url`. `header-env` is a JSON object mapping header names
to environment variable names. `forward-env` is a JSON array of explicitly
forwarded stdio environment variable names. Never put credential values in those
inputs. Outputs are `json` and `sarif`. JSON remains available for policy failures;
usage errors may prevent a report. The action preserves CLI exit codes.

The API exports baseline/snapshot creation and comparison helpers for custom
pipelines. Coverage/status are authoritative: accepted findings do not turn a
failed assessment into a pass. Tool drift is a separate gate from finding severity.
