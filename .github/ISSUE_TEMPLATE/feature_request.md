---
name: Feature request
about: Propose a new check, payload, transport, or integration
title: ''
labels: ['enhancement']
assignees: ['Pratham2511']
---

**Is your feature request related to a problem?**
E.g. "I scanned a server whose tool accepts a callback URL and MCPVeil had no way to test outbound calls to non-loopback hosts."

**What do you want to add?**

Pick the closest category:

- [ ] New security check (deterministic, response-confirmed — see CONTRIBUTING.md for the checklist)
- [ ] New payload pattern for an existing check
- [ ] Schema/arg-planner improvement (new real-world JSON-schema shape)
- [ ] Transport / connection handling
- [ ] Report format or CI integration (SARIF, exit codes, config)
- [ ] Docs / DX

**Why it matters**
Who hits this in practice? Link the affected real server(s), CVE writeups, or MCP spec sections if you can.

**Proposed behavior**

```bash
# what the CLI interaction would look like
```

**Will you help build it?**
Good-first-issue friendly: new payload packs and check implementations are documented in CONTRIBUTING.md.

- [ ] I can submit a PR
- [ ] I can provide a test server / repro
- [ ] Just suggesting
