# Safe local test environment

Use only authorized servers and disposable data. `--yes` authorizes starting
the selected target; it is not a safety boundary around that target.

For a container or VM test:

1. Install Node 22.12+ or 24 and the scanner/dependencies during setup.
2. Copy a test server and synthetic data into the disposable environment.
3. Disconnect external networking before active tests. Keep only private
   loopback networking when HTTP/SSE fixtures need it.
4. Use an empty home, clear the environment, drop capabilities, and avoid host
   credential directories, agent sockets, Docker sockets or production volumes.
5. Mount inputs read-only; provide a separate temporary writable directory for
   the test server. Apply CPU/memory/process/time limits.
6. Run `mcpveil scan --stdio "node test-server.js" --yes`, then inspect status,
   errors, coverage and redacted evidence before copying reports out.

Linux development checks can use rootless Bubblewrap with user, mount, PID,
IPC and network namespaces. Docker/Podman and VMs are alternatives. Verify the
boundary with a harmless process before executing target code. A container
shares its kernel; use a disposable VM for targets outside your trust model.

MCPVeil's temporary child HOME and filtered environment reduce accidental
credential forwarding. They do not prevent arbitrary server code from reading
other files accessible to the scanner's operating-system user. Remote test
services should have their own scoped synthetic accounts and data.

Default SQL probes contain no write statements. Other MCP tools can still
change state when invoked, even with harmless text as their argument. Exclude
known mutating tools with `--allow-tool` and use inventory-only mode when active
effects are unacceptable.
