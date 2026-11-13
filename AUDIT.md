# Optional persistent MCP audit

Scrapling's network tools are useful during a live session, but they are not a durable agent audit. This optional gateway records credential-attributed MCP requests and outcomes in private JSONL files. A passive CDP observer records top-level browser URL observations, including navigation that can result from clicks or scripts.

## Set up

Use `docker-compose.audit.example.yml` as the working `docker-compose.yml`, create `.env` from the existing example, and set strong GUI credentials and an independent `SCRAPLING_MCP_AUTH_TOKEN`. That token belongs to the **internal upstream** and is not handed to clients.

```bash
umask 077
mkdir -p chromium-config browser-data audit-data
chmod 700 chromium-config browser-data audit-data
python3 generate_audit_clients.py
docker compose config --quiet
docker compose up -d --build
```

The credential generator refuses to overwrite an existing file. It creates `audit-clients.json` with mode 0600 and unique random tokens for `agent-a`, `agent-b`, and `agent-c`. Repeat `--client LABEL` to choose a different set. Supply each client only its own token, preferably through its credential store or dynamic-header helper. Do not paste token values into chat or command arguments.

Clients use Streamable HTTP at `http://127.0.0.1:18000/mcp` with `Authorization: Bearer <their-client-token>`. The gateway replaces it with the independent upstream token. The original server listens only at `127.0.0.1:8001` inside the shared container namespace; that port and CDP are not host-published. Host bindings are loopback-only. Use a private HTTPS reverse proxy or encrypted tunnel for remote clients, and add its exact host:port to the upstream `--allowed-host` list. Never enable public forwarding to obtain an audit log.

The audit service runs under `PUID:PGID`, so the private token file and audit directory must be readable/writable by that host account. Keep the browser/state mounts private too. No Docker socket, privileged mode or relaxed seccomp is needed. The optional audit image adds four explicitly pinned Python dependencies; its Docker build context excludes secrets and browser data.

## Read the audit

```bash
python3 audit_read.py audit-data/events.jsonl
python3 audit_read.py audit-data/events.jsonl --client agent-a
python3 audit_read.py audit-data/events.jsonl --json
```

The reader includes retained rotated files in chronological file order. A client filter omits the independent `unattributed` browser observations; use the unfiltered view to see those too.

Each record has schema version 1, a UTC timestamp and an event type. MCP requests receive a generated request ID joining the `request` and `completed` records. Fields include the authenticated credential label, HTTP/RPC method, tool, safe browser-session identifier, requested URL, status, duration and inspected RPC outcome when available. The label comes from the credential mapping, not `clientInfo` or a caller-supplied identity header. Clients sharing credentials are indistinguishable; labels identify credentials, not a verified human or model.

`denied` records cover absent/incorrect tokens. `rejected` records include oversized requests. HTTP 200 is distinguished from JSON-RPC or tool errors. Cancellation/disconnection, upstream failure and incomplete response inspection are recorded separately. A `request` with no matching completion means its outcome is unknown, not success. Requests are limited to 1 MiB; at most 1 MiB of a streamed response is inspected for outcome metadata, without retaining its body.

The passive observer emits `observer_connected`, `observer_gap`, and `browser_observation` records. First sightings are target snapshots, not proof of a newly initiated navigation. Later changed page-target URLs are navigation observations. They have `client: unattributed`; overlapping MCP request IDs are correlation hints only, capped at 16, with the total count retained. A click, redirect or script cannot always be assigned to an agent, especially with concurrent activity.

## Privacy, retention and limits

- Only HTTP(S) scheme, hostname, port and path are retained. URL userinfo, query strings and fragments are removed. Other URL schemes and malformed URLs are omitted. Paths are limited to 2048 characters and can still reveal account identifiers or secrets embedded in paths; this remains private browsing data.
- Tokens, headers, cookie values, password/MFA/form inputs, scripts, arbitrary arguments, error messages, response/page contents and screenshots are not audit fields. The gateway necessarily handles request/response bytes in memory while forwarding them. Do not enable payload or HTTP access logging alongside it.
- The directory must be 0700 and the active file 0600. Records are serialized, appended and fsynced. Failure to append the request record prevents forwarding with 503. A later completion-write failure cannot undo an action; stderr reports the gap and unmatched starts require investigation. Observer storage/connection failures retry and record gaps when storage permits.
- Rotation defaults to 100 MiB per file with five rotated backups, plus the active file. Oldest retained history is overwritten when this limit is reached. Configure `--max-log-bytes` and `--backups` for the desired retention; keep encrypted off-host backups when longer history matters. Record retention can contain sensitive URLs even with redaction.
- Logs persist through gateway/container restarts. They are **not tamper-proof** against the host account, container administrator or another agent with equivalent filesystem/Docker privileges. Separate credentials do not add tenant isolation to Scrapling's globally available browser sessions.
- This is not a complete network trace. It does not observe every subresource, iframe, download, interaction or internal application action. CDP observation covers page targets of the configured shared browser, not a separate browser launched elsewhere. Use `browser_open(cdp_url="http://127.0.0.1:9222")` for the intended shared-browser workflow.
- GUI activity may appear as unattributed browser observations. Direct CDP, container access, other endpoints and out-of-band operations can bypass MCP request records. Absence of a record cannot prove an action did not happen. For stronger evidence, use independently administered off-host collection and an appropriate retention policy.

## Verify

```bash
docker build -f Dockerfile.audit -t home-browser-audit:test .
docker run --rm --network none --entrypoint /usr/local/bin/python \
  -v "$PWD:/review:ro" -w /review home-browser-audit:test \
  -B -m unittest -v test_audit_proxy
```

Verify actual initialization, tool discovery, success and tool errors, invalid credentials, streaming/disconnects, navigation observation, log permissions, redaction and persistence in your deployment. Recheck GUI/CDP boundaries and session-state behavior after image changes. Keep browser updates and the original security guidance in scope; adding an audit does not fix vulnerabilities in the browser or base image.
