# Home Browser for a Personal AI Agent

Run a persistent Chromium browser on a home server or NAS, sign into websites yourself through a visible web GUI, and let a personal AI agent use the browser through an authenticated MCP endpoint — without giving the agent your website passwords.

This project combines two maintained Docker images:

- **LinuxServer Chromium** provides a visible, persistent browser that a person can operate through a streamed web desktop.
- **Scrapling** provides browser automation and an MCP server that an agent can call.

The containers share a network namespace so Scrapling can reach Chromium's Chrome DevTools Protocol (CDP) endpoint on `localhost`. CDP is never published as a host port.

> [!WARNING]
> This is a private home-network design. Do not port-forward the browser GUI, CDP, or MCP ports to the public internet. Read [SECURITY.md](SECURITY.md) before deploying it.

## What this solves

A cloud-hosted agent may browse from a datacenter IP address and a short-lived browser profile. Some websites respond with repeated CAPTCHAs, verification loops, or other bot checks.

A browser running at home provides:

- Egress through the household internet connection.
- A persistent browser profile instead of a disposable profile.
- Normal human login, including multifactor authentication.
- Reusable website sessions without sharing the account password with the agent.
- A visible browser the owner can inspect and control.

It does **not** guarantee that any site will accept the session. Sites can still expire cookies, demand another verification step, or apply their own automation rules. Use it at a human pace for ordinary personal research and account work, not bulk scraping.

## Architecture

```text
Owner's computer
    |
    | HTTPS, private LAN or VPN/Tailscale
    v
home-chromium
    |-- Streamed Chromium GUI (Selkies)
    |-- Persistent Chromium profile in /config
    |-- CDP on 127.0.0.1:9222 inside the shared namespace
    |
    | network_mode: service:chromium
    |
home-browser
    |-- Scrapling MCP server on container port 8000
    |-- Saved Playwright state in /data
    |
    v
AI agent connects to the MCP endpoint on host port 18000
```

### Why two containers?

A GUI-only Chromium container is easy for a person to use but does not expose an agent-friendly MCP interface.

An automation-only browser is easy for an agent to use but does not provide the same owner-controlled, persistent, visible login session.

The two-container arrangement keeps those roles separate:

| Container | Responsibility | What it must not hold |
| --- | --- | --- |
| `home-chromium` | Human interaction and the persistent browser profile | Public network exposure |
| `home-browser` | Agent automation and saved session state | The owner's website password |

## Repository contents

| File | Purpose |
| --- | --- |
| `docker-compose.example.yml` | Sanitized two-service Compose example |
| `.env.example` | Example values for local IDs, credentials, and the MCP token |
| `extract_state.py` | Exports the GUI browser's default-context storage state |
| `.gitignore` | Prevents local secrets, profiles, and session files from being committed |
| `SECURITY.md` | Threat model, exposure rules, and revocation steps |

## The three details that make it work

### 1. CDP stays on localhost

The Chromium container is started with remote debugging enabled:

```text
--remote-debugging-port=9222
--remote-debugging-address=0.0.0.0
--user-data-dir=/config/chromium-profile
```

In the tested Chromium 155 build, the CDP listener still bound to `127.0.0.1` despite the address flag. Rather than publishing port 9222 — which would expose full browser control — the Scrapling service shares Chromium's network namespace:

```yaml
network_mode: "service:chromium"
```

Scrapling can then connect to:

```text
http://127.0.0.1:9222
```

from inside the shared namespace.

Because Docker attaches host-port mappings to the namespace owner, the Scrapling mapping is declared on the Chromium service:

```yaml
ports:
  - "18000:8000"
```

That looks misplaced until the shared namespace is taken into account.

### 2. A restart of Chromium requires a restart of Scrapling

If Chromium is stopped or recreated, the old network namespace disappears. The automation container can remain running but be stranded in that dead namespace.

Use this order after an individual Chromium restart:

```bash
docker restart home-chromium
# Wait until Chromium itself has started.
docker restart home-browser
```

A full `docker compose up -d` normally handles service order through `depends_on`, but the rule matters after manual restarts and recreations.

### 3. A CDP automation context does not inherit the GUI login automatically

Scrapling's CDP implementation connects to the browser and creates a new browser context for its session. Playwright contexts are isolated: that new context does not automatically receive cookies from the browser's default context.

The visible tab can therefore be logged in while a new automation session still sees the public, logged-out site.

The workaround is to connect with Playwright to the **default context** — `browser.contexts[0]` — and export its storage state:

```python
browser = playwright.chromium.connect_over_cdp("http://127.0.0.1:9222")
context = browser.contexts[0]
context.storage_state(path="/data/browser-state.json")
```

The supplied `extract_state.py` performs that export inside the automation container and writes the result directly to the persistent `/data` volume. Cookie values are not printed.

A normal agent session then follows this sequence:

```text
browser_open
browser_load_state(path="/data/browser-state.json")
browser_fetch(...)
```

## Requirements

Tested environment:

- x86-64 Linux/NAS host
- Docker Engine with Docker Compose v2
- Chromium 155 at the time of testing
- Private LAN or an authenticated overlay network such as Tailscale or WireGuard

General recommendations:

- Several gigabytes of free space for images and the persistent browser profile.
- At least 4 GB RAM for light use; 8 GB or more is preferable on a multi-service NAS.
- A dedicated project directory that is not publicly shared.
- A password manager or another safe place to generate and store the GUI password and MCP token.

Check image architecture support before deploying on an ARM system.

## Quick start

### 1. Copy the example files

If you cloned this repository:

```bash
cp docker-compose.example.yml docker-compose.yml
cp .env.example .env
mkdir -p chromium-config browser-data
```

If you are using the files from a Gist, download or copy each file into one project directory using the same names.

### 2. Edit `.env`

Set values appropriate for your host:

```dotenv
PUID=1000
PGID=1000
TZ=Etc/UTC
CHROMIUM_GUI_USER=choose-a-username
CHROMIUM_GUI_PASSWORD=choose-a-long-unique-password
SCRAPLING_MCP_AUTH_TOKEN=generate-a-long-random-token
```

Generate a token with:

```bash
openssl rand -hex 32
```

Restrict the file where supported:

```bash
chmod 600 .env
```

Use the numeric `PUID` and `PGID` of the account that owns the project directory:

```bash
id "$USER"
```

Do not commit the completed `.env` file.

### 3. Replace the allowed hosts

Open `docker-compose.yml` and replace each placeholder in the Scrapling `command` section.

Each `--allowed-host` value must match the hostname or private IP address **and port** that the agent will use. For example, if the MCP URL is:

```text
http://nas-home.example:18000/mcp
```

the corresponding allowed host is:

```text
nas-home.example:18000
```

Remove entries you do not need. Do not leave angle-bracket placeholders in the working Compose file.

### 4. Validate before starting

```bash
docker compose config
```

Review the result privately. `docker compose config` expands environment variables, so its output may reveal the GUI password and MCP token. Never paste that output into a public issue, forum, or Gist.

### 5. Start the project

```bash
docker compose pull
docker compose up -d
docker compose ps
```

The GUI desktop can report as running before Chromium has fully initialized. Give the browser a minute on first launch.

### 6. Open the visible browser

From a computer on the same private network, open:

```text
https://<NAS_PRIVATE_IP>:13001/
```

Expected behavior:

- The browser warns about a self-signed certificate.
- The GUI asks for the username and password from `.env`.
- Chromium opens after authentication.

Confirm that the address belongs to your own NAS before accepting the certificate warning.

The HTTP interface is also published as host port `13000` in the example. LinuxServer documents the HTTP port primarily for use behind a reverse proxy. Prefer the HTTPS interface for direct private-network use.

### 7. Verify CDP locally

Run:

```bash
docker exec home-browser python3 -c \
  "import urllib.request; print(urllib.request.urlopen('http://127.0.0.1:9222/json/version', timeout=10).read().decode())"
```

The response should identify the browser and protocol version. More importantly, this succeeds inside the shared namespace while port 9222 has no entry in the Compose `ports` list.

### 8. Connect the agent

Configure the agent's MCP client with:

```text
URL: http://<NAS_PRIVATE_HOSTNAME>:18000/mcp
Authorization: Bearer <SCRAPLING_MCP_AUTH_TOKEN>
```

Use the exact hostname form covered by an `--allowed-host` entry.

A successful MCP initialization and tool list confirm that the endpoint, bearer token, and allowed-host settings agree. The tested Scrapling version exposed 16 browser tools.

## First website login

The account owner — not the agent — performs the sensitive login:

1. Open the Chromium GUI.
2. Navigate to the website.
3. Sign in normally with the account credentials.
4. Complete multifactor or email verification personally.
5. Confirm that the account page is visible.
6. Leave cookies and site data in place.

Use a dedicated Chromium profile for this project. A storage-state export captures the default context's cookies and origins, so do not mix unrelated sensitive accounts into the same profile unless you understand and accept that scope.

## Export a reusable session state

Copy the script into the running automation container:

```bash
docker cp extract_state.py home-browser:/tmp/extract_state.py
```

Run it:

```bash
docker exec home-browser \
  /app/.venv/bin/python /tmp/extract_state.py \
  --output /data/browser-state.json
```

The Python path reflects the tested Scrapling image layout. If a future image changes that layout, use the Python executable in that image that can import Playwright.

Successful output reports only:

- How many browser contexts were found.
- How many pages were open, by host rather than full URL.
- How many cookies and origins were exported.
- The state file's container path.

It does not print cookie names or values.

### Refreshing the state

A state file is a snapshot, not a permanent credential.

- If Chromium is still logged in but the state file is stale, run the extractor again.
- If Chromium itself is logged out, sign in through the GUI again and then rerun the extractor.
- If a site revokes all sessions, expect a fresh human login.

No container rebuild is needed for an ordinary cookie expiration.

## Verify the complete workflow

Do not call the setup complete merely because a page returns HTTP `200`. Public pages do that too.

Use this checklist:

- [ ] The GUI returns `401` without credentials.
- [ ] The GUI opens after the correct GUI login.
- [ ] `/json/version` answers from inside `home-browser`.
- [ ] Port `9222` is absent from all host-port mappings.
- [ ] The MCP client initializes and lists tools.
- [ ] An IP-check page shows the household connection rather than a cloud datacenter.
- [ ] The visible Chromium tab is logged into the intended account.
- [ ] A fresh automation session loads the state file.
- [ ] The resulting page shows an account name, account menu, `Log out` control, subscription/library content, or another logged-in-only marker.
- [ ] The automation session still works when started again without repeating the website password.

## Operations

For a persistent, credential-attributed record of MCP tools and sanitized browsing destinations, see [the optional audit gateway](AUDIT.md). It also records separate, unattributed CDP page-target observations. This is operational history with explicit privacy and coverage limits, not proof that an unrecorded action did not occur.

### Stop the project

```bash
docker compose down
```

This stops the containers without intentionally deleting the project directory. The Chromium profile remains in `chromium-config/`, and state files remain in `browser-data/` unless you delete those directories separately.

### Update the images

Update deliberately, not during active work:

```bash
docker compose pull
docker compose up -d
```

Then repeat the GUI, CDP, MCP, egress, and logged-in-page checks. Browser updates are the most likely cause of changes in CDP binding or profile behavior.

If Watchtower or a similar service manages the host, consider excluding these containers from unattended updates. The example Compose file can include:

```yaml
labels:
  - "com.centurylinklabs.watchtower.enable=false"
```

### Back up carefully

`chromium-config/` and `browser-data/` contain live browser material. A backup can preserve both convenience and risk. Encrypt any backup that leaves the Docker host.

## Troubleshooting

### Chromium is running but CDP refuses the connection

Wait for the browser process to finish starting. The streamed desktop may be available before Chromium opens its debugging listener.

If the problem began after an unclean recreation, check the dedicated profile for stale singleton files:

```text
chromium-config/chromium-profile/SingletonLock
chromium-config/chromium-profile/SingletonCookie
chromium-config/chromium-profile/SingletonSocket
```

Stop Chromium, remove only stale `Singleton*` entries, start Chromium, and then restart `home-browser`. Do not delete the complete profile unless losing every saved login is acceptable.

### CDP works from Chromium but not from Scrapling

The containers are probably no longer sharing a live network namespace. Confirm `network_mode: "service:chromium"` is present and restart `home-browser` after the current Chromium container.

Always test CDP using `127.0.0.1:9222` from inside `home-browser`.

### The GUI is logged in but the agent is logged out

This is the browser-context issue. Confirm that the visible GUI has a logged-in tab, run `extract_state.py` again, and load the resulting state into a fresh automation session.

Do not solve this by:

- Publishing port 9222.
- Sending individual cookies through chat.
- Sharing the browser profile directory publicly.

### MCP returns an allowed-host error

The host and port in the client URL must match an `--allowed-host` value exactly. A LAN hostname, private IP address, and overlay-network hostname are separate values.

### MCP returns an authorization error

Check that the client is sending the current token as a bearer token and that the automation container was recreated after `.env` changed.

### The GUI password stopped working after editing `.env`

An existing container does not pick up a new `.env` value merely because the file changed. Recreate the Chromium service, then restart the automation container:

```bash
docker compose up -d --force-recreate chromium
docker restart home-browser
```

### Chromium reports shared-memory errors

Increase `shm_size` and recreate the affected container. The example uses 1 GB for Chromium and 2 GB for Scrapling.

## GUI-only variant

If you only want a persistent remote browser and do not need an agent:

1. Keep the Chromium service and its `/config` volume.
2. Keep GUI authentication.
3. Publish only `13001:3001`.
4. Remove the Scrapling service and the `18000:8000` mapping.
5. Remove the CDP startup flags unless another trusted local tool needs them.

That variant is simpler, but it provides no MCP endpoint or saved-state automation workflow.

## Design principles

- Prefer maintained upstream images over running a new installer directly on the NAS operating system.
- Keep persistent data in explicit directories.
- Let the owner perform password and multifactor login.
- Give the agent a separate token-authenticated interface.
- Keep CDP on loopback.
- Verify an account-specific page instead of treating HTTP `200` as proof of login.
- Keep traffic human-paced.
- Document restart order and known failure modes.

## References

- [LinuxServer Chromium documentation](https://docs.linuxserver.io/images/docker-chromium/)
- [Scrapling](https://github.com/D4Vinci/Scrapling)
- [Chrome DevTools Protocol](https://chromedevtools.github.io/devtools-protocol/)
- [Playwright browser contexts](https://playwright.dev/python/docs/browser-contexts)
- [Playwright authentication](https://playwright.dev/python/docs/auth)

## License and attribution

This repository documents an original deployment arrangement using third-party open-source projects. Chromium, LinuxServer, Scrapling, Playwright, and related names belong to their respective projects. Check each upstream project for its own license and documentation.
