# MeeCeePeeSee

MeeCeePeeSee is a honeypot for the Model Context Protocol (MCP). It presents a decoy MCP tool server (file system access, web search and a read-only database connector by default) over the two HTTP transports that remote MCP clients use, and records every connection, every client handshake and every tool invocation as structured JSON.

MCP servers are the tool layer of AI assistants and agents: whoever can reach one can make it read files, run queries or call APIs on their behalf. Exposed MCP servers are now found by internet-wide scanning, and AI agents used for intrusion will happily enumerate and call any tool they are given. A decoy MCP server that no legitimate client is configured to use is therefore a high-signal tripwire: anything that connects is either a scanner, an attacker or an agent that has been pointed at it, and the log shows exactly what it asked for.

## Features

- Built on the official [MCP Python SDK](https://github.com/modelcontextprotocol/python-sdk), so the protocol is genuine: Streamable HTTP at `/mcp` (stateful by default, optional stateless and JSON-response modes) and the HTTP+SSE transport at `/sse` and `/messages/`.
- Persona files (YAML) define the server name, version, instructions, tools and their input schemas, a decoy file tree, decoy database tables and resources. Tools behave consistently: files that do not exist return the usual `ENOENT` error, files written with `write_file` can be read back in the same process (they are kept in memory, never written to disk), and SQL against an unknown table returns PostgreSQL's `relation does not exist` error.
- Pocket litter: the default persona contains decoy credentials in `.env`, `database.yml`, `settings.py`, a runbook and an `api_keys` table. They are written as `{{name}}` placeholders and filled at start-up with values generated for each install (see Honeytokens), so no two deployments serve the same keys.
- Logging: one JSON record per HTTP request (source address and port, method, path, status, user agent, session id, Authorization header) and per JSON-RPC message, with dedicated records for `initialize` (client name, version, protocol version and capabilities) and `tools/call` (tool name and arguments, including any prompt-injection text), and a record of what each tool returned. Written to a JSON lines file and to standard output.
- Alerting: optional webhook that receives the JSON record of selected events (by default `mcp.discover`, `mcp.initialize` and `mcp.tool_call`).
- Optional bearer-token lure: answer `401` with a Bearer challenge unless a token is presented; any token is then accepted and logged.
- Nothing a client sends is executed, written to disk or fetched. The honeypot makes no outbound connections except to the webhook you configure.

## Running

```
python3 -m venv venv && venv/bin/pip install -r requirements.txt
venv/bin/python meeceepee.py --port 8000 --log logs/meeceepee.jsonl
```

Connect with any MCP client, for example the MCP Inspector, `npx mcp-remote http://host:8000/mcp`, or a client configured for `http://host:8000/sse`.

Options (command line, or environment variables with the `MEECEE_` prefix):

| Option | Environment | Default | Meaning |
|---|---|---|---|
| `--host` | `MEECEE_HOST` | `0.0.0.0` | Listening address |
| `--port` | `MEECEE_PORT` | `8000` | Listening port |
| `--persona` | `MEECEE_PERSONA` | `personas/devtools.yaml` | Persona file |
| `--log` | `MEECEE_LOG` | `logs/meeceepee.jsonl` | Event log (JSON lines) |
| `--sensor` | `MEECEE_SENSOR` | host name | Sensor name in every record |
| `--mcp-path` | `MEECEE_MCP_PATH` | `/mcp` | Streamable HTTP endpoint |
| `--sse-path`, `--messages-path` | `MEECEE_SSE_PATH`, `MEECEE_MESSAGES_PATH` | `/sse`, `/messages/` | HTTP+SSE endpoints |
| `--no-sse` | `MEECEE_SSE=false` | SSE on | Disable the HTTP+SSE transport |
| `--stateless` | `MEECEE_STATELESS=true` | off | Stateless Streamable HTTP (no session ids) |
| `--json-response` | `MEECEE_JSON_RESPONSE=true` | off | Answer POSTs with JSON instead of an SSE stream |
| `--require-token` | `MEECEE_REQUIRE_TOKEN=true` | off | Bearer-token lure |
| `--trust-proxy` | `MEECEE_TRUST_PROXY=true` | off | Take the source address from X-Forwarded-For |
| `--seed-file` | `MEECEE_SEED_FILE` | `honeytokens.seed` beside the log | Per-install seed for honeytoken values |
| `--show-honeytokens` | | | Print the honeytoken values this install serves and exit |
| `--webhook` | `MEECEE_WEBHOOK` | none | URL that receives alert records (POST, JSON) |
| `--webhook-events` | `MEECEE_WEBHOOK_EVENTS` | `mcp.discover,mcp.initialize,mcp.tool_call` | Events sent to the webhook |

## Honeytokens

Any `{{name}}` in a persona string is a honeytoken placeholder. At start-up each one gets a value, in this order:

1. the environment variable `MEECEE_TOKEN_<NAME>` (for example `MEECEE_TOKEN_AWS_ACCESS_KEY_ID`);
2. an entry under `honeytokens:` at the top level of the persona file;
3. otherwise a value derived with HMAC-SHA256 from a random per-install seed, shaped like the real thing by the end of the name, ignoring a trailing `_<number>` (`aws_access_key_id`, `aws_secret_access_key`, `stripe_secret_key`, `api_key_prefix`, `secret_key`, `password`, `token`; anything else gets 24 letters and digits).

The seed is created on first start (mode 0600) in `honeytokens.seed` beside the event log, or at `--seed-file`, so the values stay the same across restarts; delete it to get new ones. `meeceepee.py --show-honeytokens` prints the values so that you can register them with whatever watches for their use, and the `sensor.start` record lists the placeholder names. Generated values are only decoys: nothing alerts when they are used unless you watch for them. For a real alert, put real honeytokens in their place, for example the access key id and secret of a Thinkst Canarytokens AWS key token:

```
MEECEE_TOKEN_AWS_ACCESS_KEY_ID=<key id from the token> MEECEE_TOKEN_AWS_SECRET_ACCESS_KEY=<secret from the token> python3 meeceepee.py
```

## Event records

```
{"timestamp": "...", "sensor": "mcp-gw01", "event": "mcp.initialize", "client": {"name": "claude-code", "version": "2.1.0"}, "protocol_version": "2025-06-18", ...}
{"timestamp": "...", "sensor": "mcp-gw01", "event": "mcp.tool_call", "tool": "read_file", "arguments": {"path": "/srv/app/.env"}, "src_ip": "192.0.2.10", ...}
```

Event types: `sensor.start`, `http.request`, `mcp.discover` (the per-request handshake of the 2026-07-28 protocol), `mcp.initialize` (the older handshake), `mcp.request` (any other JSON-RPC method), `mcp.tool_call`, `mcp.tool_result`, `mcp.response` (client replies), `webhook.error` (standard error only).

## Deployment notes

Give the persona names and tools that fit your environment, publish it where an attacker or a misused agent would find it (an MCP configuration file on a decoy workstation, an internal service catalogue, a DNS name such as `mcp.internal`), and alert on every `mcp.initialize` and `mcp.tool_call`. Treat the log as sensitive: tool arguments can contain whatever an attacker pastes in. The server name, version, instructions and tool set of the default persona are well known once published; change them.

## Licence

Apache License 2.0. Copyright 2026 James Brine.
