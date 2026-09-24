# v46-tunnel

ngrok with a real IP: an agent on a laptop declares which of its local ports it
wants published, and the server leases it an address from a pool and binds those
ports there. Any TCP or UDP connection to `<leased-ip>:1234` becomes a
connection to `127.0.0.1:1234` on the agent's machine.

The difference from ngrok is the address. There is no HTTP routing, no
hostname-based demultiplexing, and no restriction to ports 80 and 443 — the
agent gets its own IP, and whatever ports it asked for on it, in either
protocol.

## Why the agent declares its ports

"Publish every port" and "publish the ports I named" are very different systems.
Owning all 65535 ports on an address means either 131,070 sockets per agent, or
kernel-assisted capture — TPROXY plus an nftables ruleset, `CAP_NET_ADMIN`,
Linux only.

Declaring the ports removes all of that. The server binds one ordinary listener
per declared port and needs no privileges beyond binding them. The agent needs
none at all: everything it does is a dial to its own host, never a listen.

## Running it

Server:

```sh
tunneld \
  --listen :4443 \
  --pool 198.51.100.0/24 \
  --tokens /etc/tunneld/tokens \
  --tls-cert /etc/tunneld/cert.pem --tls-key /etc/tunneld/key.pem
```

The pool addresses must already be on the host — added to an interface, or
routed to it as a block. The server only tracks which are free; it does not
configure interfaces, so a crash leaves nothing half-configured behind.

`tokens` is one `<token> <agent-name>` per line. The name is what the sticky
lease is keyed on.

### Sticky or random addresses

By default a reconnecting agent gets the address it had before. That is not a
convenience: everything pointed at a published address caches it — DNS records,
firewall allowlists, a client's config file — so an address that changes on
every reconnect breaks callers that are doing nothing wrong.

`--random-ip` allocates uniformly among the free addresses and remembers
nothing, so an agent generally lands somewhere new. Reach for it when rotation
is the point — cycling an address's reputation, or keeping an agent's address
from being a stable identifier — and not for anything long-lived. The startup
log prints `pool_mode=sticky` or `pool_mode=random` so you can confirm which is
in effect.

Either way, an agent that acquires twice without releasing (a reconnect racing
its own dead session's cleanup) gets the same address back rather than a second
one, so a flapping agent cannot drain the pool.

Agent:

```sh
tunnel-agent --server tunnel.example.com:4443 --token "$TOKEN" \
             --ports 80/udp,443,22,5432
```

`--ports` takes a comma-separated list. A bare number means TCP; `/udp` and
`/tcp+udp` say otherwise; `5000-5100` is an inclusive range.

Serving a directory instead of a local service:

```sh
tunnel-agent --server tunnel.example.com:4443 --token "$TOKEN" \
             --dir ./release --dir-port 8080
```

`index.html` is served when the directory has one, and a file listing when it
does not. The directory is served straight off the tunneled stream — there is no
local HTTP port, so nothing else on the agent's machine can reach it.

For development, `--tls-self-signed` on the server prints a fingerprint to pass
as the agent's `--tls-pin`. Pinning keeps verification on; `--insecure` turns it
off entirely and should not leave a lab.

## Two transports

QUIC is the primary. It gives one stream per tunneled connection, so loss on one
does not stall the others, and RFC 9221 datagrams for UDP, so a tunneled packet
stays unreliable and unordered — which is what the application that chose UDP
was written against.

WSS on the same port number is the fallback, for networks that pass no UDP at
all. Everything there rides one TCP connection through yamux, so tunneled
connections share loss recovery and tunneled UDP arrives reliably and in order.
That is a behaviour change for whatever is inside the tunnel, so the agent logs
a warning when it falls back. Use `--no-wss` on either side to disable it.

## What is deliberately blocked

Outbound mail — 25, 465, 587, 2525 — is refused by default. The reason is
deliverability, not secrecy: one pool address emitting spam gets the whole pool
listed, which costs every other agent sharing it. The receive-side mail ports
are not blocked; that would be a different decision, and `--deny-ports` is there
for an operator who wants it.

A denied port costs the agent that port and never its lease. One bad entry in a
list is a typo, not a reason to refuse the whole tunnel.

## Security

This publishes an agent's localhost on a public address. Be deliberate about it.

- **The agent enforces its own allow list.** It will only dial ports that were
  declared on its own command line. The server enforces the same set, but the
  agent is the side that actually reaches localhost, so a server that is
  compromised, misconfigured, or merely newer cannot talk it into opening a port
  its operator never named.
- **Declare narrowly.** Anything bound to `127.0.0.1` on a developer machine — a
  Docker API on 2375, a Redis on 6379, a Postgres on 5432 — becomes reachable
  from the internet if you declare that port.
- **There is no authentication on the published ports themselves.** Whatever is
  behind them is what a caller reaches. A served `--dir` is readable by anyone
  who can reach the address.
- **A refusal is delivered as a message, not by hanging up.** A dropped
  connection is what a network failure looks like, and agents retry those.

## Layout

| package | what it holds |
|---|---|
| `internal/portspec` | the `--ports` declaration |
| `internal/proto` | control messages and the framing for tunneled traffic |
| `internal/transport` | the seam; `quictp` and `wstp` implement it |
| `internal/pool` | address leases, sticky by agent identity |
| `internal/server` | listeners on the leased address, UDP flow table |
| `internal/agent` | local dialing, the served directory |
| `internal/tunnel` | the UDP conduit and the connection splice |
| `internal/e2e` | a real server and agent over a real session |

## Tests

```sh
go test ./...
```

The e2e package leases `::1` while the agent dials `127.0.0.1`, so both ends can
use the same port number on one machine without the server's own listener
swallowing the agent's dial.
