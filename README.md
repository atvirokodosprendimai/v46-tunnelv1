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

### IPv4, IPv6, and dual-stack

Either family works on its own — `--pool 2001:db8:1::/120` is a perfectly good
pool, and every declared port is published on it.

A pool holding **both** families leases **one address of each**, and every
declared port is bound on both. That is what lets one hostname carry an A and an
AAAA record reaching the same service:

```sh
tunneld --pool 198.51.100.0/24 --pool 2001:db8:1::/120 ...
# agent logs: published ip=198.51.100.7,2001:db8:1::7 ports=443/tcp
```

Running out of one family does not deny the other: an agent still gets its IPv6
lease when the IPv4 half is exhausted, because taking the whole agent offline
over a shortage affecting half its addresses would be worse. Sticky leases are
per family, so a reconnect gets **both** of its previous addresses back.

The agent's `--target` is separate and unaffected — it is where the agent dials
locally, and defaults to `127.0.0.1`. Pass `--target ::1` for a local service
that only listens on IPv6.

### HTTPS for a served directory

`--domain` obtains a certificate and serves `--dir` over TLS:

```sh
tunnel-agent --server tunnel.example.com:4443 --token "$TOKEN" \
             --dir ./release --domain files.example.com --acme-accept-tos
```

This publishes 80 and 443 automatically — issuance needs both reachable. The
ACME HTTP-01 challenge arrives at the server on the leased address and is
forwarded to the agent like any other traffic, which is what makes issuance work
from behind a tunnel at all. Port 80 then redirects everything else to HTTPS.

**The server needs permission to bind 80 and 443.** They are privileged ports,
so `tunneld` must run as root or hold `CAP_NET_BIND_SERVICE`
(`setcap cap_net_bind_service=+ep /usr/local/bin/tunneld`, or
`AmbientCapabilities=CAP_NET_BIND_SERVICE` in a systemd unit). Without it the
bind fails and the lease is refused with `no declared port could be bound` —
which is the server telling you exactly this, not an ACME problem. The agent
needs no privileges either way; it only dials.

**You must create the DNS record yourself.** Nothing here writes DNS. The agent
logs the exact records that have to exist, one per leased address:

```
dns_records_needed="files.example.com A 198.51.100.7; files.example.com AAAA 2001:db8:1::7"
```

Use `--acme-staging` while setting this up. Let's Encrypt's production rate
limits are low enough to hit in one afternoon of debugging, and a staging
certificate is untrusted but issued against far looser limits.

`--acme-accept-tos` is required and has no default: accepting a certificate
authority's subscriber agreement is a decision for a person, not for this
program. `--acme-cache` (default: a per-user cache directory) holds the issued
certificates and the ACME account key — losing it means re-issuing on every
restart, which is how an agent walks into a rate limit.

The certificate fronts the served directory and **nothing else**. For a
forwarded port the tunnel carries raw bytes and whatever is behind it does its
own TLS, so a certificate at the agent would have nothing to terminate.

### Parked domain, random subdomains, and a built-in nameserver

`--domain` makes the server authoritative for a zone. Every agent that connects
is given a **random 24-character subdomain** resolving to its own leased
addresses, served by a nameserver built into `tunneld`:

```sh
tunneld --domain tun.example.com \
        --dns-listen :53 --dns-ns ns1.tun.example.com \
        --pool 198.51.100.0/24 --tokens /etc/tunneld/tokens ...

# agent logs: published ip=198.51.100.7 hostname=lxzb3hkpwj6s6oxwvtsvadhi.tun.example.com
```

Delegate the zone at the parent — `tun.example.com NS ns1.tun.example.com`,
with `ns1` pointing at this host — and the names resolve. There are no records
to create per agent: the nameserver answers from the live lease table, so a name
points at whatever address that agent holds right now and stops resolving the
moment its session ends.

The label is random rather than derived from the agent's name. A derived name
leaks who is connected to anyone who can guess it, and collides the moment two
operators pick the same agent name. It is fresh on every reconnect.

With a pool of several addresses, each subdomain resolves to its own agent's
address — that is what makes this a real-IP tunnel rather than SNI-based
demultiplexing onto one address.

**Port 53 is privileged** (`CAP_NET_BIND_SERVICE` or root), same as 80/443.

#### The nameserver is deliberately not a general one

It does not recurse, does not cache, and serves no zone file. A public
authoritative nameserver is a reflection and amplification vector, so:

- recursion is never advertised
- `ANY` is answered minimally (RFC 8482) rather than with everything known
- queries are rate limited per source (`--dns-qps`), and over the limit the
  server goes **silent** rather than refusing — a refusal is still a packet sent
  to whatever address the query claimed to come from, which is the reflection
  being prevented

### Wildcard certificate and terminated HTTPS

`--wildcard-cert` obtains `*.<domain>` from a CA over ACME **DNS-01**, answered
by the built-in nameserver — which is the only challenge type that can issue a
wildcard at all, and the reason running your own zone is worth it:

```sh
tunneld --domain tun.example.com --wildcard-cert --acme-accept-tos \
        --acme-email you@example.com ...

tunnel-agent --server tunnel.example.com:4443 --token "$TOKEN" \
             --dir ./release --https
```

The agent's subdomain then serves HTTPS with no certificate for the agent to
obtain or renew, however often it reconnects and however many agents there are:
one wildcard covers them all.

**⚠ On this path the tunnel is not a raw byte pipe.** The server holds the key
and decrypts, so it sees the plaintext of every request served this way. That is
inherent to terminating at the server rather than at the agent, and it is why it
is opt-in per agent (`--https` / `--https-backend <port>`) instead of applied to
port 443 for everyone. **Your forwarded ports are unaffected** — the server
still moves opaque bytes on those and cannot read them.

Use `--acme-staging` while getting delegation right; a wildcard order that fails
because the zone is not delegated yet is easy to retry into a production rate
limit.

`--https-port` moves termination off 443 for a deployment behind a load balancer
or one running unprivileged.

Refusals here cost the agent port 443 alone and never its lease. An agent that
also declared `443/tcp` itself is refused termination — the two mean opposite
things for the same listener — and keeps every other port it named.

#### Bring your own certificate instead

An agent can still obtain its **own** certificate for the server-assigned
hostname rather than using the server's wildcard, with `--acme` and
`--acme-accept-tos`. It uses HTTP-01 through the tunnel, so it needs 80 and 443
published, and the private key never leaves the agent — at the cost of an
issuance per agent and the rate limits that implies. `--https-backend` and
`--acme`/`--domain` are mutually exclusive: both terminate TLS, in different
places.

#### A note on the two `--domain` flags

`tunneld --domain` is the zone the **server** is authoritative for.
`tunnel-agent --domain` is a hostname **you** already own and point at the
agent's leased address yourself. They are different jobs on different binaries;
the agent's is for the bring-your-own-domain case above.

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
| `internal/subdomain` | random labels and the live label→agent registry |
| `internal/dnsd` | the authoritative nameserver and its rate limiter |
| `internal/wildcard` | the wildcard certificate: ACME DNS-01, renewal, cache |
| `internal/e2e` | a real server and agent over a real session |

## Tests

```sh
go test ./...
```

The e2e package leases `::1` while the agent dials `127.0.0.1`, so both ends can
use the same port number on one machine without the server's own listener
swallowing the agent's dial.
