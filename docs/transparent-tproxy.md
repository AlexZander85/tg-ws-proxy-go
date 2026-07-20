# Transparent Telegram bridge (Linux TPROXY)

`tg-ws-proxy` can optionally accept direct Telegram MTProto obfuscated2
connections intercepted by a Linux router. Clients do not need a `tg://proxy`
link or an MTProxy secret in this mode.

The binary only provides the application-layer listener. It intentionally does
not create firewall rules, policy-routing tables, or Telegram address sets.
Those remain the responsibility of the router administrator or a frontend such
as `zapret-gui`.

## Start the listener

```sh
tg-ws-proxy \
  --host 127.0.0.1 \
  --port 1443 \
  --secret 0123456789abcdef0123456789abcdef \
  --transparent-listen 0.0.0.0:16080 \
  --transparent-bypass-mark 0x4100 \
  --transparent-dc-map 2=149.154.167.0/24 \
  --transparent-dc-map 4=149.154.166.0/24
```

The regular MTProxy listener remains available on `--host` / `--port`.
`--transparent-listen` enables the additional listener and requires Linux
`IP_TRANSPARENT` support plus the privileges needed to set it.

Options:

- `--transparent-listen HOST:PORT` enables the listener;
- `--transparent-bypass-mark MARK` applies `SO_MARK` to upstream TCP/WSS
  sockets so external firewall rules can exclude the proxy's own traffic;
- `--transparent-dc-map DC=IP_OR_CIDR` maps an original destination to a
  Telegram DC and may be repeated. When no mapping matches, the listener uses
  the DC encoded in the obfuscated2 handshake;
- `--transparent-fail-open=false` drops unrecognized connections instead of
  relaying them directly to their original destination.

Only direct TCP MTProto obfuscated2 transports are converted. UDP traffic,
voice calls, QUIC, and unsupported TCP transports are outside this listener's
scope.

## Minimal nftables example

The interception mark and the upstream bypass mark must be different. In this
example `0x4000` is used only to route intercepted packets to the local TPROXY
socket, while `0x4100` is the bypass mark configured on the proxy's own
upstream sockets.

```nft
 table inet tgws {
   set telegram_v4 {
     type ipv4_addr
     flags interval
     elements = { 149.154.160.0/20, 91.108.4.0/22 }
   }

   chain prerouting {
     type filter hook prerouting priority mangle; policy accept;

     iifname "br-lan" \
       ip daddr @telegram_v4 \
       tcp dport 443 \
       tproxy ip to 127.0.0.1:16080 \
       meta mark set 0x4000 \
       accept
   }
 }
```

Route only the interception mark to the local table:

```sh
ip rule add fwmark 0x4000/0xffff lookup 100
ip route add local 0.0.0.0/0 dev lo table 100
```

Any local-output interception rules should return immediately for mark
`0x4100`, otherwise the proxy may capture its own WSS/TCP connections.

Equivalent IPv6 rules require an IPv6 address set, an IPv6 TPROXY expression,
and a local `::/0` route in the policy-routing table.

## Fail-open behavior

Before a connection is classified as supported MTProto, the listener retains
all consumed bytes. If the handshake is short, unsupported, or its DC cannot
be resolved, fail-open mode opens a marked TCP connection to the original
destination, writes the retained prefix, and relays the remaining stream.

After a supported MTProto handshake has been accepted, existing WS, Cloudflare
Worker/domain, and TCP fallback behavior is used. A failure after that point
closes the connection rather than replaying the original encrypted session.
