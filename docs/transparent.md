# Transparent Telegram bridge (Linux TPROXY)

The transparent listener accepts connections redirected with Linux TPROXY. It reads Telegram's direct obfuscated2 init packet, resolves the destination data center from the original destination IP, and reuses the existing WebSocket, Cloudflare and TCP fallback pipeline.

The feature is disabled by default and does not modify firewall or routing state.

## Start the listener

```shell
tg-ws-proxy \
  --host 127.0.0.1 \
  --port 1443 \
  --transparent-listen 0.0.0.0:1444
```

The process needs `CAP_NET_ADMIN` (or root) to create an `IP_TRANSPARENT` socket.

Unrecognized or incomplete connections are forwarded to their original destination by default. Disable that behavior with:

```shell
--transparent-fail-open=false
```

## Data-center mappings

Built-in mappings cover the known Telegram DC endpoints and commonly used DC2/DC4 ranges. The original destination mapping takes precedence over the DC field in the obfuscated2 header because direct Telegram clients do not always populate that field reliably.

Additional or overriding mappings are repeatable:

```shell
--transparent-dc-map 2:149.154.167.0/24 \
--transparent-dc-map 4:2001:67c:4e8:f004::/64
```

## nftables example (IPv4)

Choose a mark and routing table that do not conflict with the rest of the router configuration:

```shell
ip rule add fwmark 0x1444/0xffff lookup 1444
ip route add local 0.0.0.0/0 dev lo table 1444

nft add table inet tg_ws_proxy
nft 'add chain inet tg_ws_proxy prerouting { type filter hook prerouting priority mangle; policy accept; }'
nft add rule inet tg_ws_proxy prerouting \
  ip daddr { 91.108.4.0/22, 149.154.161.0/24, 149.154.165.0/24, 149.154.166.0/24, 149.154.167.0/24, 149.154.171.5, 149.154.175.50, 149.154.175.100 } \
  tcp dport 443 meta mark set 0x1444 tproxy to :1444 accept
```

Adapt interface matching, IPv6 rules, Telegram address sets and exclusions to the host firewall. In particular, avoid redirecting traffic created by the proxy itself when applying equivalent rules to locally generated traffic.
