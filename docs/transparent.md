# Transparent Telegram bridge (Linux TPROXY)

The transparent listener accepts connections redirected with Linux TPROXY. It reads Telegram's direct obfuscated2 init packet, resolves the destination data center from the original destination IP, and reuses the existing WebSocket, Cloudflare and TCP fallback pipeline.

The feature is disabled by default and does not modify firewall or routing state.

## Start the listener

Transparent-only IPv4 example:

```shell
tg-ws-proxy \
  --no-mtproxy-listener \
  --transparent-listen 0.0.0.0:1444 \
  --outbound-mark 0x8000
```

The process needs `CAP_NET_ADMIN` (or root) both for `IP_TRANSPARENT` and for Linux `SO_MARK`. Omit `--no-mtproxy-listener` to keep the normal secret-based MTProxy listener active in parallel.

The listener option is repeatable, which allows explicit dual-stack binding:

```shell
--transparent-listen 0.0.0.0:1444 \
--transparent-listen '[::]:1444'
```

`--max-conns` is a process-wide limit shared by the explicit MTProxy listener and all transparent listeners.

Unrecognized or incomplete connections are forwarded to their original destination by default. Disable that behavior with:

```shell
--transparent-fail-open=false
```

Fail-open, direct Telegram TCP fallback, WebSocket, CF proxy, CF Worker and pool connections all use the configured outbound mark. This lets firewall OUTPUT rules return marked packets before applying TPROXY and prevents routing loops.

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

For locally generated Telegram traffic, return the proxy's outbound mark before marking other OUTPUT packets:

```shell
nft 'add chain inet tg_ws_proxy output { type route hook output priority mangle; policy accept; }'
nft add rule inet tg_ws_proxy output meta mark 0x8000 return
# Add Telegram destination matching and packet marking after the return rule.
```

Adapt interface matching, IPv6 rules, Telegram address sets and exclusions to the host firewall. The numeric mark passed to `--outbound-mark` must match the firewall bypass rule and **must be different from the TPROXY routing mark**. The TPROXY mark has an `ip rule` that routes packets to a local table; reusing it as `SO_MARK` could route the proxy's own upstream sockets back to loopback before the OUTPUT chain can bypass them.
