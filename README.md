# lycoris

## a bpf based proxy

currently, many proxy use http proxy or socks5 proxy protocol, all of them need the program support proxy protocol

actually this is a big limit, when you use some programs don't support specify the proxy, or it's very hard to enable
the proxy, you will want to smash you computer :(

lycoris can solve this problem, at least solve the 95%

## how it work

there are 3 parts about lycoris

- lycoris-bpf
- lycoris-client
- lycoris-server

### lycoris-bpf

`lycoris-bpf` will hook all socket connect(for now it only hook TCP4), and check if the dst ip should be proxies or not,
if it is a need proxy ip, lycoris-bpf will change the socket dst ip to `lycoris-client`, and save the real dst ip and
port in bpf lru map, so `lycoris-client` can get it and send the dst ip and port to `lycoris-server` to connect the
target

### lycoris-client

`lycoris-client` will listen a tcp socket, when a new tcp accepted, it will try to get the real dst ip and port from
bpf lru map, and send to `lycoris-server`

### lycoris-server

`lycoris-server` is a simple proxy server, like [camouflage](https://github.com/Sherlock-Holo/camouflage), trojan or
something else

## the whitelist/blacklist ip file

it just a simple txt like

```
127.0.0.1/8
10.100.0.0/16
```

## features

- [x] TCP4 proxy
- [x] UDP4 proxy
- [x] whitelist/blacklist ip mode switch
- [ ] TCP6 proxy
- [ ] UDP6 proxy
