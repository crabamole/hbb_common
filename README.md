# hbb_common

Fork of [rustdesk/hbb_common](https://github.com/rustdesk/hbb_common) for
[crabamole](https://github.com/crabamole): the library shared by the RustDesk clients and
the server (protocol, config, sockets).

Used as the `libs/hbb_common` submodule of
[rustdesk](https://github.com/crabamole/rustdesk) and
[rustdesk-server](https://github.com/crabamole/rustdesk-server).

## What it changes

Only how clients reach the server over WebSocket, so everything goes through one HTTPS host:

- WebSocket connections keep the api-server's port, and relays go to `/ws/relay`.
- A client dials the relay URL that hbbs hands out, exactly as given, and only `ws://` or
  `wss://` relays.

Everything else follows upstream, merged when RustDesk releases.

## Changing it

1. Commit here.
2. Move the submodule pointer in both rustdesk and rustdesk-server, so the clients and the
   server keep the same protocol.
