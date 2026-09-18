# GeDefense native nginx path

GeDefense can be placed between nginx and a local application without adding a scripting runtime, nginx extension, SDK, or third-party library.

Flow:

`client -> nginx TLS termination -> GeDefense Unix socket -> local loopback application`

The nginx side uses only its ordinary upstream and reverse-proxy directives. GeDefense owns request normalization, body inspection, rate limits, response observation, XDR correlation, and the final allow/block decision.

## Security boundary

The inline socket is local and mode `0660`. Production deployments should assign `socket_group` to a dedicated group containing only the reverse-proxy worker identity and enable peer-credential enforcement when stable worker UID/GID values are available.

`inline_upstream` is deliberately restricted to either a clean absolute `unix:///...` socket path or an explicit loopback IP literal with an explicit port. Request data can therefore never select or rewrite the destination upstream. A Unix application socket removes the need to expose even a loopback TCP listener.

nginx must overwrite the two internal metadata headers shown in `gedefense-l7.conf.example`. GeDefense strips them before forwarding to the application. Request identifiers are generated inside GeDefense with the operating system CSPRNG and are never trusted from the client-facing proxy path. Cookies, Authorization, and other application credentials continue to the application but are excluded from GeDefense's inspection candidate set and evidence records.

The inline path is opt-in. `l7.enabled=true` keeps the local inspection API available; `l7.inline_enabled=true` additionally starts the native traffic path.
