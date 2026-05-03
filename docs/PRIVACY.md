# vpsguard Privacy

vpsguard is a VPS-local security agent. It does not use a hosted vpsguard
backend, does not require an account, and does not accept remote commands.

By default, events are written to stdout/journald on the same VPS.

Optional outbound traffic:

- Telegram Bot API, only when `telegram.bot_token` and `telegram.chat_id` are configured.
- A healthchecks.io-style URL, only when `healthcheck_url` is configured.
- GitHub release downloads, only when the operator explicitly runs `vpsguard update`.

Collected event fields can include process paths, command lines, usernames,
source IPs, destination ports, changed file paths, and detector error messages.
Telegram bot tokens are never intentionally logged.

Uninstall with:

```sh
sudo vpsguard uninstall
```
