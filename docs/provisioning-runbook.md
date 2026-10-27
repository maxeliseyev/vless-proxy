# Provisioning runbook — issuing links to users

How to give someone access to the exit server, revoke it, and rotate. The exit
server (`vproxy-server`) is deployed on the VPS next to the cover site from the
**citycam** repo (`/opt/citylivecam`; `ssh -i ~/.ssh/squirrel
subwhale@91.184.243.9`, root-owned dir, `subwhale` has NOPASSWD sudo).

Accounts are managed with `accounts.sh` (on the VPS at `/opt/citylivecam`
since 2026-10-27) and applied with **SIGHUP** — `vproxy-server` 0.18.4+ reloads
its allow-list on SIGHUP, so adding or removing a user does **not** drop live
connections. `accounts.sh` keeps a gitignored `accounts.tsv` (`label<TAB>uuid`)
and regenerates `server.toml` from it.

## Model

A user *is* a UUID. The server keeps an in-memory allow-list of UUIDs (`users`
in `server.toml`); a connection authenticates by proving it holds a UUID on
that list. So:

- **One UUID per person**, labelled in `accounts.tsv`. Never share a UUID — you
  can neither tell people apart nor revoke one without cutting the other.
- **The link is the UUID plus where to reach the server**; it carries no secret
  beyond the UUID, so treat the link as the credential.
- **The allow-list is read per new connection.** A reload (SIGHUP) takes effect
  for the next connection; existing sessions carry on. So **adding** a user is
  seamless, and **removing** one takes effect on their next connect — to cut a
  removed user's live session immediately, restart instead of SIGHUP.

## The link format

```
h3://<uuid>@citylivecam.org:443?sni=citylivecam.org#<label>
```

`citylivecam.org` is the exit host (from the deploy's `.env` `DOMAIN`), port 443
shared with the cover site. `<label>` is a free-text name the client shows. The
clients (iOS app, CLI `-f <file>`, OpenWrt installer) consume this link as-is.
`accounts.sh` prints it for you.

## Add / list / revoke / rotate

```sh
ssh -i ~/.ssh/squirrel subwhale@91.184.243.9
cd /opt/citylivecam

sudo bash accounts.sh add alice      # new UUID, prints alice's h3:// link
sudo docker compose kill -s HUP vproxy-server   # apply, no dropped connections

sudo bash accounts.sh list           # every account with its link
sudo bash accounts.sh rm alice       # remove, then apply:
sudo docker compose kill -s HUP vproxy-server   # (restart instead to cut a live session now)
```

**Rotate** (new UUID, same person, no lapse): `add alice-new` + HUP, send the
new link, confirm they are on it, then `rm alice` + HUP.

`accounts.sh regen` just rewrites `server.toml` from `accounts.tsv` (e.g. after
hand-editing labels); it changes no UUIDs, so a HUP after it is a no-op.

## Notes

- `accounts.sh` **rewrites `server.toml` entirely from `accounts.tsv`**. The TSV
  was seeded from the UUIDs that were already live (labelled `user-1..3`,
  2026-10-27 migration); rename those labels in `accounts.tsv` as needed. Never
  run `add`/`rm`/`regen` with a TSV missing a current account — it would drop it.
- The VPS cannot `git pull` (private repo, no fetch key); to update `accounts.sh`
  itself, copy the new version over
  (`cat accounts.sh | ssh … 'sudo tee /opt/citylivecam/accounts.sh >/dev/null'`).
- Manual fallback: edit `users = [...]` in `server.toml` directly, then
  `docker compose kill -s HUP vproxy-server`.

## Verify

A probe finishes the transport handshake before app auth, so it proves
reachability from any machine with the CLI without a real account:

```sh
vproxy --probe -u 'h3://<any-uuid>@citylivecam.org:443?sni=citylivecam.org'
```

To prove a *specific* UUID is live, run a client with its link and make a
request; on the server `vproxy-server --stats` / `--tui` (its admin socket)
shows connections.

## Limits

SIGHUP reload handles add/remove without dropping connections, which is enough
for the current scale. Remaining rough edges: removing a user doesn't cut their
*live* session (only their next connect) unless you restart; and there is no
admin command to add/remove over the wire (it's still file + signal). When the
**second VPS/exit** lands (planned November), each user needs a *pair* of links
with client-side failover; the link format and `accounts.sh` grow a second host
then.
