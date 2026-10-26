# Provisioning runbook — issuing links to users

How to give someone access to the exit server, revoke it, and rotate. The exit
server (`vproxy-server`) is deployed on the VPS next to the cover site from the
**citycam** repo (`/opt/citylivecam`; `ssh -i ~/.ssh/squirrel
subwhale@91.184.243.9`, root-owned dir, `subwhale` has NOPASSWD sudo).

The citycam repo ships an `accounts.sh` helper, but as of 2026-10-26 it is **not
on the VPS** (the checkout predates it and the VPS cannot `git pull` — private
repo, no fetch key; files are edited directly). The VPS runs its services from
prebuilt ghcr images, so the live `server.toml` is maintained by hand. With a
handful of users (currently 3), the manual method below is the working path;
`accounts.sh` is an optional convenience to copy over later.

## Model

A user *is* a UUID. The server keeps an in-memory allow-list of UUIDs (`users`
in `server.toml`); a connection authenticates by proving it holds a UUID on
that list. So:

- **One UUID per person.** Never share a UUID — you can neither tell people
  apart nor revoke one without cutting the other. Keep a label→UUID note
  somewhere off the server (the server stores no names).
- **The link is the UUID plus where to reach the server**; it carries no secret
  beyond the UUID, so treat the link as the credential.
- **The allow-list lives only in the running process's memory**, loaded from
  `server.toml` at startup — every change needs a `vproxy-server` restart.

## The link format

```
h3://<uuid>@citylivecam.org:443?sni=citylivecam.org#<label>
```

`citylivecam.org` is the exit host (from the deploy's `.env` `DOMAIN`), port 443
shared with the cover site. `<label>` is a free-text name the client shows. The
clients (iOS app, CLI `-f <file>`, OpenWrt installer) consume this link as-is.

## Add a user (manual — the working method on the VPS today)

```sh
ssh -i ~/.ssh/squirrel subwhale@91.184.243.9
cd /opt/citylivecam
uuidgen | tr A-F a-f                       # a fresh lowercase UUID
sudo "$EDITOR" server.toml                 # add it to users = ["...", "<uuid>"]
docker compose restart vproxy-server       # apply (reloads the allow-list)
```

Then give the user `h3://<uuid>@citylivecam.org:443?sni=citylivecam.org#<label>`.
The restart briefly drops every live connection; clients redial automatically.

**Revoke** = delete that UUID's entry from `users` and restart. **Rotate** = add
a new UUID, send the new link, confirm the user is on it, then remove the old
one and restart once more (so access never lapses).

## Optional: the `accounts.sh` helper

`accounts.sh` (in the citycam repo) automates the above over a gitignored
`accounts.tsv` (`label<TAB>uuid`): `add <label>` (prints the link), `list`,
`rm <label>`, `regen`. It is worth copying onto the VPS once the roster grows
past a handful. Two cautions:

- It is **not on the VPS** yet and the VPS cannot `git pull`; copy it over
  (`scp` to a writable path, then `sudo cp` into `/opt/citylivecam`).
- `add`/`rm`/`regen` **rewrite `server.toml` entirely from `accounts.tsv`**, so
  first seed the TSV with every UUID already in `server.toml`
  (`printf 'label\t<uuid>\n' >> accounts.tsv`) — otherwise the first command
  drops them, including the OpenWrt router's account. `accounts.sh regen` then
  reproduces the current `users` list; diff before restarting if unsure.

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

Editing `server.toml` + a restart is fine for a handful of people, but every
change drops all live connections for a moment (the server reloads the whole
list at startup, not incrementally). Hot-reload of the allow-list — or a small
admin endpoint — removes that. When the **second VPS/exit** lands (planned
November), each user needs a *pair* of links with client-side failover; the
link format and `accounts.sh` grow a second host then.
