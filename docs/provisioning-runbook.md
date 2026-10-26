# Provisioning runbook — issuing links to users

How to give someone access to the exit server, revoke it, and rotate. This is
the manual process as it stands today; see [Limits](#limits) for what should
replace it.

## Model

A user *is* a UUID. The server (`vproxy-server`) keeps an in-memory allow-list
of UUIDs (`users` in `server.toml`). A connection authenticates by proving it
holds a UUID on that list — see the auth token in `crates/server/src/lib.rs`
(`users: Vec<Uuid>`). So:

- **One UUID per person.** Never share a UUID between people — you cannot tell
  them apart in logs and cannot revoke one without cutting the other.
- **The link is the UUID plus where to reach the server.** It carries no
  secret beyond the UUID, so treat the link itself as the credential.
- **The list lives only in the running process's memory**, loaded from
  `server.toml` at startup — every change needs a restart to take effect.

## The link format

```
h3://<uuid>@citylivecam.org:443?sni=citylivecam.org#<label>
```

- `<uuid>` — the user's UUID.
- host `citylivecam.org`, port `443` — the exit server (AEZA, Finland,
  `91.184.243.9`), sharing 443 with the cover site.
- `sni=citylivecam.org` — the name presented in TLS; keep it equal to the host.
- `#<label>` — a free-text label the client shows (e.g. `#Ratatosk`); optional.

The clients (iOS app, CLI `-f <file>`, OpenWrt installer) all consume this link
as-is. There is **no link generator** — you assemble the string by hand.

## Add a user

```sh
# 1. a fresh UUID for this person
uuidgen            # -> e.g. 7f3c1e2a-...-...     (lowercase it if needed)

# 2. add it to the server's allow-list
ssh -i ~/.ssh/squirrel subwhale@91.184.243.9
cd /opt/citylivecam
sudo docker compose ps                 # confirm the service name (vproxy-server)
sudo "$EDITOR" server.toml             # users = ["<existing>...", "<new-uuid>"]
sudo docker compose restart vproxy-server

# 3. hand the user their link
#    h3://<new-uuid>@citylivecam.org:443?sni=citylivecam.org#Ratatosk
```

The restart drops every live connection on the server for a moment; clients
redial automatically. Keep a note of which UUID belongs to whom somewhere off
the server (the server stores no names).

## Revoke a user

```sh
ssh -i ~/.ssh/squirrel subwhale@91.184.243.9
cd /opt/citylivecam
sudo "$EDITOR" server.toml             # delete that UUID's line from users
sudo docker compose restart vproxy-server
```

After the restart that UUID can no longer authenticate. There is no soft
"disable" — removal is the revoke.

## Rotate a user (new UUID, same person)

Add a new UUID, send the new link, confirm the user is on it, then remove the
old UUID and restart once more. Two restarts, so the user keeps access the
whole time (the old link works until the final restart).

## Verify

From any machine with the CLI, a probe finishes the transport handshake before
app auth, so it proves reachability without a real account:

```sh
vproxy --probe -u 'h3://<any-uuid>@citylivecam.org:443?sni=citylivecam.org'
```

To prove a *specific* UUID is live, run the client with its link and make a
request — on the server, `vproxy-server --stats` / `--tui` (its admin socket)
shows connections.

## Limits

This is the bottleneck to replace before onboarding beyond a handful of people:

- Editing TOML + restarting by hand does not scale and drops all connections
  on every change. A small admin action — an `accounts.sh add/remove <uuid>`
  that edits the file and reloads, or a server endpoint with hot-reload of the
  allow-list — removes both problems.
- When the **second VPS/exit** lands (planned November), each user needs a
  *pair* of links with client-side failover; the link format and this runbook
  grow a second host, and a generator becomes worth building.
