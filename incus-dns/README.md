# Incus DNS sync

`main.py` watches Incus lifecycle events and keeps per-container AAAA records
in the configured Technitium zone up to date.  Optionally, it seeds one
convenience CNAME in a separate service zone when an instance is created.

## Negative-caching safety (why records are *not* withdrawn eagerly)

A downstream recursive resolver (unbound, …) caches NXDOMAIN/NODATA for the
zone's SOA MINIMUM (RFC 2308).  Withdrawing a record for even a second —
e.g. while a container is being updated, or while it is failed and later
fixed — makes every lookup in that window keep failing *after* the record is
restored, for the whole negative TTL.  That used to take down dependent
services for the duration of routine container maintenance.

The generator therefore mirrors **instance existence, not runtime state**:

- **Stopped or frozen instances keep their AAAA.**  A stopped container
  keeps its name, MAC and address reservation, and comes back on the same
  address; an unreachable address is strictly better than a negative-cached
  name.  (`instance-stopped` no longer deletes anything.)
- **`instance-deleted` withdrawals are deferred** by
  `delete_grace_seconds` (default 120).  Any later event for the same name
  (a delete + re-create rebuild) cancels the withdrawal, and the timer
  re-checks `incus list` before deleting anyway.
- **Address changes are written add-first**: the new AAAA exists before the
  stale one is removed, so the name never has zero records.  A TTL-only
  change is an in-place update.
- **The SOA MINIMUM of both managed zones is capped at startup** to
  `max_negative_ttl` (default 60 s), so any negative answer that still leaks
  out (e.g. after a genuine deletion) is cached downstream for at most a
  minute instead of a quarter hour.
- **Startup sweeps orphans**: AAAA records whose instance no longer exists
  at all are removed — this also covers `instance-deleted` events missed
  while the daemon was down.  If `incus list` fails, nothing is removed.

TTL note: record TTLs bound how long clients may keep an address after a
container was recreated with a new one (new MAC → new SLAAC address), so the
deployed config uses a short TTL (300) — the extra query load is negligible
on an internal zone.

If you also control the downstream unbound, `serve-expired: yes` and
`cache-max-negative-ttl: 60` are a good belt-and-braces complement, but the
generator no longer depends on them.

```toml
[technitium]
ttl = 300                  # positive-answer TTL
max_negative_ttl = 60      # cap for zone SOA MINIMUM (negative cache)

[incus]
delete_grace_seconds = 120 # defer AAAA withdrawal after instance-deleted
```

## Fault isolation & PTR degradation

A DNS error on one instance never stops syncing the others: every event and
every initial-sync instance is processed in its own try/except, and deferred
deletions catch their own errors.

Technitium only writes the reverse zone when a PTR record is genuinely new
(it silently skips existing ones), so a token without reverse-zone *write*
permission can work for months and then fail on the first container rebuild
that produces a new address.  When that happens (`Cannot update reverse zone
… access was denied`), the AAAA is still added without the PTR and a warning
is logged — name resolution is never held hostage by reverse-zone
permissions.  To restore PTR creation, grant the API token's user write
access to the reverse zone (`…ip6.arpa`) in the Technitium admin UI.

## One-time service CNAMEs

With `service_zone` set, a CNAME such as `postgres.s.hetmer.net` pointing to
`postgres.c.hetmer.net` is considered an initial convenience value, not a
continuously managed record.

The program creates it only for an `instance-created` lifecycle event.  It
does not create or restore CNAMEs on:

- daemon restart or initial full sync;
- container restart;
- `incus rebuild` / rebase (which produces update/start events);
- address changes or any other AAAA sync.

The one-time claim is recorded before the DNS request in a JSON state file.
After creation, an administrator may rename, repoint, replace, or delete the
service record without this service changing it back.  CNAMEs are not deleted
when an instance is deleted.  If a *new* instance later reuses the deleted
instance's name, it gets one new initialization attempt; an existing alias at
that name is still left untouched.

On the first deployment (when no state file exists), the program first writes
every currently existing Incus instance name into that file and creates no
CNAMEs.  Only instances created after that baseline are eligible for the
one-time CNAME action.

The state file must live on persistent storage for the guarantee to survive a
rebuild of the DNS-sync service itself.  The default is
`/var/lib/incus-dns-sync/service-cname-state.json`; mount that directory on a
persistent Incus custom volume if this program runs in a rebuildable
container.

```toml
[technitium]
url = "http://[fdcc:c99d:b6cf:10::53]:5380"
api_token = "..."
zone = "c.hetmer.net"
service_zone = "s.hetmer.net"
service_cname_state_path = "/var/lib/incus-dns-sync/service-cname-state.json"
ttl = 300
create_ptr = true
```

If the state file is unreadable or malformed, startup fails rather than risk
recreating an administrator-managed alias.  To intentionally reset the
one-time history, stop the service and edit/remove that JSON file from its
persistent volume.
