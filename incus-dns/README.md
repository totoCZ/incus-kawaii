# Incus DNS sync

`main.py` watches Incus lifecycle events and keeps per-container AAAA records
in the configured Technitium zone up to date.  Optionally, it seeds one
convenience CNAME in a separate service zone when an instance is created.

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
