# Versioned Vulnerability Database Store

Trivy keeps its vulnerability database in a **versioned store** under the cache
directory (`<cache-dir>/db`). Instead of replacing a single `trivy.db` file, the
store retains several complete versions side by side and makes one of them
active at a time. This page describes the guarantees and the operations
available for air-gapped and otherwise network-restricted environments.

## Why

A network-disconnected update used to be a single full-file copy. If the copy
was interrupted, the machine was left with a half-written database and no way to
tell, and the only recovery was to delete the whole cache and start over. The
versioned store changes that:

- Every version is verified against a sha256 digest before it is used.
- A version becomes usable only after its manifest is written atomically, so an
  interrupted transfer cannot damage the version that is already in use.
- Switching versions is a single atomic rename, so a running scan sees either
  the complete old version or the complete new one.
- Previous versions are retained, so rolling back is a supported operation.

## Layout

```
<cache-dir>/db/
  .lock                      advisory lock (readers shared, writers exclusive)
  current                    active version identifier
  versions/
    <version>/
      trivy.db
      metadata.json
      manifest.json          sizes, digests, schema version, timestamps
  staging/                   in-progress transfers, never read by scans
```

A version identifier is derived from the sha256 digest of `trivy.db` and is the
value accepted by `--db-version`.

## Guarantees

| Requirement | How it is met |
| --- | --- |
| Only verified data is used | Every file is hashed and compared with the manifest at the moment it is opened for a scan. A mismatch makes the database unavailable; it is never used in a degraded mode. |
| Multiple usable versions | Each version is self-contained and independently verifiable. |
| Atomic switching | The active version is a text file replaced by an atomic rename. Readers hold a shared lock, writers an exclusive one. |
| Interrupted transfer is safe | Downloads are staged outside `versions/`; nothing is installed unless the staged copy verifies and the manifest is written. |
| Predictable eviction | Versions are evicted oldest first, never below `--db-retention`, and only until `--db-max-size` is satisfied. |
| Reproducible reports | Each report records the database version that produced it. |

## Retention

```bash
# Keep the active version plus two rollback candidates
trivy image --db-retention 3 alpine:3.20

# Cap the total size of retained versions; the oldest are evicted first
trivy image --db-max-size 2GB alpine:3.20
```

`--db-retention` defaults to `2` (the active version and one rollback target).
Size pressure never evicts below the retention floor; if the floor itself
exceeds `--db-max-size`, Trivy logs a warning rather than deleting versions the
policy says to keep.

The same settings can be put in `trivy.yaml`:

```yaml
db:
  retention: 3
  max-size: 2GB
```

## Working with versions

```bash
# List retained versions, newest first; the active one is marked
trivy db list

# Use a specific version for one scan, without changing the active version
trivy image --db-version 4e9eeae0fecac123 alpine:3.20

# Make a version active for subsequent runs
trivy db activate 4e9eeae0fecac123

# Switch back to the previous version
trivy db rollback

# Switch to a specific version (fails explicitly if it was evicted)
trivy db rollback 4e9eeae0fecac123

# Remove a non-active version
trivy db remove 4e9eeae0fecac123
```

A report produced with a pinned version records it, for example in JSON:

```json
{
  "Trivy": {
    "VulnerabilityDB": { "Version": "4e9eeae0fecac123" }
  }
}
```

## Carrying a database into an isolated network

### Full archive

Export a version on the connected side and import it on the isolated side:

```bash
# Connected side
trivy db export --output /media/usb/trivy-db.tar.gz

# Isolated side
trivy db import-archive --input /media/usb/trivy-db.tar.gz --activate
```

The archive carries its manifest. On import every byte is verified before the
version is installed; a truncated or altered archive is refused and the active
version is untouched.

A plain directory (`trivy.db` plus optional `metadata.json`) can also be
imported:

```bash
trivy db import --input /media/usb/trivy-db --activate
```

### Delta packages

When only a small part of the database changed, a delta package carries only the
changed bytes:

```bash
# Connected side: build the delta between two database directories
trivy db delta create --base ./old-db --target ./new-db --output /media/usb/new.delta

# Isolated side: apply it on top of the installed base version
trivy db delta apply --base 4e9eeae0fecac123 --delta /media/usb/new.delta
```

Applying a delta reconstructs a complete version and verifies it against the
digest recorded in the delta header. If the base is not present, or the result
does not match, the delta is refused with a checkable reason and the active
version remains in place. The reconstructed result is byte-for-byte identical to
a full install of the same database.

## Exit codes

Operational database failures use dedicated exit codes so that automation can
react without parsing logs:

| Code | Meaning |
| --- | --- |
| `10` | The vulnerability database is unavailable (missing, corrupt, or failed verification). |
| `11` | The requested database version is not present locally. |
| `12` | The rollback could not be performed (for example, the target was evicted). |

## Behaviour on failure

- **Interrupted transfer**: the current version stays active and usable; the
  update reports an error. Nothing is silently skipped.
- **Delta cannot reproduce the full database**: the delta is rejected with the
  expected and actual digests; the active version is unchanged.
- **Rollback target evicted**: the command fails explicitly with exit code 12;
  it does not pretend to succeed.

## Legacy databases

A cache created by an older Trivy release (a single `trivy.db` without
`versions/`) is still read directly. Running an update converts it: the new
version is installed into the store and becomes active.
