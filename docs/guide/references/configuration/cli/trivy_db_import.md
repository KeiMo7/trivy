## trivy db import

Import a database directory without contacting a registry

```
trivy db import [flags]
```

### Examples

```
  # Import a database carried in on removable media and activate it
  $ trivy db import --input /media/usb/trivy-db --activate

```

### Options

```
      --activate         activate the imported version
  -h, --help             help for import
      --input string     directory containing trivy.db
      --version string   version identifier to record (default: derived from content)
```

### Options inherited from parent commands

```
      --cacert string             Path to PEM-encoded CA certificate file
      --cache-dir string          cache directory (default "/path/to/cache")
  -c, --config string             config path (empty string disables loading) (default "trivy.yaml")
      --db-max-size string        maximum total size of retained vulnerability database versions (e.g. 2GB); oldest versions are evicted first
      --db-retention int          number of vulnerability database versions to keep for rollback (default 2)
  -d, --debug                     debug mode
      --generate-default-config   write the default config to trivy-default.yaml
      --insecure                  allow insecure server connections
  -q, --quiet                     suppress progress bar and log output
      --timeout duration          timeout (default 5m0s)
```

### SEE ALSO

* [trivy db](trivy_db.md)	 - Manage the local vulnerability database versions

