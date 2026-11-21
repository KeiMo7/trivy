## trivy db import-archive

Import a self-verifying database archive

```
trivy db import-archive [flags]
```

### Examples

```
  # Import a database archive and activate it
  $ trivy db import-archive --input /media/usb/trivy-db.tar.gz --activate

```

### Options

```
      --activate       activate the imported version
  -h, --help           help for import-archive
      --input string   path to the database archive
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
  -v, --version                   show version
```

### SEE ALSO

* [trivy db](trivy_db.md)	 - Manage the local vulnerability database versions

