## trivy db list

List locally retained database versions

```
trivy db list [flags]
```

### Examples

```
  # List database versions
  $ trivy db list

  # List versions as JSON
  $ trivy db list --format json

```

### Options

```
      --format string   output format (table or json) (default "table")
  -h, --help            help for list
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

