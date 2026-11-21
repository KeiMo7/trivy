## trivy db delta apply

Apply a delta package on top of a locally installed version

```
trivy db delta apply [flags]
```

### Examples

```
  $ trivy db delta apply --base 7ac92b6e54e81046 --delta /media/usb/new.delta

```

### Options

```
      --base string    local base version (default: the active version)
      --delta string   path to the delta package
  -h, --help           help for apply
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

* [trivy db delta](trivy_db_delta.md)	 - Create or apply delta packages

