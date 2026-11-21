## trivy db export

Export a self-verifying database archive for offline transfer

```
trivy db export [flags]
```

### Examples

```
  # Export the active version
  $ trivy db export --output /media/usb/trivy-db.tar.gz

  # Export a specific version
  $ trivy db export --version 7ac92b6e54e81046 --output /media/usb/trivy-db.tar.gz

```

### Options

```
  -h, --help             help for export
      --output string    path of the archive to write
      --version string   version to export (default: the active version)
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

