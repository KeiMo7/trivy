## trivy db

Manage the local vulnerability database versions

### Options

```
      --db-max-size string   maximum total size of retained vulnerability database versions (e.g. 2GB); oldest versions are evicted first
      --db-retention int     number of vulnerability database versions to keep for rollback (default 2)
  -h, --help                 help for db
```

### Options inherited from parent commands

```
      --cacert string             Path to PEM-encoded CA certificate file
      --cache-dir string          cache directory (default "/path/to/cache")
  -c, --config string             config path (empty string disables loading) (default "trivy.yaml")
  -d, --debug                     debug mode
      --generate-default-config   write the default config to trivy-default.yaml
      --insecure                  allow insecure server connections
  -q, --quiet                     suppress progress bar and log output
      --timeout duration          timeout (default 5m0s)
  -v, --version                   show version
```

### SEE ALSO

* [trivy](trivy.md)	 - Unified security scanner
* [trivy db activate](trivy_db_activate.md)	 - Make an installed version the active one
* [trivy db delta](trivy_db_delta.md)	 - Create or apply delta packages
* [trivy db export](trivy_db_export.md)	 - Export a self-verifying database archive for offline transfer
* [trivy db import](trivy_db_import.md)	 - Import a database directory without contacting a registry
* [trivy db import-archive](trivy_db_import-archive.md)	 - Import a self-verifying database archive
* [trivy db list](trivy_db_list.md)	 - List locally retained database versions
* [trivy db remove](trivy_db_remove.md)	 - Remove an installed version
* [trivy db rollback](trivy_db_rollback.md)	 - Switch back to the previous version, or to a specific one

