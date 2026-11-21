package db

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/samber/lo"
	bolt "go.etcd.io/bbolt"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/metadata"
	"github.com/aquasecurity/trivy/pkg/clock"
	"github.com/aquasecurity/trivy/pkg/db/store"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/oci"
)

const (
	SchemaVersion = db.SchemaVersion
	dbMediaType   = "application/vnd.aquasec.trivy.db.layer.v1.tar+gzip"
)

var (
	// GitHub Container Registry
	DefaultGHCRRepository = fmt.Sprintf("%s:%d", "ghcr.io/aquasecurity/trivy-db", db.SchemaVersion)
	defaultGHCRRepository = lo.Must(name.NewTag(DefaultGHCRRepository))

	// GCR mirror
	DefaultGCRRepository = fmt.Sprintf("%s:%d", "mirror.gcr.io/aquasec/trivy-db", db.SchemaVersion)
	defaultGCRRepository = lo.Must(name.NewTag(DefaultGCRRepository))

	Close = db.Close
	Path  = db.Path
)

// Init initializes the vulnerability database with read-only mode
func Init(dbDir string, opts ...db.Option) error {
	opts = append(opts, db.WithBoltOptions(&bolt.Options{ReadOnly: true}))
	return db.Init(dbDir, opts...)
}

type options struct {
	artifact       *oci.Artifact
	dbRepositories []name.Reference
	storeOptions   StoreOptions
}

// Option is a functional option
type Option func(*options)

// WithOCIArtifact takes an OCI artifact
func WithOCIArtifact(art *oci.Artifact) Option {
	return func(opts *options) {
		opts.artifact = art
	}
}

// WithDBRepository takes a dbRepository
func WithDBRepository(dbRepository []name.Reference) Option {
	return func(opts *options) {
		opts.dbRepositories = dbRepository
	}
}

// WithStoreOptions sets the retention policy of the versioned store.
func WithStoreOptions(storeOpts StoreOptions) Option {
	return func(opts *options) {
		opts.storeOptions = storeOpts
	}
}

// Client implements DB operations
type Client struct {
	*options

	dbDir    string
	metadata metadata.Client
	quiet    bool
}

func Dir(cacheDir string) string {
	return filepath.Join(cacheDir, "db")
}

// NewClient is the factory method for DB client
func NewClient(dbDir string, quiet bool, opts ...Option) *Client {
	o := &options{
		dbRepositories: []name.Reference{
			defaultGCRRepository,
			defaultGHCRRepository,
		},
		storeOptions: DefaultStoreOptions(),
	}

	for _, opt := range opts {
		opt(o)
	}

	return &Client{
		options:  o,
		dbDir:    dbDir,
		metadata: metadata.NewClient(dbDir),
		quiet:    quiet,
	}
}

// NeedsUpdate check is DB needs update
//
// When the versioned store is in use, its active version is validated by
// verifying every file against the recorded digest. A corrupt or evicted
// active version is never treated as usable; it makes NeedsUpdate report that
// an update is required (or fail under --skip-db-update).
func (c *Client) NeedsUpdate(ctx context.Context, cliVersion string, skip bool) (bool, error) {
	if st, ok := c.store(); ok {
		return c.needsUpdateFromStore(ctx, st, cliVersion, skip)
	}
	var noRequiredFiles bool
	if _, err := os.Stat(db.Path(c.dbDir)); errors.Is(err, os.ErrNotExist) {
		log.DebugContext(ctx, "There is no db file")
		noRequiredFiles = true
	}
	meta, err := c.metadata.Get()
	if err != nil {
		log.DebugContext(ctx, "There is no valid metadata file", log.Err(err))
		noRequiredFiles = true

		meta = metadata.Metadata{Version: db.SchemaVersion}
	}

	// We can't use the DB if either `trivy.db` or `metadata.json` is missing.
	// In that case, we need to download the DB.
	if noRequiredFiles {
		if skip {
			log.ErrorContext(ctx, "The first run cannot skip downloading DB")
			return false, store.Unavailable("--skip-db-update cannot be specified on the first run: no usable local database")
		}
		return true, nil
	}

	// There are 3 cases when DownloadAt field is zero:
	// - metadata file was not created yet. This is the first run of Trivy.
	// - trivy-db was downloaded with `oras`. In this case user can use `--skip-db-update` (like for air-gapped) or re-download trivy-db.
	// - trivy-db was corrupted while copying from tmp directory to cache directory. We should update this trivy-db.
	// We can't detect these cases, so we will show warning for users who use oras + air-gapped.
	if meta.DownloadedAt.IsZero() && !skip {
		log.WarnContext(ctx, "Trivy DB may be corrupted and will be re-downloaded. If you manually downloaded DB - use the `--skip-db-update` flag to skip updating DB.")
		return true, nil
	}

	if db.SchemaVersion < meta.Version {
		log.ErrorContext(ctx, "Trivy version is old. Update to the latest version.", log.String("version", cliVersion))
		return false, xerrors.Errorf("the version of DB schema doesn't match. Local DB: %d, Expected: %d",
			meta.Version, db.SchemaVersion)
	}

	if skip {
		if err = c.validate(meta); err != nil {
			return false, xerrors.Errorf("validate error: %w", err)
		}

		log.DebugContext(ctx, "Skipping DB update...")
		return false, nil
	}

	if db.SchemaVersion != meta.Version {
		log.DebugContext(ctx, "The local DB schema version does not match with supported version schema.",
			log.Int("local_version", meta.Version), log.Int("supported_version", db.SchemaVersion))
		return true, nil
	}

	return !c.isNewDB(ctx, meta), nil
}

// store opens the versioned store rooted at the client's db directory. It
// returns ok=false when the store does not manage a database yet, in which case
// the legacy single-file logic applies. An empty versions directory (created
// merely by opening the store) does not count as managed.
func (c *Client) store() (*store.Store, bool) {
	if !hasVersionedLayout(c.dbDir) {
		return nil, false
	}
	s, err := OpenStore(filepath.Dir(c.dbDir), c.storeOptions)
	if err != nil {
		log.Debug("Failed to open versioned database store", log.Err(err))
		return nil, false
	}
	return s, true
}

// hasVersionedLayout reports whether at least one directory with a manifest
// exists under versions/.
func hasVersionedLayout(dbDir string) bool {
	entries, err := os.ReadDir(filepath.Join(dbDir, "versions"))
	if err != nil {
		return false
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if _, err := os.Stat(filepath.Join(dbDir, "versions", e.Name(), "manifest.json")); err == nil {
			return true
		}
	}
	return false
}

// needsUpdateFromStore implements NeedsUpdate for the versioned store.
func (c *Client) needsUpdateFromStore(ctx context.Context, st *store.Store, cliVersion string, skip bool) (bool, error) {
	m, err := st.Current()
	if err != nil {
		if skip {
			log.ErrorContext(ctx, "The first run cannot skip downloading DB")
			return false, xerrors.New("--skip-db-update cannot be specified without a verified database version")
		}
		log.DebugContext(ctx, "There is no usable database version", log.Err(err))
		return true, nil
	}

	// Verify the active version before deciding anything. A version that does
	// not verify is unusable, even with --skip-db-update.
	if _, _, release, err := st.OpenActive(ctx); err != nil {
		if skip {
			return false, xerrors.Errorf("local database version %q failed verification: %w", m.Version, err)
		}
		log.WarnContext(ctx, "The active database version failed integrity verification; it will be re-downloaded",
			log.String("version", m.Version), log.Err(err))
		return true, nil
	} else {
		release()
	}

	if db.SchemaVersion < m.SchemaVersion {
		log.ErrorContext(ctx, "Trivy version is old. Update to the latest version.", log.String("version", cliVersion))
		return false, xerrors.Errorf("the version of DB schema doesn't match. Local DB: %d, Expected: %d",
			m.SchemaVersion, db.SchemaVersion)
	}

	if skip {
		if db.SchemaVersion != m.SchemaVersion {
			log.Error("The local DB has an old schema version which is not supported by the current version of Trivy CLI. DB needs to be updated.")
			return false, xerrors.Errorf("--skip-db-update cannot be specified with the old DB schema. Local DB: %d, Expected: %d",
				m.SchemaVersion, db.SchemaVersion)
		}
		log.DebugContext(ctx, "Skipping DB update...")
		return false, nil
	}

	if db.SchemaVersion != m.SchemaVersion {
		log.DebugContext(ctx, "The local DB schema version does not match with supported version schema.",
			log.Int("local_version", m.SchemaVersion), log.Int("supported_version", db.SchemaVersion))
		return true, nil
	}

	now := clock.Now(ctx)
	if now.Before(m.NextUpdate) {
		log.Debug("DB update was skipped because the local DB is the latest")
		return false, nil
	}
	if now.Before(m.DownloadedAt.Add(time.Hour)) {
		log.Debug("DB update was skipped because the local DB was downloaded during the last hour")
		return false, nil
	}
	return true, nil
}

func (c *Client) validate(meta metadata.Metadata) error {
	if db.SchemaVersion != meta.Version {
		log.Error("The local DB has an old schema version which is not supported by the current version of Trivy CLI. DB needs to be updated.")
		return xerrors.Errorf("--skip-db-update cannot be specified with the old DB schema. Local DB: %d, Expected: %d",
			meta.Version, db.SchemaVersion)
	}
	return nil
}

func (c *Client) isNewDB(ctx context.Context, meta metadata.Metadata) bool {
	now := clock.Now(ctx)
	if now.Before(meta.NextUpdate) {
		log.Debug("DB update was skipped because the local DB is the latest")
		return true
	}

	if now.Before(meta.DownloadedAt.Add(time.Hour)) {
		log.Debug("DB update was skipped because the local DB was downloaded during the last hour")
		return true
	}
	return false
}

// Download downloads the DB file into dst.
//
// When dst is the store root, the download is staged in a temporary directory
// and installed atomically, so an interrupted transfer never touches the
// active version. Callers that pass an unrelated temporary directory (for
// example the server's hot-update worker) get the raw download and decide
// themselves when to install it.
func (c *Client) Download(ctx context.Context, dst string, opt types.RegistryOptions) error {
	install := filepath.Clean(dst) == filepath.Clean(c.dbDir)
	if !install {
		if err := c.downloadDB(ctx, opt, dst); err != nil {
			return xerrors.Errorf("OCI artifact error: %w", err)
		}
		if err := c.updateDownloadedAt(ctx, dst); err != nil {
			return xerrors.Errorf("failed to update downloaded_at: %w", err)
		}
		return nil
	}

	s, err := OpenStore(filepath.Dir(c.dbDir), DefaultStoreOptions())
	if err != nil {
		return err
	}
	staging, err := s.StagingDir("download")
	if err != nil {
		return err
	}
	defer os.RemoveAll(staging) //nolint: errcheck

	if err = c.downloadDB(ctx, opt, staging); err != nil {
		return xerrors.Errorf("OCI artifact error: %w", err)
	}
	if err = c.updateDownloadedAt(ctx, staging); err != nil {
		return xerrors.Errorf("failed to update downloaded_at: %w", err)
	}

	m, err := s.InstallFromStaging(ctx, staging, store.InstallOptions{
		Origin: "download",
		Now:    clock.Now(ctx).UTC(),
	})
	if err != nil {
		return xerrors.Errorf("failed to install vulnerability DB: %w", err)
	}
	if err = s.Activate(ctx, m.Version); err != nil {
		return xerrors.Errorf("failed to activate vulnerability DB: %w", err)
	}
	if err = mirrorMetadata(filepath.Join(c.dbDir, "versions", m.Version), c.dbDir); err != nil {
		return err
	}
	log.InfoContext(ctx, "Installed vulnerability database version", log.String("version", m.Version))
	return nil
}

func (c *Client) Clear(ctx context.Context) error {
	if st, ok := c.store(); ok {
		if err := st.Clean(ctx); err != nil {
			return xerrors.Errorf("failed to remove vulnerability database: %w", err)
		}
	}
	if err := os.RemoveAll(c.dbDir); err != nil {
		return xerrors.Errorf("failed to remove vulnerability database: %w", err)
	}
	return nil
}

func (c *Client) updateDownloadedAt(ctx context.Context, dbDir string) error {
	log.Debug("Updating database metadata...")

	// We have to initialize a metadata client here
	// since the destination may be different from the cache directory.
	client := metadata.NewClient(dbDir)
	meta, err := client.Get()
	if err != nil {
		return xerrors.Errorf("unable to get metadata: %w", err)
	}

	meta.DownloadedAt = clock.Now(ctx).UTC()
	if err = client.Update(meta); err != nil {
		return xerrors.Errorf("failed to update metadata: %w", err)
	}

	return nil
}

func (c *Client) initArtifacts(opt types.RegistryOptions) oci.Artifacts {
	if c.artifact != nil {
		return oci.Artifacts{c.artifact}
	}
	return oci.NewArtifacts(c.dbRepositories, opt)
}

func (c *Client) downloadDB(ctx context.Context, opt types.RegistryOptions, dst string) error {
	log.InfoContext(ctx, "Downloading vulnerability DB...")
	downloadOpt := oci.DownloadOption{
		MediaType: dbMediaType,
		Quiet:     c.quiet,
	}
	if err := c.initArtifacts(opt).Download(ctx, dst, downloadOpt); err != nil {
		return xerrors.Errorf("failed to download vulnerability DB: %w", err)
	}
	return nil
}

func (c *Client) ShowInfo() error {
	if st, ok := c.store(); ok {
		m, err := st.Current()
		if err == nil {
			log.Debug("DB info", log.String("version", m.Version), log.Int("schema", m.SchemaVersion),
				log.Time("updated_at", m.UpdatedAt), log.Time("next_update", m.NextUpdate),
				log.Time("downloaded_at", m.DownloadedAt))
			return nil
		}
	}
	meta, err := c.metadata.Get()
	if err != nil {
		return xerrors.Errorf("something wrong with DB: %w", err)
	}
	log.Debug("DB info", log.Int("schema", meta.Version), log.Time("updated_at", meta.UpdatedAt),
		log.Time("next_update", meta.NextUpdate), log.Time("downloaded_at", meta.DownloadedAt))
	return nil
}
