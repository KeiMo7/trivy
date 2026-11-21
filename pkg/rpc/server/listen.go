package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/NYTimes/gziphandler"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/twitchtv/twirp"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/cache"
	"github.com/aquasecurity/trivy/pkg/db"
	storepkg "github.com/aquasecurity/trivy/pkg/db/store"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/version"
	rpcCache "github.com/aquasecurity/trivy/rpc/cache"
	rpcScanner "github.com/aquasecurity/trivy/rpc/scanner"
)

const updateInterval = 1 * time.Hour

// Server represents Trivy server
type Server struct {
	appVersion     string
	addr           string
	cacheDir       string
	dbDir          string
	token          string
	tokenHeader    string
	pathPrefix     string
	dbRepositories []name.Reference

	// For OCI registries
	types.RegistryOptions
}

// NewServer returns an instance of Server
func NewServer(appVersion, addr, cacheDir, token, tokenHeader, pathPrefix string, dbRepositories []name.Reference, opt types.RegistryOptions) Server {
	return Server{
		appVersion:      appVersion,
		addr:            addr,
		cacheDir:        cacheDir,
		dbDir:           db.Dir(cacheDir),
		token:           token,
		tokenHeader:     tokenHeader,
		pathPrefix:      pathPrefix,
		dbRepositories:  dbRepositories,
		RegistryOptions: opt,
	}
}

// ListenAndServe starts Trivy server
func (s Server) ListenAndServe(ctx context.Context, serverCache cache.Cache, skipDBUpdate bool) error {
	requestWg := &sync.WaitGroup{}
	dbUpdateWg := &sync.WaitGroup{}

	server := &http.Server{
		Addr:              s.addr,
		Handler:           s.NewServeMux(ctx, serverCache, dbUpdateWg, requestWg),
		ReadHeaderTimeout: 10 * time.Second,
	}

	// Start DB update worker
	go func() {
		worker := newDBWorker(db.NewClient(s.dbDir, true, db.WithDBRepository(s.dbRepositories)))
		ticker := time.NewTicker(updateInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				log.Debug("Server shutting down gracefully...")

				// Give active requests time to complete
				shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				if err := server.Shutdown(shutdownCtx); err != nil {
					log.Errorf("Server shutdown error: %v", err)
				}
				cancel()
				return
			case <-ticker.C:
				if err := worker.update(ctx, s.appVersion, s.cacheDir, s.dbDir, skipDBUpdate, dbUpdateWg, requestWg, s.RegistryOptions); err != nil {
					log.Errorf("%+v\n", err)
				}
			}
		}
	}()

	log.Infof("Listening %s...", s.addr)

	// This will block until Shutdown is called
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return xerrors.Errorf("server error: %w", err)
	}

	return nil
}

func (s Server) NewServeMux(ctx context.Context, serverCache cache.Cache, dbUpdateWg, requestWg *sync.WaitGroup) *http.ServeMux {
	withWaitGroup := func(base http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Stop processing requests during DB update
			dbUpdateWg.Wait()

			// Wait for all requests to be processed before DB update
			requestWg.Add(1)
			defer requestWg.Done()

			base.ServeHTTP(w, r.WithContext(ctx))

		})
	}

	mux := http.NewServeMux()

	var twirpOpts []any
	if s.pathPrefix != "" {
		pathPrefix := "/" + strings.TrimPrefix(s.pathPrefix, "/") // Twirp requires the leading slash
		twirpOpts = append(twirpOpts, twirp.WithServerPathPrefix(pathPrefix))
	}

	scanServer := rpcScanner.NewScannerServer(initializeScanServer(serverCache), twirpOpts...)
	scanHandler := withToken(withWaitGroup(scanServer), s.token, s.tokenHeader)
	mux.Handle(scanServer.PathPrefix(), gziphandler.GzipHandler(scanHandler))

	cacheServer := rpcCache.NewCacheServer(NewCacheServer(serverCache), twirpOpts...)
	layerHandler := withToken(withWaitGroup(cacheServer), s.token, s.tokenHeader)
	mux.Handle(cacheServer.PathPrefix(), gziphandler.GzipHandler(layerHandler))

	mux.HandleFunc("/healthz", func(rw http.ResponseWriter, _ *http.Request) {
		if _, err := rw.Write([]byte("ok")); err != nil {
			log.Error("Health check error", log.Err(err))
		}
	})

	mux.HandleFunc("/version", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Add("Content-Type", "application/json")

		if err := json.NewEncoder(w).Encode(version.NewVersionInfo(s.cacheDir, version.Server())); err != nil {
			log.Error("Version error", log.Err(err))
		}
	})

	return mux
}

func withToken(base http.Handler, token, tokenHeader string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if token != "" && token != r.Header.Get(tokenHeader) {
			rpcScanner.WriteError(w, twirp.NewError(twirp.Unauthenticated, "invalid token"))
			return
		}
		base.ServeHTTP(w, r)
	})
}

type dbWorker struct {
	dbClient *db.Client
}

func newDBWorker(dbClient *db.Client) dbWorker {
	return dbWorker{dbClient: dbClient}
}

func (w dbWorker) update(ctx context.Context, appVersion, cacheDir, dbDir string,
	skipDBUpdate bool, dbUpdateWg, requestWg *sync.WaitGroup, opt types.RegistryOptions) error {
	log.Debug("Check for DB update...")
	needsUpdate, err := w.dbClient.NeedsUpdate(ctx, appVersion, skipDBUpdate)
	if err != nil {
		return xerrors.Errorf("failed to check if db needs an update")
	} else if !needsUpdate {
		return nil
	}

	log.Info("Updating DB...")
	if err = w.hotUpdate(ctx, cacheDir, dbDir, dbUpdateWg, requestWg, opt); err != nil {
		return xerrors.Errorf("failed DB hot update: %w", err)
	}
	return nil
}

func (w dbWorker) hotUpdate(ctx context.Context, cacheDir, dbDir string, dbUpdateWg, requestWg *sync.WaitGroup, opt types.RegistryOptions) error {
	dbStore, err := db.OpenStore(cacheDir, db.DefaultStoreOptions())
	if err != nil {
		return xerrors.Errorf("failed to open database store: %w", err)
	}

	// Download into the store's staging area so that installing the new
	// version is a rename on the same filesystem, not a second copy.
	tmpDir, err := dbStore.StagingDir("db-worker")
	if err != nil {
		return xerrors.Errorf("failed to create a staging dir: %w", err)
	}
	defer os.RemoveAll(tmpDir) //nolint: errcheck

	if err = w.dbClient.Download(ctx, tmpDir, opt); err != nil {
		return xerrors.Errorf("failed to download vulnerability DB: %w", err)
	}

	// Install and verify the new database before suspending any requests.
	// Until activation succeeds, in-flight scans keep reading the old version.
	m, err := dbStore.InstallFromStaging(ctx, tmpDir, storepkg.InstallOptions{Origin: "download"})
	if err != nil {
		return xerrors.Errorf("failed to install vulnerability DB: %w", err)
	}

	log.Info("Suspending all requests during DB update")
	dbUpdateWg.Add(1)
	defer dbUpdateWg.Done()

	log.Info("Waiting for all requests to be processed before DB update...")
	requestWg.Wait()

	if err = db.Close(); err != nil {
		return xerrors.Errorf("failed to close DB: %w", err)
	}

	// Swap the version atomically and reopen it. A failure here leaves the
	// previous version active and in place.
	if err = dbStore.Activate(ctx, m.Version); err != nil {
		return xerrors.Errorf("failed to activate the new database version: %w", err)
	}
	current, err := dbStore.Current()
	if err != nil {
		return xerrors.Errorf("failed to read the active database version: %w", err)
	}
	if err = db.MirrorMetadata(filepath.Join(dbDir, "versions", current.Version), dbDir); err != nil {
		return err
	}

	log.Info("Reopening DB...", log.String("version", current.Version))
	if err = db.Init(filepath.Join(dbDir, "versions", current.Version)); err != nil {
		return xerrors.Errorf("failed to open DB: %w", err)
	}

	return nil
}
