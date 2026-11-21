package store

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/xerrors"
)

// Archive layout (a gzip-compressed tar):
//
//	manifest.json          the version manifest (digests, sizes, schema)
//	trivy.db               the database file
//	metadata.json          optional trivy-db metadata
//
// The manifest is written first but is only trusted after every payload entry
// has been verified against it, so a truncated archive is rejected as a whole.
const archiveManifestName = "manifest.json"

// PackVersion writes a portable archive of an installed version to w. The
// archive carries the manifest so that ImportArchive can verify the payload
// byte for byte before installing it.
func (s *Store) PackVersion(version string, w io.Writer) error {
	m, err := s.Manifest(version)
	if err != nil {
		return err
	}
	dir := s.versionDir(version)
	if err = verifyDir(dir, m); err != nil {
		return wrapKind(KindIntegrity, err, "version %q failed verification before packaging", version)
	}

	gw := gzip.NewWriter(w)
	tw := tar.NewWriter(gw)

	mb, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return xerrors.Errorf("failed to encode manifest: %w", err)
	}
	if err = writeTarEntry(tw, archiveManifestName, mb, m.CreatedAt); err != nil {
		return err
	}
	for _, f := range m.Files {
		if err = copyToTar(tw, filepath.Join(dir, f.Name), f.Name, f.Size); err != nil {
			return err
		}
	}
	if err = tw.Close(); err != nil {
		return xerrors.Errorf("failed to finalize archive: %w", err)
	}
	if err = gw.Close(); err != nil {
		return xerrors.Errorf("failed to finalize archive: %w", err)
	}
	return nil
}

// ImportArchive installs a version from a portable archive produced by
// PackVersion. The payload is verified against the embedded manifest and
// installed atomically; a truncated or tampered archive is refused.
func (s *Store) ImportArchive(ctx context.Context, r io.Reader, origin string) (Manifest, error) {
	staging, err := s.StagingDir("import")
	if err != nil {
		return Manifest{}, err
	}
	defer os.RemoveAll(staging) //nolint: errcheck

	m, err := unpackArchive(r, staging)
	if err != nil {
		return Manifest{}, err
	}
	if origin != "" {
		m.Origin = origin
	}
	if m.Origin == "" {
		m.Origin = "import"
	}
	if m.CreatedAt.IsZero() {
		m.CreatedAt = time.Now()
	}

	// Only the final move is serialised against readers.
	unlock, err := s.acquireExclusive(ctx)
	if err != nil {
		return Manifest{}, err
	}
	defer unlock()
	if err = installStaged(s.root, staging, m); err != nil {
		return Manifest{}, err
	}
	return m, nil
}

func writeTarEntry(tw *tar.Writer, name string, data []byte, modTime time.Time) error {
	hdr := &tar.Header{
		Name:     name,
		Mode:     0o600,
		Size:     int64(len(data)),
		ModTime:  modTime,
		Typeflag: tar.TypeReg,
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return xerrors.Errorf("failed to write archive header: %w", err)
	}
	if _, err := tw.Write(data); err != nil {
		return xerrors.Errorf("failed to write archive entry: %w", err)
	}
	return nil
}

func copyToTar(tw *tar.Writer, path, name string, size int64) error {
	f, err := os.Open(path)
	if err != nil {
		return xerrors.Errorf("failed to open %s: %w", name, err)
	}
	defer f.Close()

	hdr := &tar.Header{
		Name:     name,
		Mode:     0o600,
		Size:     size,
		Typeflag: tar.TypeReg,
	}
	if err = tw.WriteHeader(hdr); err != nil {
		return xerrors.Errorf("failed to write archive header: %w", err)
	}
	n, err := io.Copy(tw, f)
	if err != nil {
		return xerrors.Errorf("failed to write archive entry %s: %w", name, err)
	}
	if n != size {
		return integrityError("", "", "file %s changed while packaging", name)
	}
	return nil
}

func unpackArchive(r io.Reader, dst string) (Manifest, error) {
	gr, err := gzip.NewReader(r)
	if err != nil {
		return Manifest{}, wrapKind(KindInvalid, err, "not a gzip-compressed database archive")
	}
	defer gr.Close()
	tr := tar.NewReader(gr)

	var m Manifest
	var seen bool
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return Manifest{}, wrapKind(KindInterrupted, err, "database archive is truncated or corrupt")
		}
		if hdr.Typeflag != tar.TypeReg {
			return Manifest{}, invalid("unexpected archive entry %q", hdr.Name)
		}
		if filepath.Base(hdr.Name) != hdr.Name || hdr.Name == "." || hdr.Name == ".." {
			return Manifest{}, invalid("unsafe archive entry %q", hdr.Name)
		}

		if hdr.Name == archiveManifestName {
			b, err := io.ReadAll(tr)
			if err != nil {
				return Manifest{}, wrapKind(KindInterrupted, err, "failed to read archive manifest")
			}
			if err = json.Unmarshal(b, &m); err != nil {
				return Manifest{}, wrapKind(KindIntegrity, err, "archive manifest is corrupt")
			}
			if err = m.validate(); err != nil {
				return Manifest{}, err
			}
			seen = true
			continue
		}
		if !seen {
			return Manifest{}, invalid("archive is missing its manifest")
		}
		if err = writeEntry(tr, filepath.Join(dst, hdr.Name)); err != nil {
			return Manifest{}, err
		}
	}
	if !seen {
		return Manifest{}, invalid("archive is missing its manifest")
	}
	if err = verifyDir(dst, m); err != nil {
		return Manifest{}, wrapKind(KindIntegrity, err, "archive payload failed verification")
	}
	if err = writeManifest(dst, m); err != nil {
		return Manifest{}, err
	}
	return m, nil
}

func writeEntry(r io.Reader, path string) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return xerrors.Errorf("failed to create %s: %w", path, err)
	}
	if _, err = io.Copy(f, r); err != nil {
		_ = f.Close()
		return wrapKind(KindInterrupted, err, "failed to extract %s", filepath.Base(path))
	}
	if err = f.Sync(); err != nil {
		_ = f.Close()
		return xerrors.Errorf("failed to sync %s: %w", path, err)
	}
	return f.Close()
}
