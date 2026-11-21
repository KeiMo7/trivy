package store

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/xerrors"
)

// DigestPrefix is the algorithm prefix used by all digests in this package.
const DigestPrefix = "sha256:"

// DigestFile returns the sha256 digest of a file as "sha256:<hex>".
func DigestFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", xerrors.Errorf("failed to open %s: %w", path, err)
	}
	defer f.Close()

	h := sha256.New()
	if _, err = io.Copy(h, f); err != nil {
		return "", xerrors.Errorf("failed to hash %s: %w", path, err)
	}
	return DigestPrefix + hex.EncodeToString(h.Sum(nil)), nil
}

// digestBytes returns the sha256 digest of b in the same format as DigestFile.
func digestBytes(b []byte) string {
	sum := sha256.Sum256(b)
	return DigestPrefix + hex.EncodeToString(sum[:])
}

// verifyFile checks that the file exists, has the expected size and digest.
// Any mismatch is reported as an integrity error; the caller must not use the
// file.
func verifyFile(path string, want File) error {
	st, err := os.Stat(path)
	if err != nil {
		return integrityError(want.Digest, "", "missing file %s in version: %v", want.Name, err)
	}
	if !st.Mode().IsRegular() {
		return integrityError(want.Digest, "", "file %s is not a regular file", want.Name)
	}
	if st.Size() != want.Size {
		return integrityError(want.Digest, "", "size mismatch for %s: expected %d bytes, got %d",
			want.Name, want.Size, st.Size())
	}
	got, err := DigestFile(path)
	if err != nil {
		return wrapKind(KindIntegrity, err, "failed to verify %s", want.Name)
	}
	if got != want.Digest {
		return integrityError(want.Digest, got, "digest mismatch for %s: expected %s, got %s",
			want.Name, want.Digest, got)
	}
	return nil
}

// verifyDir checks every file listed in the manifest under dir.
func verifyDir(dir string, m Manifest) error {
	for _, f := range m.Files {
		if err := verifyFile(filepath.Join(dir, f.Name), f); err != nil {
			return err
		}
	}
	return nil
}

// dirSize returns the total size of the regular files under dir.
func dirSize(dir string) (int64, error) {
	var total int64
	err := filepath.WalkDir(dir, func(_ string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.Type().IsRegular() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		total += info.Size()
		return nil
	})
	if err != nil {
		return 0, xerrors.Errorf("failed to walk %s: %w", dir, err)
	}
	return total, nil
}
