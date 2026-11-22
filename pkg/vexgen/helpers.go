package vexgen

import (
	"os"
	"path/filepath"

	v1 "github.com/google/go-containerregistry/pkg/v1"
)

// writeFileReadOnly writes the document with fixed permissions and no temp
// artifacts outside the requested path.
func writeFileReadOnly(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

// v1Config builds the minimal image config needed for OCI PURL construction.
func v1Config(arch string) v1.ConfigFile {
	if arch == "" {
		arch = "amd64"
	}
	return v1.ConfigFile{Architecture: arch}
}
