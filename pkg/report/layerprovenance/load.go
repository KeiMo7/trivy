package layerprovenance

import (
	"bufio"
	"encoding/json"
	"errors"
	"io"
	"os"

	"golang.org/x/xerrors"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/types"
)

// Previous is a loaded previous provenance report.
type Previous struct {
	// Path is the path the report was read from, as given by the user.
	Path string

	// SchemaVersion is the report format version recorded in the header.
	SchemaVersion int

	// Report carries the artifact identity from the header.
	Report types.Report

	// Findings are the finding records, used for identity matching.
	Findings []Finding
}

// LoadPrevious reads a previous provenance report.
//
// A missing, corrupt or incompatible report is an error that names the path
// and says what is wrong; it is never silently treated as "everything is new".
func LoadPrevious(path string) (*Previous, error) {
	if path == "" {
		return nil, nil
	}

	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, &types.UserError{Message: xerrors.Errorf(
				"previous report not found: %s; scan the previous image with --format layer-provenance first, "+
					"or drop --previous-report to see all findings as new", path).Error()}
		}
		return nil, &types.UserError{Message: xerrors.Errorf(
			"failed to open previous report %s: %w", path, err).Error()}
	}
	defer f.Close()

	prev := &Previous{Path: path}
	scanner := bufio.NewScanner(f)
	// Layer and finding records are small, but allow reasonably long lines.
	scanner.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)

	var (
		line     int
		headerOK bool
	)
	for scanner.Scan() {
		line++
		raw := scanner.Bytes()
		if len(raw) == 0 {
			continue
		}

		var meta struct {
			Type          string `json:"type"`
			SchemaVersion int    `json:"schemaVersion"`
		}
		if err := json.Unmarshal(raw, &meta); err != nil {
			return nil, &types.UserError{Message: xerrors.Errorf(
				"previous report %s is corrupt: line %d is not valid JSON: %w", path, line, err).Error()}
		}

		switch meta.Type {
		case RecordTypeHeader:
			if meta.SchemaVersion != SchemaVersion {
				return nil, &types.UserError{Message: xerrors.Errorf(
					"previous report %s is incompatible: format version %d was found, but this version of Trivy "+
						"writes and reads version %d; regenerate the previous report with the same Trivy version",
					path, meta.SchemaVersion, SchemaVersion).Error()}
			}
			var h Header
			if err := json.Unmarshal(raw, &h); err != nil {
				return nil, &types.UserError{Message: xerrors.Errorf(
					"previous report %s is corrupt: the header (line %d) cannot be read: %w", path, line, err).Error()}
			}
			prev.SchemaVersion = h.SchemaVersion
			prev.Report.ArtifactName = h.Artifact.Name
			prev.Report.ArtifactType = ftypes.ArtifactType(h.Artifact.Type)
			prev.Report.ArtifactID = h.Artifact.ID
			headerOK = true
		case RecordTypeFinding:
			var f Finding
			if err := json.Unmarshal(raw, &f); err != nil {
				return nil, &types.UserError{Message: xerrors.Errorf(
					"previous report %s is corrupt: finding on line %d cannot be read: %w", path, line, err).Error()}
			}
			if f.Identity == "" {
				return nil, &types.UserError{Message: xerrors.Errorf(
					"previous report %s is corrupt: finding on line %d has no identity", path, line).Error()}
			}
			// A report may itself be a diff. Its "removed" records describe
			// findings that were absent from that scan, so they must not be
			// treated as findings present in it when it is used as a baseline.
			if f.Status == StatusRemoved {
				continue
			}
			prev.Findings = append(prev.Findings, f)
		}
	}
	if err := scanner.Err(); err != nil && !errors.Is(err, io.EOF) {
		return nil, &types.UserError{Message: xerrors.Errorf(
			"previous report %s could not be read: %w", path, err).Error()}
	}

	if !headerOK {
		return nil, &types.UserError{Message: xerrors.Errorf(
			"previous report %s is incomplete: it has no %q record, so its format version and artifact are unknown; "+
				"regenerate it with --format layer-provenance", path, RecordTypeHeader).Error()}
	}
	return prev, nil
}
