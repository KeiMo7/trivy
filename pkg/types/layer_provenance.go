package types

import ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"

// LayerProvenance holds layer attribution recorded while scanning.
//
// It is an internal representation and is not serialized by the existing
// report formats; a field holding it is therefore tagged `json:"-"`.
type LayerProvenance struct {
	// Roles is aligned by index with Report.Metadata.Layers.
	Roles []ftypes.LayerRole `json:"-"`
}
