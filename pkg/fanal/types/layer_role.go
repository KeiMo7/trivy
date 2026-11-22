package types

// LayerRole is the semantic role of a container image layer.
//
// The role is decided while the image is inspected, from the image history and
// the base-image boundary detected at that time. It is intentionally not
// inferred from file paths later on: the same path can exist in more than one
// layer, and only the analysis has the information needed to tell which layer
// actually provided the effective file.
type LayerRole string

const (
	// LayerRoleBase is a layer that belongs to the base image.
	LayerRoleBase LayerRole = "base"

	// LayerRoleMiddle is a layer built on top of the base image that is not the
	// top-most layer.
	LayerRoleMiddle LayerRole = "middle"

	// LayerRoleApplication is the top-most layer of the image, where the
	// application is usually added.
	LayerRoleApplication LayerRole = "application"

	// LayerRoleUnknown is used when the role cannot be determined, e.g. for
	// artifacts that are not container images.
	LayerRoleUnknown LayerRole = "unknown"
)
