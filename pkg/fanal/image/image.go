package image

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/hashicorp/go-multierror"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
)

type imageSourceFunc func(ctx context.Context, imageName string, ref name.Reference, option types.ImageOptions) (types.Image, func(), error)

var imageSourceFuncs = map[types.ImageSource]imageSourceFunc{
	types.ContainerdImageSource: tryContainerdDaemon,
	types.PodmanImageSource:     tryPodmanDaemon,
	types.DockerImageSource:     tryDockerDaemon,
	types.RemoteImageSource:     tryRemote,
}

func NewContainerImage(ctx context.Context, imageName string, opt types.ImageOptions) (types.Image, func(), error) {
	ctx = log.WithContextPrefix(ctx, log.PrefixContainerImage)

	if len(opt.ImageSources) == 0 {
		return nil, func() {}, xerrors.New("no image sources supplied")
	}

	var errs error
	var nameOpts []name.Option
	if opt.RegistryOptions.Insecure {
		nameOpts = append(nameOpts, name.Insecure)
	}

	ref, err := name.ParseReference(imageName, nameOpts...)
	if err != nil {
		return nil, func() {}, xerrors.Errorf("failed to parse the image name: %w", err)
	}

	for _, src := range opt.ImageSources {
		trySrc, ok := imageSourceFuncs[src]
		if !ok {
			log.WarnContext(ctx, "Unknown image source", log.String("source", string(src)))
			continue
		}

		img, cleanup, err := trySrc(ctx, imageName, ref, opt)
		if err == nil {
			// Return v1.Image if the image is found
			log.DebugContext(ctx, "Image found", log.String("image", imageName), log.String("source", string(src)))
			return img, cleanup, nil
		}
		err = multierror.Prefix(err, fmt.Sprintf("%s error:", src))
		errs = multierror.Append(errs, err)
	}

	return nil, func() {}, xerrors.Errorf("unable to find the specified image %q in %q: %w", imageName, opt.ImageSources, errs)
}

func ID(img v1.Image) (string, error) {
	h, err := img.ConfigName()
	if err != nil {
		return "", xerrors.Errorf("unable to get the image ID: %w", err)
	}
	return h.String(), nil
}

func LayerIDs(img v1.Image) ([]string, error) {
	conf, err := img.ConfigFile()
	if err != nil {
		return nil, xerrors.Errorf("unable to get the config file: %w", err)
	}

	var layerIDs []string
	for _, d := range conf.RootFS.DiffIDs {
		layerIDs = append(layerIDs, d.String())
	}
	return layerIDs, nil
}

// GuessBaseImageIndex tries to guess index of base layer
//
// e.g. In the following example, we should detect layers in debian:8.
//
//	FROM debian:8
//	RUN apt-get update
//	COPY mysecret /
//	ENTRYPOINT ["entrypoint.sh"]
//	CMD ["somecmd"]
//
// debian:8 may be like
//
//	ADD file:5d673d25da3a14ce1f6cf66e4c7fd4f4b85a3759a9d93efb3fd9ff852b5b56e4 in /
//	CMD ["/bin/sh"]
//
// In total, it would be like:
//
//	ADD file:5d673d25da3a14ce1f6cf66e4c7fd4f4b85a3759a9d93efb3fd9ff852b5b56e4 in /
//	CMD ["/bin/sh"]              # empty layer (detected)
//	RUN apt-get update
//	COPY mysecret /
//	ENTRYPOINT ["entrypoint.sh"] # empty layer (skipped)
//	CMD ["somecmd"]              # empty layer (skipped)
//
// This method tries to detect CMD in the second line and assume the first line is a base layer.
//  1. Iterate histories from the bottom.
//  2. Skip all the empty layers at the bottom. In the above example, "entrypoint.sh" and "somecmd" will be skipped
//  3. If it finds CMD, it assumes that it is the end of base layers.
//  4. It gets all the layers as base layers above the CMD found in #3.
func GuessBaseImageIndex(histories []v1.History) int {
	baseImageIndex := -1
	var foundNonEmpty bool
	for i, h := range slices.Backward(histories) {
		// Skip the last CMD, ENTRYPOINT, etc.
		if !foundNonEmpty {
			if h.EmptyLayer {
				continue
			}
			foundNonEmpty = true
		}

		if !h.EmptyLayer {
			continue
		}

		// Detect CMD instruction in base image
		if strings.HasPrefix(h.CreatedBy, "/bin/sh -c #(nop)  CMD") ||
			strings.HasPrefix(h.CreatedBy, "CMD") { // BuildKit
			baseImageIndex = i
			break
		}
	}
	return baseImageIndex
}

// BaseDiffIDs returns the uncompressed layer IDs that belong to the base image.
//
// The boundary is guessed from the image history (see GuessBaseImageIndex) and
// mapped onto the diff IDs, which do not contain empty layers. The result is
// recorded while the image is analyzed so that later stages do not have to
// infer layer provenance from file paths. It returns nil when the boundary
// cannot be determined.
func BaseDiffIDs(diffIDs []string, histories []v1.History) []string {
	baseImageIndex := GuessBaseImageIndex(histories)

	// Diff IDs don't include empty layers, so the index is different from histories
	var diffIDIndex int
	var baseDiffIDs []string
	for i, h := range histories {
		// It is no longer base layer.
		if i > baseImageIndex {
			break
		}
		// Empty layers are not included in diff IDs.
		if h.EmptyLayer {
			continue
		}

		if diffIDIndex >= len(diffIDs) {
			// something wrong...
			return nil
		}
		baseDiffIDs = append(baseDiffIDs, diffIDs[diffIDIndex])
		diffIDIndex++
	}
	return baseDiffIDs
}

// ClassifyLayerRoles classifies image layers into base, middle and application
// roles. diffIDs are ordered from the bottom to the top of the image, matching
// the order of the layers in the report.
//
// Layers up to and including the detected base image boundary are base layers.
// The top-most layer is the application layer, and the layers in between are
// middle layers. When the boundary cannot be detected only the top-most layer
// is classified, as no layer can be safely attributed to the base image.
func ClassifyLayerRoles(diffIDs []string, histories []v1.History) []types.LayerRole {
	if len(diffIDs) == 0 {
		return nil
	}
	return classifyLayerRoles(diffIDs, BaseDiffIDs(diffIDs, histories))
}

func classifyLayerRoles(diffIDs, baseDiffIDs []string) []types.LayerRole {
	roles := make([]types.LayerRole, len(diffIDs))
	for i := range diffIDs {
		switch {
		case i < len(baseDiffIDs):
			// The detected base layers are always a prefix of the image.
			roles[i] = types.LayerRoleBase
		case i == len(diffIDs)-1:
			roles[i] = types.LayerRoleApplication
		default:
			roles[i] = types.LayerRoleMiddle
		}
	}
	return roles
}
