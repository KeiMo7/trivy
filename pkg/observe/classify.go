package observe

import (
	"errors"
	"io/fs"
	"strings"

	"github.com/samber/lo"
)

// keyword-based classification. Trivy talks to several external daemons and
// registries whose concrete error types are not part of a shared interface, so
// message matching on the wrapped error text is the pragmatic common
// denominator. Matching is intentionally narrow to avoid mislabeling.
var (
	networkKeywords = []string{
		"no such host",
		"connection refused",
		"connection reset",
		"network is unreachable",
		"i/o timeout",
		"tls handshake timeout",
		"dial tcp",
		"temporarily unavailable",
	}

	authKeywords = []string{
		"unauthorized",
		"forbidden",
		"authentication required",
		"401",
		"403",
		"denied",
		"invalid credentials",
	}

	dependencyKeywords = []string{
		"docker daemon",
		"podman daemon",
		"cannot connect to the docker daemon",
		"no such file or directory", // e.g. missing daemon socket
		"executable file not found",
		"unable to find the specified image",
		"not installed",
		"unsupported version",
		"version too old",
	}

	resourceKeywords = []string{
		"no space left on device",
		"out of memory",
		"exceeds maximum allowed size",
		"too many open files",
		"disk quota exceeded",
	}

	validationKeywords = []string{
		"unknown format",
		"invalid image name",
		"failed to parse the image name",
		"no image sources supplied",
		"unknown target kind",
	}
)

func messageOf(err error) string {
	return strings.ToLower(err.Error())
}

func containsAny(msg string, keywords []string) bool {
	return lo.SomeBy(keywords, func(k string) bool {
		return strings.Contains(msg, k)
	})
}

func isNetworkError(err error) bool {
	return containsAny(messageOf(err), networkKeywords)
}

func isAuthError(err error) bool {
	return containsAny(messageOf(err), authKeywords)
}

func isDependencyError(err error) bool {
	return containsAny(messageOf(err), dependencyKeywords)
}

func isResourceError(err error) bool {
	if errors.Is(err, fs.ErrPermission) && strings.Contains(messageOf(err), "temp") {
		return true
	}
	return containsAny(messageOf(err), resourceKeywords)
}

func isValidationError(err error) bool {
	return containsAny(messageOf(err), validationKeywords)
}
