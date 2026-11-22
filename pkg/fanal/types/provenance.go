package types

// PackageProvenance is the origin layer of a package that was observed while
// the layers were merged.
//
// It is kept next to the merged package list rather than on Package itself so
// that the existing package attribution, and therefore the existing report
// output, stays unchanged. The identity fields mirror the package fields used
// to match a package back to its merged result.
type PackageProvenance struct {
	// Kind is "os" for OS packages and the language type for library packages.
	Kind string

	PkgID    string
	Name     string
	Version  string
	FilePath string
	// PkgPath is the language package path, as reported in vulnerabilities.
	PkgPath string

	// Layer is the layer that provided the effective package database entry.
	Layer Layer
}
