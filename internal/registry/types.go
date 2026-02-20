package registry

import (
	"encoding/json"
	"time"
)

// PackageMetadata represents the full metadata for an npm package as returned by the registry.
type PackageMetadata struct {
	// Name is the name of the package.
	Name string `json:"name"`
	// Description is a short summary of the package's purpose.
	Description string `json:"description"`
	// DistTags maps tags (like "latest") to version strings.
	DistTags map[string]string `json:"dist-tags"`
	// Versions maps version strings to their respective metadata.
	Versions map[string]PackageVersion `json:"versions"`
	// Time contains timestamps for each version publish event.
	Time map[string]time.Time `json:"time"`
	// Maintainers is the list of people authorized to publish the package.
	Maintainers []Maintainer `json:"maintainers"`
	// Repository points to the source code repository.
	Repository *Repository `json:"repository,omitempty"`
	// License is the license under which the package is published.
	License string `json:"license"`
	// Readme is the content of the package's README file.
	Readme string `json:"readme"`
}

// Deprecated represents a deprecation message, which can be a string or a boolean in some registries.
type Deprecated string

// UnmarshalJSON handles both string and boolean values for the deprecated field.
func (d *Deprecated) UnmarshalJSON(b []byte) error {
	if len(b) > 0 && b[0] == '"' {
		var s string
		if err := json.Unmarshal(b, &s); err != nil {
			return err
		}
		*d = Deprecated(s)
		return nil
	}

	var boolean bool
	if err := json.Unmarshal(b, &boolean); err != nil {
		// If it's neither a string nor a bool, it might be null or something else.
		// We treat it as not deprecated.
		*d = ""
		return nil
	}

	if boolean {
		*d = "true"
	} else {
		*d = ""
	}
	return nil
}

// PackageVersion represents a specific version of a package and its manifest.
type PackageVersion struct {
	// Name is the name of the package.
	Name string `json:"name"`
	// Version is the specific version string.
	Version string `json:"version"`
	// Description is a short summary of the package version.
	Description string `json:"description"`
	// Main is the primary entry point file for the package.
	Main string `json:"main"`
	// Scripts contains lifecycle scripts (preinstall, install, etc.).
	Scripts map[string]string `json:"scripts"`
	// Dependencies are the packages required for production.
	Dependencies map[string]string `json:"dependencies"`
	// DevDependencies are the packages required for development and testing.
	DevDependencies map[string]string `json:"devDependencies"`
	// Dist contains distribution information like tarball URL and integrity.
	Dist Dist `json:"dist"`
	// Maintainers is the list of maintainers for this version.
	Maintainers []Maintainer `json:"maintainers"`
	// Repository points to the source code repository for this version.
	Repository *Repository `json:"repository,omitempty"`
	// License is the license for this version.
	License string `json:"license"`
	// Homepage is the URL to the package's homepage.
	Homepage string `json:"homepage,omitempty"`
	// Deprecated is the deprecation message, if any.
	Deprecated Deprecated `json:"deprecated,omitempty"`
	// HasInstallScript indicates if the package has an install-time script.
	HasInstallScript bool `json:"hasInstallScript,omitempty"`
	// Binary contains information about binary executables.
	Binary interface{} `json:"binary,omitempty"`
	// GypFile indicates if the package has a binding.gyp file.
	GypFile bool `json:"gypfile,omitempty"`
}

// Dist contains distribution info for a package version, including where to find the tarball.
type Dist struct {
	// Tarball is the URL to the package's tarball archive.
	Tarball string `json:"tarball"`
	// Shasum is the SHA1 checksum of the tarball.
	Shasum string `json:"shasum"`
	// Integrity is the subresource integrity string (e.g., sha512-...).
	Integrity string `json:"integrity"`
	// Signatures contains cryptographic signatures for the tarball.
	Signatures []Signature `json:"signatures,omitempty"`
	// Attestations contains build provenance attestations.
	Attestations *Attestations `json:"attestations,omitempty"`
}

// Signature represents a cryptographic signature for a package distribution.
type Signature struct {
	// Keyid is the ID of the key used for the signature.
	Keyid string `json:"keyid"`
	// Sig is the actual signature string.
	Sig string `json:"sig"`
}

// Attestations represents provenance and integrity attestations for the package.
type Attestations struct {
	// URL is the location where attestations can be retrieved.
	URL string `json:"url"`
	// Provenance contains SLSA build provenance information.
	Provenance *Provenance `json:"provenance,omitempty"`
}

// Provenance represents SLSA-style build provenance information.
type Provenance struct {
	// PredicateType identifies the type of SLSA predicate used.
	PredicateType string `json:"predicateType"`
}

// Maintainer represents an npm user authorized to maintain a package.
type Maintainer struct {
	// Name is the npm username.
	Name string `json:"name"`
	// Email is the maintainer's email address.
	Email string `json:"email"`
}

// Repository represents a source code repository location.
type Repository struct {
	// Type is the type of repository (e.g., "git").
	Type string `json:"type"`
	// URL is the location of the repository.
	URL string `json:"url"`
}

// DownloadCount represents weekly download statistics from the npm API.
type DownloadCount struct {
	// Downloads is the total number of downloads in the period.
	Downloads int `json:"downloads"`
	// Start is the start date of the period (YYYY-MM-DD).
	Start string `json:"start"`
	// End is the end date of the period (YYYY-MM-DD).
	End string `json:"end"`
	// Package is the name of the package.
	Package string `json:"package"`
}
