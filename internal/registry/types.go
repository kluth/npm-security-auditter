package registry

import (
	"encoding/json"
	"time"
)

// PackageMetadata represents the full metadata for an npm package.
type PackageMetadata struct {
	Name        string                    `json:"name"`
	Description string                    `json:"description"`
	DistTags    map[string]string         `json:"dist-tags"`
	Versions    map[string]PackageVersion `json:"versions"`
	Time        map[string]time.Time      `json:"time"`
	Maintainers []Maintainer              `json:"maintainers"`
	Repository  *Repository               `json:"repository,omitempty"`
	License     string                    `json:"license"`
	Readme      string                    `json:"readme"`
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

// PackageVersion represents a specific version of a package.
type PackageVersion struct {
	Name             string            `json:"name"`
	Version          string            `json:"version"`
	Description      string            `json:"description"`
	Main             string            `json:"main"`
	Scripts          map[string]string `json:"scripts"`
	Dependencies     map[string]string `json:"dependencies"`
	DevDependencies  map[string]string `json:"devDependencies"`
	Dist             Dist              `json:"dist"`
	Maintainers      []Maintainer      `json:"maintainers"`
	Repository       *Repository       `json:"repository,omitempty"`
	License          string            `json:"license"`
	Homepage         string            `json:"homepage,omitempty"`
	Deprecated       Deprecated        `json:"deprecated,omitempty"`
	HasInstallScript bool              `json:"hasInstallScript,omitempty"`
	Binary           interface{}       `json:"binary,omitempty"`
	GypFile          bool              `json:"gypfile,omitempty"`
}

// Dist contains distribution info for a package version.
type Dist struct {
	Tarball      string        `json:"tarball"`
	Shasum       string        `json:"shasum"`
	Integrity    string        `json:"integrity"`
	Signatures   []Signature   `json:"signatures,omitempty"`
	Attestations *Attestations `json:"attestations,omitempty"`
}

// Signature represents a dist signature.
type Signature struct {
	Keyid string `json:"keyid"`
	Sig   string `json:"sig"`
}

// Attestations represents provenance attestations.
type Attestations struct {
	URL        string      `json:"url"`
	Provenance *Provenance `json:"provenance,omitempty"`
}

// Provenance represents build provenance info.
type Provenance struct {
	PredicateType string `json:"predicateType"`
}

// Maintainer represents an npm maintainer.
type Maintainer struct {
	Name  string `json:"name"`
	Email string `json:"email"`
}

// Repository represents a source repository.
type Repository struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

// DownloadCount represents npm download stats.
type DownloadCount struct {
	Downloads int    `json:"downloads"`
	Start     string `json:"start"`
	End       string `json:"end"`
	Package   string `json:"package"`
}
