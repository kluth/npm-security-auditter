package project

import (
	"encoding/json"
	"os"
	"strings"
)

// PackageJSON represents a standard package.json file containing project metadata and dependencies.
type PackageJSON struct {
	// Name is the name of the project.
	Name string `json:"name"`
	// Version is the version of the project.
	Version string `json:"version"`
	// Dependencies are the packages required for production.
	Dependencies map[string]string `json:"dependencies"`
	// DevDependencies are the packages required for development and testing.
	DevDependencies map[string]string `json:"devDependencies"`
}

// PackageLock represents a package-lock.json file, supporting multiple lockfile versions.
type PackageLock struct {
	// Name is the name of the project.
	Name string `json:"name"`
	// Version is the version of the project.
	Version string `json:"version"`
	// LockfileVersion is the version of the lockfile format (1, 2, or 3).
	LockfileVersion int `json:"lockfileVersion"`
	// Packages contains dependency information for lockfile v3.
	Packages map[string]LockPackage `json:"packages"`
	// Dependencies contains dependency information for lockfile v1 and v2.
	Dependencies map[string]LegacyLockPackage `json:"dependencies"`
}

// LockPackage represents a single package entry in a modern package-lock.json file.
type LockPackage struct {
	// Version is the installed version of the package.
	Version string `json:"version"`
	// Resolved is the URL or location from which the package was retrieved.
	Resolved string `json:"resolved"`
	// Integrity is the subresource integrity string.
	Integrity string `json:"integrity"`
	// Dependencies maps dependency names to their version requirements.
	Dependencies map[string]string `json:"dependencies"`
}

// LegacyLockPackage represents a package entry in older package-lock.json formats.
type LegacyLockPackage struct {
	// Version is the installed version of the package.
	Version string `json:"version"`
	// Resolved is the URL or location from which the package was retrieved.
	Resolved string `json:"resolved"`
	// Integrity is the subresource integrity string.
	Integrity string `json:"integrity"`
	// Dependencies contains nested legacy lock package entries.
	Dependencies map[string]LegacyLockPackage `json:"dependencies"`
}

// Dependency represents a package and its version that needs to be audited.
type Dependency struct {
	// Name is the name of the package.
	Name string
	// Version is the specific version or version range of the package.
	Version string
}

// ParsePackageJSON reads and parses a package.json file.
func ParsePackageJSON(path string) ([]Dependency, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var pkg PackageJSON
	if err := json.Unmarshal(data, &pkg); err != nil {
		return nil, err
	}

	var deps []Dependency
	for name, ver := range pkg.Dependencies {
		deps = append(deps, Dependency{Name: name, Version: ver})
	}
	for name, ver := range pkg.DevDependencies {
		deps = append(deps, Dependency{Name: name, Version: ver})
	}

	return deps, nil
}

// ParsePackageLock reads and parses a package-lock.json file.
func ParsePackageLock(path string) ([]Dependency, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var lock PackageLock
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, err
	}

	var deps []Dependency
	// For lockfileVersion 3, we look at Packages
	if len(lock.Packages) > 0 {
		for name, pkg := range lock.Packages {
			if name == "" { // skip root
				continue
			}
			// name might be "node_modules/lodash"
			cleanName := name
			if strings.HasPrefix(name, "node_modules/") {
				cleanName = name[len("node_modules/"):]
			}
			if strings.Contains(cleanName, "node_modules/") {
				continue // skip nested node_modules
			}
			deps = append(deps, Dependency{Name: cleanName, Version: pkg.Version})
		}
	} else {
		// Fallback to legacy Dependencies
		for name, pkg := range lock.Dependencies {
			deps = append(deps, Dependency{Name: name, Version: pkg.Version})
		}
	}

	return deps, nil
}

// AuditNodeModules scans the node_modules directory for dependencies.
func AuditNodeModules(root string) ([]Dependency, error) {
	nodeModulesPath := strings.TrimSuffix(root, "/") + "/node_modules"
	entries, err := os.ReadDir(nodeModulesPath)
	if err != nil {
		return nil, err
	}

	var deps []Dependency
	for _, entry := range entries {
		if !entry.IsDir() || strings.HasPrefix(entry.Name(), ".") {
			continue
		}

		// Handle scoped packages
		if strings.HasPrefix(entry.Name(), "@") {
			scopedEntries, err := os.ReadDir(nodeModulesPath + "/" + entry.Name())
			if err == nil {
				for _, scopedEntry := range scopedEntries {
					if scopedEntry.IsDir() {
						deps = append(deps, Dependency{
							Name: entry.Name() + "/" + scopedEntry.Name(),
						})
					}
				}
			}
			continue
		}

		deps = append(deps, Dependency{Name: entry.Name()})
	}

	return deps, nil
}
