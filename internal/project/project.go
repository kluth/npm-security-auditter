package project

import (
	"encoding/json"
	"os"
	"strings"
)

// PackageJSON represents a standard package.json file.
type PackageJSON struct {
	Name            string            `json:"name"`
	Version         string            `json:"version"`
	Dependencies    map[string]string `json:"dependencies"`
	DevDependencies map[string]string `json:"devDependencies"`
}

// PackageLock represents a package-lock.json file.
type PackageLock struct {
	Name            string                      `json:"name"`
	Version         string                      `json:"version"`
	LockfileVersion int                         `json:"lockfileVersion"`
	Packages        map[string]LockPackage      `json:"packages"`        // For lockfileVersion 3
	Dependencies    map[string]LegacyLockPackage `json:"dependencies"` // For lockfileVersion 1, 2
}

type LockPackage struct {
	Version      string            `json:"version"`
	Resolved     string            `json:"resolved"`
	Integrity    string            `json:"integrity"`
	Dependencies map[string]string `json:"dependencies"`
}

type LegacyLockPackage struct {
	Version      string                        `json:"version"`
	Resolved     string                        `json:"resolved"`
	Integrity    string                        `json:"integrity"`
	Dependencies map[string]LegacyLockPackage `json:"dependencies"`
}

// Dependency represents a package and version to be audited.
type Dependency struct {
	Name    string
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