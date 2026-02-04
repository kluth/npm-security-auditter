package project

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParsePackageJSON(t *testing.T) {
	t.Run("valid package.json with dependencies", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "package.json")
		content := `{
			"name": "test-pkg",
			"version": "1.0.0",
			"dependencies": {
				"lodash": "^4.17.21",
				"express": "^4.18.2"
			},
			"devDependencies": {
				"jest": "^29.0.0"
			}
		}`
		os.WriteFile(path, []byte(content), 0o644)

		deps, err := ParsePackageJSON(path)
		if err != nil {
			t.Fatalf("ParsePackageJSON() error = %v", err)
		}

		if len(deps) != 3 {
			t.Errorf("expected 3 deps, got %d", len(deps))
		}

		found := map[string]bool{}
		for _, d := range deps {
			found[d.Name] = true
			if d.Name == "lodash" && d.Version != "^4.17.21" {
				t.Errorf("lodash version = %q, want %q", d.Version, "^4.17.21")
			}
		}
		if !found["lodash"] || !found["express"] || !found["jest"] {
			t.Error("expected lodash, express, and jest in deps")
		}
	})

	t.Run("empty package.json", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "package.json")
		os.WriteFile(path, []byte(`{}`), 0o644)

		deps, err := ParsePackageJSON(path)
		if err != nil {
			t.Fatalf("ParsePackageJSON() error = %v", err)
		}
		if len(deps) != 0 {
			t.Errorf("expected 0 deps, got %d", len(deps))
		}
	})

	t.Run("file not found", func(t *testing.T) {
		_, err := ParsePackageJSON("/nonexistent/package.json")
		if err == nil {
			t.Error("expected error for missing file")
		}
	})

	t.Run("invalid JSON", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "package.json")
		os.WriteFile(path, []byte(`{invalid`), 0o644)

		_, err := ParsePackageJSON(path)
		if err == nil {
			t.Error("expected error for invalid JSON")
		}
	})

	t.Run("only devDependencies", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "package.json")
		content := `{
			"name": "dev-only",
			"devDependencies": {
				"eslint": "^8.0.0"
			}
		}`
		os.WriteFile(path, []byte(content), 0o644)

		deps, err := ParsePackageJSON(path)
		if err != nil {
			t.Fatalf("ParsePackageJSON() error = %v", err)
		}
		if len(deps) != 1 {
			t.Errorf("expected 1 dep, got %d", len(deps))
		}
		if deps[0].Name != "eslint" {
			t.Errorf("expected eslint, got %s", deps[0].Name)
		}
	})
}

func TestParsePackageLock(t *testing.T) {
	t.Run("lockfile v3 with packages", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "package-lock.json")
		content := `{
			"name": "test-project",
			"version": "1.0.0",
			"lockfileVersion": 3,
			"packages": {
				"": {
					"name": "test-project",
					"version": "1.0.0"
				},
				"node_modules/lodash": {
					"version": "4.17.21",
					"resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"
				},
				"node_modules/express": {
					"version": "4.18.2",
					"resolved": "https://registry.npmjs.org/express/-/express-4.18.2.tgz"
				},
				"node_modules/express/node_modules/nested": {
					"version": "1.0.0"
				}
			}
		}`
		os.WriteFile(path, []byte(content), 0o644)

		deps, err := ParsePackageLock(path)
		if err != nil {
			t.Fatalf("ParsePackageLock() error = %v", err)
		}

		// Should skip root ("") and nested node_modules
		if len(deps) != 2 {
			t.Errorf("expected 2 deps, got %d: %+v", len(deps), deps)
		}

		found := map[string]bool{}
		for _, d := range deps {
			found[d.Name] = true
		}
		if !found["lodash"] || !found["express"] {
			t.Error("expected lodash and express in deps")
		}
	})

	t.Run("lockfile v1 with legacy dependencies", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "package-lock.json")
		content := `{
			"name": "test-project",
			"version": "1.0.0",
			"lockfileVersion": 1,
			"dependencies": {
				"axios": {
					"version": "1.4.0",
					"resolved": "https://registry.npmjs.org/axios/-/axios-1.4.0.tgz"
				}
			}
		}`
		os.WriteFile(path, []byte(content), 0o644)

		deps, err := ParsePackageLock(path)
		if err != nil {
			t.Fatalf("ParsePackageLock() error = %v", err)
		}

		if len(deps) != 1 {
			t.Errorf("expected 1 dep, got %d", len(deps))
		}
		if deps[0].Name != "axios" {
			t.Errorf("expected axios, got %s", deps[0].Name)
		}
		if deps[0].Version != "1.4.0" {
			t.Errorf("expected version 1.4.0, got %s", deps[0].Version)
		}
	})

	t.Run("packages without node_modules prefix", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "package-lock.json")
		content := `{
			"name": "test",
			"lockfileVersion": 3,
			"packages": {
				"": {},
				"some-dep": {
					"version": "1.0.0"
				}
			}
		}`
		os.WriteFile(path, []byte(content), 0o644)

		deps, err := ParsePackageLock(path)
		if err != nil {
			t.Fatalf("error = %v", err)
		}
		if len(deps) != 1 {
			t.Errorf("expected 1 dep, got %d", len(deps))
		}
	})

	t.Run("file not found", func(t *testing.T) {
		_, err := ParsePackageLock("/nonexistent/package-lock.json")
		if err == nil {
			t.Error("expected error for missing file")
		}
	})

	t.Run("invalid JSON", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "package-lock.json")
		os.WriteFile(path, []byte(`{invalid`), 0o644)

		_, err := ParsePackageLock(path)
		if err == nil {
			t.Error("expected error for invalid JSON")
		}
	})
}

func TestAuditNodeModules(t *testing.T) {
	t.Run("regular packages", func(t *testing.T) {
		dir := t.TempDir()
		nm := filepath.Join(dir, "node_modules")
		os.MkdirAll(filepath.Join(nm, "lodash"), 0o755)
		os.MkdirAll(filepath.Join(nm, "express"), 0o755)
		// Create a file (should be skipped)
		os.WriteFile(filepath.Join(nm, "readme.txt"), []byte("hi"), 0o644)
		// Create a hidden dir (should be skipped)
		os.MkdirAll(filepath.Join(nm, ".cache"), 0o755)

		deps, err := AuditNodeModules(dir)
		if err != nil {
			t.Fatalf("AuditNodeModules() error = %v", err)
		}

		if len(deps) != 2 {
			t.Errorf("expected 2 deps, got %d: %+v", len(deps), deps)
		}

		found := map[string]bool{}
		for _, d := range deps {
			found[d.Name] = true
		}
		if !found["lodash"] || !found["express"] {
			t.Error("expected lodash and express")
		}
	})

	t.Run("scoped packages", func(t *testing.T) {
		dir := t.TempDir()
		nm := filepath.Join(dir, "node_modules")
		os.MkdirAll(filepath.Join(nm, "@types", "node"), 0o755)
		os.MkdirAll(filepath.Join(nm, "@types", "react"), 0o755)
		os.MkdirAll(filepath.Join(nm, "lodash"), 0o755)

		deps, err := AuditNodeModules(dir)
		if err != nil {
			t.Fatalf("AuditNodeModules() error = %v", err)
		}

		if len(deps) != 3 {
			t.Errorf("expected 3 deps, got %d: %+v", len(deps), deps)
		}

		found := map[string]bool{}
		for _, d := range deps {
			found[d.Name] = true
		}
		if !found["@types/node"] || !found["@types/react"] {
			t.Errorf("expected scoped packages, got: %+v", deps)
		}
	})

	t.Run("no node_modules", func(t *testing.T) {
		dir := t.TempDir()
		_, err := AuditNodeModules(dir)
		if err == nil {
			t.Error("expected error when node_modules doesn't exist")
		}
	})

	t.Run("trailing slash in root", func(t *testing.T) {
		dir := t.TempDir()
		nm := filepath.Join(dir, "node_modules")
		os.MkdirAll(filepath.Join(nm, "pkg-a"), 0o755)

		deps, err := AuditNodeModules(dir + "/")
		if err != nil {
			t.Fatalf("AuditNodeModules() error = %v", err)
		}
		if len(deps) != 1 {
			t.Errorf("expected 1 dep, got %d", len(deps))
		}
	})
}
