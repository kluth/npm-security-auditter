package registry

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestNewClient(t *testing.T) {
	tests := []struct {
		name        string
		registryURL string
		wantURL     string
	}{
		{
			name:        "default registry",
			registryURL: "",
			wantURL:     DefaultRegistry,
		},
		{
			name:        "custom registry",
			registryURL: "https://custom.registry.com",
			wantURL:     "https://custom.registry.com",
		},
		{
			name:        "trailing slash removed",
			registryURL: "https://custom.registry.com/",
			wantURL:     "https://custom.registry.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewClient(tt.registryURL)
			if c.registryURL != tt.wantURL {
				t.Errorf("NewClient().registryURL = %q, want %q", c.registryURL, tt.wantURL)
			}
		})
	}
}

func TestGetPackage(t *testing.T) {
	metadata := PackageMetadata{
		Name:        "test-package",
		Description: "A test package",
		DistTags:    map[string]string{"latest": "1.0.0"},
		Versions: map[string]PackageVersion{
			"1.0.0": {
				Name:    "test-package",
				Version: "1.0.0",
				Scripts: map[string]string{"test": "echo test"},
			},
		},
		Maintainers: []Maintainer{{Name: "testuser", Email: "test@example.com"}},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/test-package":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(metadata)
		case "/@scope/scoped-pkg":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(PackageMetadata{Name: "@scope/scoped-pkg"})
		case "/not-found":
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(`{"error": "Not found"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	client := NewClient(server.URL)

	tests := []struct {
		name    string
		pkg     string
		wantErr bool
		wantPkg string
	}{
		{
			name:    "existing package",
			pkg:     "test-package",
			wantErr: false,
			wantPkg: "test-package",
		},
		{
			name:    "scoped package",
			pkg:     "@scope/scoped-pkg",
			wantErr: false,
			wantPkg: "@scope/scoped-pkg",
		},
		{
			name:    "not found package",
			pkg:     "not-found",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			pkg, err := client.GetPackage(ctx, tt.pkg)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetPackage() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && pkg.Name != tt.wantPkg {
				t.Errorf("GetPackage().Name = %q, want %q", pkg.Name, tt.wantPkg)
			}
		})
	}
}

func TestGetDownloads(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/downloads/point/last-week/test-pkg" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(DownloadCount{
				Downloads: 50000,
				Package:   "test-pkg",
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	client := NewClient("")
	client.downloadsURL = server.URL

	ctx := context.Background()
	dl, err := client.GetDownloads(ctx, "test-pkg")
	if err != nil {
		t.Fatalf("GetDownloads() error = %v", err)
	}
	if dl.Downloads != 50000 {
		t.Errorf("GetDownloads().Downloads = %d, want 50000", dl.Downloads)
	}
}

func TestGetPackage_Errors(t *testing.T) {
	t.Run("Network Error", func(t *testing.T) {
		// Create a client with an invalid URL/closed port to trigger Do error
		client := NewClient("http://127.0.0.1:0") // port 0 usually invalid/closed
		_, err := client.GetPackage(context.Background(), "pkg")
		if err == nil {
			t.Error("expected network error")
		}
	})

	t.Run("JSON Decode Error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("invalid-json"))
		}))
		defer server.Close()

		client := NewClient(server.URL)
		_, err := client.GetPackage(context.Background(), "pkg")
		if err == nil {
			t.Error("expected json decoding error")
		}
	})

	t.Run("Status Error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer server.Close()

		client := NewClient(server.URL)
		_, err := client.GetPackage(context.Background(), "pkg")
		if err == nil {
			t.Error("expected status error")
		}
		if !time.Now().IsZero() && err != nil && err.Error() != "" {
			// just checking if we can access error
		}
	})
}

func TestGetDownloads_Errors(t *testing.T) {
	t.Run("Network Error", func(t *testing.T) {
		client := NewClient("")
		client.downloadsURL = "http://127.0.0.1:0"
		_, err := client.GetDownloads(context.Background(), "pkg")
		if err == nil {
			t.Error("expected network error")
		}
	})

	t.Run("Status Error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}))
		defer server.Close()

		client := NewClient("")
		client.downloadsURL = server.URL
		_, err := client.GetDownloads(context.Background(), "pkg")
		if err == nil {
			t.Error("expected status error")
		}
	})

	t.Run("JSON Decode Error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("invalid-json"))
		}))
		defer server.Close()

		client := NewClient("")
		client.downloadsURL = server.URL
		_, err := client.GetDownloads(context.Background(), "pkg")
		if err == nil {
			t.Error("expected json decoding error")
		}
	})
}
