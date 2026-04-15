package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"

	"log/slog"

	"github.com/projectdiscovery/subfinder/v2/pkg/runner"
)

// findSubdomains runs subfinder for a single domain, applying provider
// configuration when available, and returns a sorted unique subdomain list.
func findSubdomains(domain string) ([]string, error) {
	slog.Info("finding subdomains", "domain", domain)

	// Prefer user-level provider credentials when available.
	providerConfigPath, hasProviderConfig := findProviderConfigPath()

	// configure the options
	subfinderOpts := &runner.Options{
		Threads:            10, // Thread controls the number of threads to use for active enumerations
		Timeout:            30, // Timeout is the seconds to wait for sources to respond
		MaxEnumerationTime: 10, // MaxEnumerationTime is the maximum amount of time in mins to wait for enumeration
		Silent:             true,

		// ResultCallback: func(s *resolve.HostEntry) {
		// callback function executed after each unique subdomain is found
		// },
		// ProviderConfig: "your_provider_config.yaml",
		// and other config related options
	}

	if hasProviderConfig {
		// Only set provider config when we have a verified file path.
		subfinderOpts.ProviderConfig = providerConfigPath
	}

	subfinder, err := runner.NewRunner(subfinderOpts)

	if err != nil {
		slog.Error("failed to initialize subfinder runner", "error", err)
		return nil, err
	}

	output := &bytes.Buffer{}
	var sourceMap map[string]map[string]struct{}

	// To run subdomain enumeration on a single domain
	sourceMap, err = subfinder.EnumerateSingleDomainWithCtx(context.Background(), domain, []io.Writer{output})

	if err != nil {
		slog.Error("failed to enumerate subdomains", "domain", domain, "error", err)
		return nil, fmt.Errorf("failed to enumerate single domain: %v", err)
	}

	subdomains := make([]string, 0, len(sourceMap))

	// Flatten source map keys into a deterministic list.
	for subdomain := range sourceMap {
		subdomains = append(subdomains, subdomain)
	}

	sort.Strings(subdomains)
	slog.Info("subdomain enumeration complete", "domain", domain, "count", len(subdomains))

	return subdomains, nil
}

// findProviderConfigPath resolves and validates the default subfinder provider
// config file path and indicates whether it is safe to use.
func findProviderConfigPath() (string, bool) {
	// Resolve the default subfinder provider config path in the user's home directory.
	homeDir, err := os.UserHomeDir()
	if err != nil {
		slog.Warn("could not determine home directory for subfinder provider config", "error", err)
		return "", false
	}

	path := filepath.Join(homeDir, ".config", "subfinder", "provider-config.yaml")

	info, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// Missing provider credentials are non-fatal; run with passive sources only.
			slog.Warn("subfinder provider config not found, continuing without provider config", "path", path)
			return "", false
		}

		slog.Warn("failed to check subfinder provider config, continuing without provider config", "path", path, "error", err)
		return "", false
	}

	if info.IsDir() {
		// A directory at this path is a configuration error; ignore and continue.
		slog.Warn("subfinder provider config path is a directory, continuing without provider config", "path", path)
		return "", false
	}

	slog.Info("subfinder provider config found", "path", path)
	return path, true
}
