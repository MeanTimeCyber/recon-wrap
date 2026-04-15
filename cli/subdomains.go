package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"sort"

	"log/slog"

	"github.com/projectdiscovery/subfinder/v2/pkg/runner"
)

func findSubdomains(domain string) ([]string, error) {
	slog.Info("finding subdomains", "domain", domain)

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

	for subdomain := range sourceMap {
		subdomains = append(subdomains, subdomain)
	}

	sort.Strings(subdomains)
	slog.Info("subdomain enumeration complete", "domain", domain, "count", len(subdomains))

	return subdomains, nil
}
