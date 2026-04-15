package main

import (
	"flag"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/asaskevich/govalidator"
)

func main() {
	// setup logging
	handler := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug})
	slog.SetDefault(slog.New(handler))

	// parse command line arguments, validate input
	inputDomain := flag.String("i", "", "Target domain (e.g. example.com)")
	disableLiveURLPrint := flag.Bool("quiet-httpx", false, "Disable live URL output while httpx is running")
	flag.Parse()

	if !isValidDomain(*inputDomain) {
		slog.Error("invalid domain", "input", *inputDomain, "hint", "use a valid hostname like example.com")
		os.Exit(1)
	}

	// start the enumeration process
	slog.Info("looking up domain", "domain", *inputDomain)

	// find subdomains
	subdomains, err := findSubdomains(*inputDomain)

	if err != nil {
		slog.Error("error finding subdomains", "error", err)
		os.Exit(1)
	}

	slog.Info("subdomain discovery complete", "count", len(subdomains))

	// add the root domain to the list of subdomains for website details lookup
	subdomains = append(subdomains, *inputDomain)

	// find website details for each subdomain
	details, err := getWebsiteDetails(subdomains, *disableLiveURLPrint, *inputDomain)

	if err != nil {
		slog.Error("error finding website details", "error", err)
		os.Exit(1)
	}

	reportPath := *inputDomain + "_websites-" + time.Now().UTC().Format("20060102-150405") + ".md"

	if err := writeWebsiteDetailsMarkdown(reportPath, details); err != nil {
		slog.Error("error writing markdown website details", "error", err)
		os.Exit(1)
	}

	slog.Info("markdown output written", "path", reportPath, "count", len(details))

	slog.Info("Fin.")
}

func isValidDomain(domain string) bool {
	domain = strings.TrimSpace(domain)
	if domain == "" {
		return false
	}

	// Require a registrable-style domain input like example.com.
	if !strings.Contains(domain, ".") {
		return false
	}

	return govalidator.IsDNSName(domain)
}
