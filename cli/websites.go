package main

import (
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"

	customport "github.com/projectdiscovery/httpx/common/customports"
	"github.com/projectdiscovery/httpx/runner"
)

type WebsiteDetails struct {
	Input        string
	URL          string
	SNI          string
	Host         string
	HostIP       string
	ASN          string
	JarmHash     string
	StatusCode   int
	Error        string
	Port         string
	Title        string
	Location     string
	FinalURL     string
	WebServer    string
	ContentType  string
	ResponseTime string
	Technologies []string
	CPE          []string
	WordPress    string
	HTTP2        bool
	WebSocket    bool
	CDNName      string
	CNAMEs       []string
}

func getWebsiteDetails(subdomains []string, disableLiveURLPrint bool, sniName string) ([]WebsiteDetails, error) {
	slog.Info("Inspecting websites", "targets", len(subdomains))

	ports := customport.CustomPorts{}

	if err := ports.Set("80,81,88,3000,5000,7000,8000,8008,8080,8081,8088,8888,9000,9090,443,444,5443,6443,7443,8443,9443,10443"); err != nil {
		return nil, fmt.Errorf("invalid custom ports: %w", err)
	}

	slog.Info("first pass starting", "targets", len(subdomains), "ports", ports.String(), "quiet_httpx", disableLiveURLPrint)

	// First pass: quick checks across all targets/ports.
	resultsCh := make(chan WebsiteDetails)
	results := make([]WebsiteDetails, 0, len(subdomains))
	goodTargets := make([]string, 0, len(subdomains))
	goodTargetsSet := make(map[string]struct{})
	firstPassProcessed := 0
	done := make(chan struct{})

	go func() {
		defer close(done)
		for result := range resultsCh {
			results = append(results, result)
			firstPassProcessed++

			if firstPassProcessed%250 == 0 {
				slog.Info("first pass progress", "processed", firstPassProcessed, "good_targets", len(goodTargets))
			}

			target := targetKey(result)

			if isGoodStatusCode(result.StatusCode) && target != "" {
				if _, exists := goodTargetsSet[target]; !exists {
					goodTargetsSet[target] = struct{}{}
					goodTargets = append(goodTargets, target)
				}
			}
		}
	}()

	firstPassOptions := runner.Options{
		Methods:            "GET",
		InputTargetHost:    subdomains,
		Silent:             true,
		DisableStdout:      disableLiveURLPrint,
		CustomPorts:        ports,
		ExtractTitle:       true,
		Location:           true,
		StatusCode:         true,
		OutputServerHeader: true,
		OutputContentType:  true,
		OutputResponseTime: true,
		OutputIP:           true,
		OutputCName:        true,
		FollowRedirects:    true,
		OnResult: func(r runner.Result) {
			result := WebsiteDetails{
				Input:        r.Input,
				URL:          r.URL,
				Host:         r.Host,
				HostIP:       r.HostIP,
				StatusCode:   r.StatusCode,
				Port:         r.Port,
				Title:        r.Title,
				Location:     r.Location,
				FinalURL:     r.FinalURL,
				WebServer:    r.WebServer,
				ContentType:  r.ContentType,
				ResponseTime: r.ResponseTime,
				CNAMEs:       r.CNAMEs,
			}

			// handle error
			if r.Err != nil {
				result.Error = r.Err.Error()
			}

			resultsCh <- result
		},
	}

	if err := firstPassOptions.ValidateOptions(); err != nil {
		slog.Error("invalid first pass options", "error", err)
		return nil, fmt.Errorf("invalid options: %w", err)
	}

	firstPassRunner, err := runner.New(&firstPassOptions)

	if err != nil {
		return nil, fmt.Errorf("error running HTTPX first pass: %q", err.Error())
	}

	defer firstPassRunner.Close()

	slog.Info("first pass runner started")
	firstPassRunner.RunEnumeration()

	close(resultsCh)
	<-done

	slog.Info("first pass complete", "results", len(results), "second_pass_targets", len(goodTargets))

	if len(goodTargets) == 0 {
		slog.Info("second pass skipped", "reason", "no healthy targets from first pass")
		return results, nil
	}

	// Second pass: run expensive fingerprinting only for healthy responses.
	enrichedByTargetCh := make(chan WebsiteDetails)
	enrichedByTarget := make(map[string]WebsiteDetails, len(goodTargets))
	secondPassProcessed := 0
	doneEnriched := make(chan struct{})

	go func() {
		defer close(doneEnriched)
		for enriched := range enrichedByTargetCh {
			secondPassProcessed++

			target := targetKey(enriched)
			if target != "" {
				existing, exists := enrichedByTarget[target]
				if exists {
					enrichedByTarget[target] = mergeWebsiteDetails(existing, enriched)
				} else {
					enrichedByTarget[target] = enriched
				}
			}

			if secondPassProcessed%100 == 0 {
				slog.Info("second pass progress", "processed", secondPassProcessed, "enriched_targets", len(enrichedByTarget))
			}
		}
	}()

	secondPassOptions := runner.Options{
		Methods:            "GET",
		InputTargetHost:    goodTargets,
		Silent:             true,
		DisableStdout:      disableLiveURLPrint,
		ExtractTitle:       true,
		Location:           true,
		StatusCode:         true,
		OutputServerHeader: true,
		OutputContentType:  true,
		OutputResponseTime: true,
		OutputIP:           true,
		OutputCName:        true,
		FollowRedirects:    true,
		TechDetect:         true,
		CPEDetect:          true,
		WordPress:          true,
		TLSProbe:           true,
		HTTP2Probe:         true,
		Favicon:            true,
		Jarm:               true,
		Asn:                true,
		SniName:            sniName,
		OnResult: func(r runner.Result) {
			cpeValues := make([]string, 0, len(r.CPE))
			for _, cpe := range r.CPE {
				cpeValues = append(cpeValues, fmt.Sprint(cpe))
			}

			wordpress := ""
			if r.WordPress != nil {
				wordpress = fmt.Sprint(*r.WordPress)
			}

			enriched := WebsiteDetails{
				Input:        r.Input,
				URL:          r.URL,
				SNI:          r.SNI,
				Host:         r.Host,
				HostIP:       r.HostIP,
				JarmHash:     r.JarmHash,
				StatusCode:   r.StatusCode,
				Port:         r.Port,
				Title:        r.Title,
				Location:     r.Location,
				FinalURL:     r.FinalURL,
				WebServer:    r.WebServer,
				ContentType:  r.ContentType,
				ResponseTime: r.ResponseTime,
				Technologies: r.Technologies,
				CPE:          cpeValues,
				WordPress:    wordpress,
				HTTP2:        r.HTTP2,
				WebSocket:    r.WebSocket,
				CDNName:      r.CDNName,
				CNAMEs:       r.CNAMEs,
			}

			if r.ASN != nil {
				enriched.ASN = r.ASN.String()
			}

			if r.Err != nil {
				enriched.Error = r.Err.Error()
			}

			enrichedByTargetCh <- enriched
		},
	}

	if err := secondPassOptions.ValidateOptions(); err != nil {
		slog.Error("invalid second pass options", "error", err)
		return nil, fmt.Errorf("invalid options: %w", err)
	}

	secondPassRunner, err := runner.New(&secondPassOptions)
	if err != nil {
		return nil, fmt.Errorf("error running HTTPX second pass: %q", err.Error())
	}
	defer secondPassRunner.Close()

	slog.Info("second pass runner started", "targets", len(goodTargets))
	secondPassRunner.RunEnumeration()
	close(enrichedByTargetCh)
	<-doneEnriched

	slog.Info("merge phase starting", "base_results", len(results), "enriched_targets", len(enrichedByTarget))
	mergedResults := 0
	for i, result := range results {
		target := targetKey(result)

		enriched, ok := enrichedByTarget[target]
		if !ok {
			continue
		}

		results[i] = mergeWebsiteDetails(result, enriched)
		mergedResults++
	}

	slog.Info("second pass complete", "enriched_results", len(enrichedByTarget), "merged_results", mergedResults)

	return results, nil
}

func isGoodStatusCode(statusCode int) bool {
	if statusCode >= 200 && statusCode < 400 {
		return true
	}

	return statusCode == 401 || statusCode == 403
}

func mergeWebsiteDetails(base WebsiteDetails, enriched WebsiteDetails) WebsiteDetails {
	base.SNI = pickString(enriched.SNI, base.SNI)
	base.Host = pickString(enriched.Host, base.Host)
	base.HostIP = pickString(enriched.HostIP, base.HostIP)
	base.ASN = pickString(enriched.ASN, base.ASN)
	base.JarmHash = pickString(enriched.JarmHash, base.JarmHash)
	base.Title = pickString(enriched.Title, base.Title)
	base.Location = pickString(enriched.Location, base.Location)
	base.FinalURL = pickString(enriched.FinalURL, base.FinalURL)
	base.WebServer = pickString(enriched.WebServer, base.WebServer)
	base.ContentType = pickString(enriched.ContentType, base.ContentType)
	base.ResponseTime = pickString(enriched.ResponseTime, base.ResponseTime)
	base.WordPress = pickString(enriched.WordPress, base.WordPress)
	base.CDNName = pickString(enriched.CDNName, base.CDNName)

	if len(enriched.Technologies) > 0 {
		base.Technologies = enriched.Technologies
	}

	if len(enriched.CPE) > 0 {
		base.CPE = enriched.CPE
	}

	if len(enriched.CNAMEs) > 0 {
		base.CNAMEs = enriched.CNAMEs
	}

	base.HTTP2 = enriched.HTTP2
	base.WebSocket = enriched.WebSocket

	if enriched.StatusCode != 0 {
		base.StatusCode = enriched.StatusCode
	}

	if enriched.Port != "" {
		base.Port = enriched.Port
	}

	if enriched.Error != "" {
		base.Error = enriched.Error
	}

	return base
}

func pickString(primary string, fallback string) string {
	if primary != "" {
		return primary
	}

	return fallback
}

func targetKey(details WebsiteDetails) string {
	if details.URL != "" {
		return details.URL
	}

	if details.FinalURL != "" {
		return details.FinalURL
	}

	return details.Input
}

func writeWebsiteDetailsMarkdown(filePath string, results []WebsiteDetails) error {
	markdown := renderWebsiteDetailsMarkdown(results)
	return os.WriteFile(filePath, []byte(markdown), 0644)
}

func renderWebsiteDetailsMarkdown(results []WebsiteDetails) string {
	var b strings.Builder

	b.WriteString("# Discovered Website Details\n\n")
	b.WriteString("| Input | URL | Final URL | Host | IP | Port | Status | Server | Technologies | CPE | JARM | ASN | Error |\n")
	b.WriteString("|---|---|---|---|---|---:|---:|---|---|---|---|---|---|\n")

	for _, result := range results {
		b.WriteString("|")
		b.WriteString(" ")
		b.WriteString(escapeMarkdownCell(result.Input))
		b.WriteString(" | ")
		b.WriteString(escapeMarkdownCell(result.URL))
		b.WriteString(" | ")
		b.WriteString(escapeMarkdownCell(result.FinalURL))
		b.WriteString(" | ")
		b.WriteString(escapeMarkdownCell(result.Host))
		b.WriteString(" | ")
		b.WriteString(escapeMarkdownCell(result.HostIP))
		b.WriteString(" | ")
		b.WriteString(escapeMarkdownCell(result.Port))
		b.WriteString(" | ")
		b.WriteString(strconv.Itoa(result.StatusCode))
		b.WriteString(" | ")
		b.WriteString(escapeMarkdownCell(result.WebServer))
		b.WriteString(" | ")
		b.WriteString(escapeMarkdownCell(strings.Join(result.Technologies, ", ")))
		b.WriteString(" | ")
		b.WriteString(escapeMarkdownCell(strings.Join(result.CPE, ", ")))
		b.WriteString(" | ")
		b.WriteString(escapeMarkdownCell(result.JarmHash))
		b.WriteString(" | ")
		b.WriteString(escapeMarkdownCell(result.ASN))
		b.WriteString(" | ")
		b.WriteString(escapeMarkdownCell(result.Error))
		b.WriteString(" |\n")
	}

	return b.String()
}

func escapeMarkdownCell(value string) string {
	value = strings.ReplaceAll(value, "|", "\\|")
	value = strings.ReplaceAll(value, "\n", " ")
	value = strings.TrimSpace(value)
	if value == "" {
		return "-"
	}

	return value
}
