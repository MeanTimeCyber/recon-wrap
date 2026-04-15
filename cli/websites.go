package main

import (
	"fmt"
	"log/slog"

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
	FavIconMMH3  string
	FavIconMD5   string
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

// getWebsiteDetails performs two-pass website probing: a broad first pass for
// reachability and a focused second pass for deep enrichment on healthy targets.
func getWebsiteDetails(subdomains []string, disableLiveURLPrint bool, sniName string) ([]WebsiteDetails, error) {
	slog.Info("Inspecting websites", "targets", len(subdomains))

	ports := customport.CustomPorts{}

	// Probe a broad set of common web ports in the initial sweep.
	if err := ports.Set("80,88,8000,8008,8080,8081,8088,8888,9000,9090,443,444,5443,6443,7443,8443,9443,10443"); err != nil {
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

			// Keep only healthy responses for expensive second-pass fingerprinting.
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
		Threads:            100,
		RateLimit:          300,
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
					// Merge multiple callbacks for the same target without losing populated fields.
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
		Threads:            40,
		RateLimit:          100,
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
				FavIconMMH3:  r.FavIconMMH3,
				FavIconMD5:   r.FavIconMD5,
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

		// Overlay deep second-pass fingerprints onto first-pass baseline results.
		results[i] = mergeWebsiteDetails(result, enriched)
		mergedResults++
	}

	slog.Info("second pass complete", "enriched_results", len(enrichedByTarget), "merged_results", mergedResults)

	return results, nil
}

// isGoodStatusCode returns true for response codes considered worth deep
// follow-up enrichment in the second pass.
func isGoodStatusCode(statusCode int) bool {
	if statusCode >= 200 && statusCode < 400 {
		return true
	}

	return statusCode == 401 || statusCode == 403
}

// mergeWebsiteDetails overlays enriched fields onto a baseline result while
// preserving any already-populated values that enrichment did not improve.
func mergeWebsiteDetails(base WebsiteDetails, enriched WebsiteDetails) WebsiteDetails {
	base.SNI = pickString(enriched.SNI, base.SNI)
	base.Host = pickString(enriched.Host, base.Host)
	base.HostIP = pickString(enriched.HostIP, base.HostIP)
	base.ASN = pickString(enriched.ASN, base.ASN)
	base.FavIconMMH3 = pickString(enriched.FavIconMMH3, base.FavIconMMH3)
	base.FavIconMD5 = pickString(enriched.FavIconMD5, base.FavIconMD5)
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

// pickString prefers a non-empty primary value and falls back otherwise.
func pickString(primary string, fallback string) string {
	if primary != "" {
		return primary
	}

	return fallback
}

// targetKey builds a stable endpoint key used to correlate records between scan
// passes, preferring URL then final URL, then the original input target.
func targetKey(details WebsiteDetails) string {
	// Use a stable lookup key across passes to correlate the same endpoint.
	if details.URL != "" {
		return details.URL
	}

	if details.FinalURL != "" {
		return details.FinalURL
	}

	return details.Input
}
