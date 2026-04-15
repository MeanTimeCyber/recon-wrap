package main

import (
	"os"
	"strconv"
	"strings"
)

// writeWebsiteDetailsMarkdown renders website details and writes them to a
// markdown file at the provided path.
func writeWebsiteDetailsMarkdown(filePath string, inputDomain string, results []WebsiteDetails) error {
	markdown := renderWebsiteDetailsMarkdown(inputDomain, results)
	return os.WriteFile(filePath, []byte(markdown), 0644)
}

// renderWebsiteDetailsMarkdown builds a report with a concise summary table
// followed by per-site detail tables for all discovered endpoints.
func renderWebsiteDetailsMarkdown(inputDomain string, results []WebsiteDetails) string {
	var b strings.Builder
	orderedResults := prioritizeInputDomainResults(inputDomain, results)

	b.WriteString("# Discovered Website Details\n\n")
	b.WriteString("Input domain: **")
	b.WriteString(escapeMarkdownCell(inputDomain))
	b.WriteString("**\n\n")

	b.WriteString("## Summary\n\n")
	b.WriteString("| Input | URL | Status | Title | Server | Technologies |\n")
	b.WriteString("|---|---|---:|---|---|---|\n")

	for _, result := range orderedResults {
		inputLabel := escapeMarkdownCell(result.Input)
		if isInputDomainResult(inputDomain, result) {
			inputLabel = "**" + inputLabel + " (input)"
		}

		b.WriteString("| ")
		b.WriteString(inputLabel)
		b.WriteString(" | ")
		b.WriteString(escapeMarkdownCell(result.URL))
		b.WriteString(" | ")
		b.WriteString(strconv.Itoa(result.StatusCode))
		b.WriteString(" | ")
		b.WriteString(escapeMarkdownCell(result.Title))
		b.WriteString(" | ")
		b.WriteString(escapeMarkdownCell(result.WebServer))
		b.WriteString(" | ")
		b.WriteString(escapeMarkdownCell(strings.Join(result.Technologies, ", ")))
		b.WriteString(" |\n")
	}

	b.WriteString("\n## Detailed Results\n")

	for _, result := range orderedResults {
		b.WriteString("\n### ")
		if isInputDomainResult(inputDomain, result) {
			b.WriteString("Input Domain")
		} else {
			b.WriteString("Subdomain")
		}
		b.WriteString(": ")
		b.WriteString(escapeMarkdownCell(result.URL))
		b.WriteString(" details\n\n")
		b.WriteString("\n\n")
		b.WriteString("| Field | Value |\n")
		b.WriteString("|---|---|\n")
		b.WriteString("| Input | ")
		b.WriteString(escapeMarkdownCell(result.Input))
		b.WriteString(" |\n")
		b.WriteString("| URL | ")
		b.WriteString(escapeMarkdownCell(result.URL))
		b.WriteString(" |\n")
		b.WriteString("| Final URL | ")
		b.WriteString(escapeMarkdownCell(result.FinalURL))
		b.WriteString(" |\n")
		b.WriteString("| SNI | ")
		b.WriteString(escapeMarkdownCell(result.SNI))
		b.WriteString(" |\n")
		b.WriteString("| Host | ")
		b.WriteString(escapeMarkdownCell(result.Host))
		b.WriteString(" |\n")
		b.WriteString("| IP | ")
		b.WriteString(escapeMarkdownCell(result.HostIP))
		b.WriteString(" |\n")
		b.WriteString("| Port | ")
		b.WriteString(escapeMarkdownCell(result.Port))
		b.WriteString(" |\n")
		b.WriteString("| Status | ")
		b.WriteString(strconv.Itoa(result.StatusCode))
		b.WriteString(" |\n")
		b.WriteString("| Title | ")
		b.WriteString(escapeMarkdownCell(result.Title))
		b.WriteString(" |\n")
		b.WriteString("| Location | ")
		b.WriteString(escapeMarkdownCell(result.Location))
		b.WriteString(" |\n")
		b.WriteString("| Server | ")
		b.WriteString(escapeMarkdownCell(result.WebServer))
		b.WriteString(" |\n")
		b.WriteString("| Content Type | ")
		b.WriteString(escapeMarkdownCell(result.ContentType))
		b.WriteString(" |\n")
		b.WriteString("| Response Time | ")
		b.WriteString(escapeMarkdownCell(result.ResponseTime))
		b.WriteString(" |\n")
		b.WriteString("| Technologies | ")
		b.WriteString(escapeMarkdownCell(strings.Join(result.Technologies, ", ")))
		b.WriteString(" |\n")
		b.WriteString("| CPE | ")
		b.WriteString(escapeMarkdownCell(strings.Join(result.CPE, ", ")))
		b.WriteString(" |\n")
		b.WriteString("| WordPress | ")
		b.WriteString(escapeMarkdownCell(result.WordPress))
		b.WriteString(" |\n")
		b.WriteString("| HTTP2 | ")
		b.WriteString(strconv.FormatBool(result.HTTP2))
		b.WriteString(" |\n")
		b.WriteString("| WebSocket | ")
		b.WriteString(strconv.FormatBool(result.WebSocket))
		b.WriteString(" |\n")
		b.WriteString("| CDN | ")
		b.WriteString(escapeMarkdownCell(result.CDNName))
		b.WriteString(" |\n")
		b.WriteString("| CNAMEs | ")
		b.WriteString(escapeMarkdownCell(strings.Join(result.CNAMEs, ", ")))
		b.WriteString(" |\n")
		b.WriteString("| FaviconMMH3 | ")
		b.WriteString(escapeMarkdownCell(result.FavIconMMH3))
		b.WriteString(" |\n")
		b.WriteString("| FaviconMD5 | ")
		b.WriteString(escapeMarkdownCell(result.FavIconMD5))
		b.WriteString(" |\n")
		b.WriteString("| ASN | ")
		b.WriteString(escapeMarkdownCell(result.ASN))
		b.WriteString(" |\n")
		b.WriteString("| Error | ")
		b.WriteString(escapeMarkdownCell(result.Error))
		b.WriteString(" |\n")
	}

	return b.String()
}

// prioritizeInputDomainResults returns a new slice where entries belonging to
// the input domain are placed first while preserving original relative order.
func prioritizeInputDomainResults(inputDomain string, results []WebsiteDetails) []WebsiteDetails {
	prioritized := make([]WebsiteDetails, 0, len(results))

	for _, result := range results {
		if isInputDomainResult(inputDomain, result) {
			prioritized = append(prioritized, result)
		}
	}

	for _, result := range results {
		if !isInputDomainResult(inputDomain, result) {
			prioritized = append(prioritized, result)
		}
	}

	return prioritized
}

// isInputDomainResult reports whether the result maps to the root input domain.
func isInputDomainResult(inputDomain string, result WebsiteDetails) bool {
	return strings.EqualFold(strings.TrimSpace(result.Input), strings.TrimSpace(inputDomain))
}

// escapeMarkdownCell sanitizes table cell values by escaping separators,
// flattening newlines, and normalizing empty values for markdown output.
func escapeMarkdownCell(value string) string {
	value = strings.ReplaceAll(value, "|", "\\|")
	value = strings.ReplaceAll(value, "\n", " ")
	value = strings.TrimSpace(value)
	if value == "" {
		return "-"
	}

	return value
}
