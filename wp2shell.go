package main

import (
	"encoding/csv"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var metaGenerator = regexp.MustCompile(`(?i)<meta\s+[^>]*name=["']generator["'][^>]*content=["']WordPress\s+([0-9.]+)["']`)
var feedGenerator = regexp.MustCompile(`(?i)<generator>https?://wordpress\.org/\?v=([0-9.]+)</generator>`)

type result struct {
	URL          string
	HTTPCode     string
	HTTPResponse string
	RequestError string
	ResponseBody string
	Version      string
	Status       string
}

func versionParts(value string) ([3]int, bool) {
	var parts [3]int
	items := strings.Split(strings.TrimSpace(value), ".")

	if len(items) == 0 || len(items) > 3 {
		return parts, false
	}

	for index, item := range items {
		if item == "" {
			return parts, false
		}

		number, err := strconv.Atoi(item)
		if err != nil || number < 0 {
			return parts, false
		}

		parts[index] = number
	}

	return parts, true
}

func compareVersions(left, right [3]int) int {
	for index := 0; index < 3; index++ {
		if left[index] < right[index] {
			return -1
		}
		if left[index] > right[index] {
			return 1
		}
	}

	return 0
}

func inRange(current [3]int, first string, last string) bool {
	lower, lowerOK := versionParts(first)
	upper, upperOK := versionParts(last)

	return lowerOK && upperOK && compareVersions(lower, current) <= 0 && compareVersions(current, upper) <= 0
}

func isVulnerable(value string) bool {
	current, ok := versionParts(value)
	if !ok {
		return false
	}

	return inRange(current, "6.9.0", "6.9.4") || inRange(current, "7.0.0", "7.0.1")
}

func fetch(client *http.Client, target string) (int, string, string, string) {
	request, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		return 0, "invalid_request", "", err.Error()
	}

	request.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/44.0.2403.157 Safari/537.36")

	response, err := client.Do(request)
	if err != nil {
		return 0, "request_error", "", err.Error()
	}
	defer response.Body.Close()

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return response.StatusCode, response.Status, "", err.Error()
	}

	return response.StatusCode, response.Status, string(body), ""
}

func extractVersion(body string) string {
	if match := metaGenerator.FindStringSubmatch(body); len(match) == 2 {
		return match[1]
	}

	if match := feedGenerator.FindStringSubmatch(body); len(match) == 2 {
		return match[1]
	}

	return ""
}

func feedURL(target string) string {
	parsed, err := url.Parse(target)
	if err != nil {
		return strings.TrimRight(target, "/") + "/feed/"
	}

	parsed.Path = strings.TrimRight(parsed.Path, "/") + "/feed/"
	parsed.RawQuery = ""
	parsed.Fragment = ""

	return parsed.String()
}

func validateURL(client *http.Client, target string) result {
	target = normalizeTarget(target)
	httpCode, httpResponse, body, requestError := fetch(client, target)
	version := extractVersion(body)

	if version == "" && httpCode != 0 {
		_, _, feedBody, _ := fetch(client, feedURL(target))
		version = extractVersion(feedBody)
	}

	if version == "" {
		return result{URL: target, HTTPCode: fmt.Sprint(httpCode), HTTPResponse: httpResponse, RequestError: requestError, ResponseBody: body, Version: "unknown", Status: "unknown"}
	}

	status := "safe"
	if isVulnerable(version) {
		status = "vulnerable"
	}

	return result{URL: target, HTTPCode: fmt.Sprint(httpCode), HTTPResponse: httpResponse, RequestError: requestError, ResponseBody: body, Version: version, Status: status}
}

func normalizeTarget(value string) string {
	value = strings.TrimSpace(value)
	if hasURLScheme(value) {
		return value
	}
	return "https://" + value
}

func hasURLScheme(value string) bool {
	return strings.HasPrefix(value, "http://") || strings.HasPrefix(value, "https://")
}

func loadTargets(path string, column string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	reader := csv.NewReader(file)
	reader.FieldsPerRecord = -1

	rows, err := reader.ReadAll()
	if err != nil {
		return nil, err
	}

	if len(rows) == 0 {
		return nil, errors.New("CSV is empty")
	}

	columnIndex := 0
	startRow := 0

	for index, name := range rows[0] {
		if strings.EqualFold(strings.TrimSpace(name), column) {
			columnIndex = index
			startRow = 1
			break
		}
	}

	var targets []string
	for _, row := range rows[startRow:] {
		if len(row) <= columnIndex {
			continue
		}

		target := strings.TrimSpace(row[columnIndex])
		if target != "" {
			targets = append(targets, target)
		}
	}

	if len(targets) == 0 {
		return nil, errors.New("no targets found")
	}

	return targets, nil
}

func writeResults(results []result) error {
	writer := csv.NewWriter(os.Stdout)
	defer writer.Flush()

	if err := writer.Write([]string{"url", "http_code", "http_response", "request_error", "wordpress_version", "status", "response_body"}); err != nil {
		return err
	}

	for _, item := range results {
		if err := writer.Write([]string{item.URL, item.HTTPCode, item.HTTPResponse, item.RequestError, item.Version, item.Status, item.ResponseBody}); err != nil {
			return err
		}
	}

	return writer.Error()
}

func writeOutput(path string, results []result) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	if err := writer.Write([]string{"url", "version", "affected", "status_code", "http_response", "request_error", "response_body"}); err != nil {
		return err
	}

	for _, item := range results {
		affected := "false"
		if item.Status == "vulnerable" {
			affected = "true"
		}

		if err := writer.Write([]string{item.URL, item.Version, affected, item.HTTPCode, item.HTTPResponse, item.RequestError, item.ResponseBody}); err != nil {
			return err
		}
	}

	return writer.Error()
}

func main() {
	singleURL := flag.String("u", "", "single target URL")
	output := flag.String("o", "", "write url, version, affected, status_code, http_response, request_error, and response_body to CSV")
	column := flag.String("column", "url", "URL column name for CSV files")
	timeout := flag.Duration("timeout", 10*time.Second, "HTTP timeout")
	flag.Parse()

	if (*singleURL == "" && flag.NArg() != 1) || (*singleURL != "" && flag.NArg() != 0) {
		fmt.Fprintln(os.Stderr, "usage: wp2shell -u https://target.example | wp2shell targets.csv")
		os.Exit(2)
	}

	var targets []string
	var err error

	if *singleURL != "" {
		targets = []string{normalizeTarget(*singleURL)}
	} else {
		targets, err = loadTargets(flag.Arg(0), *column)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}

	client := &http.Client{Timeout: *timeout}
	results := make([]result, 0, len(targets))

	for _, target := range targets {
		results = append(results, validateURL(client, target))
	}

	if err := writeResults(results); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	if *output != "" {
		if err := writeOutput(*output, results); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
}
