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
	URL      string
	HTTPCode string
	Version  string
	Status   string
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

func fetch(client *http.Client, target string) (int, string) {
	request, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		return 0, ""
	}

	request.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/44.0.2403.157 Safari/537.36")

	response, err := client.Do(request)
	if err != nil {
		return 0, ""
	}
	defer response.Body.Close()

	body, err := io.ReadAll(io.LimitReader(response.Body, 2*1024*1024))
	if err != nil {
		return response.StatusCode, ""
	}

	return response.StatusCode, string(body)
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
	httpCode, body := fetch(client, target)
	version := extractVersion(body)

	if version == "" && httpCode != 0 {
		_, feedBody := fetch(client, feedURL(target))
		version = extractVersion(feedBody)
	}

	if version == "" {
		return result{target, fmt.Sprint(httpCode), "unknown", "unknown"}
	}

	status := "safe"
	if isVulnerable(version) {
		status = "vulnerable"
	}

	return result{target, fmt.Sprint(httpCode), version, status}
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

	if err := writer.Write([]string{"url", "http_code", "wordpress_version", "status"}); err != nil {
		return err
	}

	for _, item := range results {
		if err := writer.Write([]string{item.URL, item.HTTPCode, item.Version, item.Status}); err != nil {
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

	if err := writer.Write([]string{"url", "version", "affected", "status_code"}); err != nil {
		return err
	}

	for _, item := range results {
		affected := "false"
		if item.Status == "vulnerable" {
			affected = "true"
		}

		if err := writer.Write([]string{item.URL, item.Version, affected, item.HTTPCode}); err != nil {
			return err
		}
	}

	return writer.Error()
}

func main() {
	singleURL := flag.String("u", "", "single target URL")
	output := flag.String("o", "", "write url, version, affected, and status_code to CSV")
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
		if !hasURLScheme(*singleURL) {
			fmt.Fprintln(os.Stderr, "URL must start with http:// or https://")
			os.Exit(2)
		}
		targets = []string{*singleURL}
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
