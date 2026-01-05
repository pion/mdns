//go:build ignore

// SPDX-FileCopyrightText: The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

// Run with: go run fetch.go
// Downloads RFC and draft specifications, cleans up page breaks,
// and splits them into chapters for easier reference.

package main

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var specs = []struct {
	name string
	url  string
}{
	{"rfc6762", "https://www.rfc-editor.org/rfc/rfc6762.txt"},
	{"rfc6763", "https://www.rfc-editor.org/rfc/rfc6763.txt"},
	{"draft-ietf-rtcweb-mdns-ice-candidates-02", "https://www.ietf.org/archive/id/draft-ietf-rtcweb-mdns-ice-candidates-02.txt"},
	{"draft-ietf-mmusic-mdns-ice-candidates-03", "https://www.ietf.org/archive/id/draft-ietf-mmusic-mdns-ice-candidates-03.txt"},
}

// Patterns for detecting page breaks and section headers
var (
	// Page footer: ends with [Page N]
	pageFooterRe = regexp.MustCompile(`\[Page \d+\]\s*$`)
	// Page header: "RFC NNNN" or "Internet-Draft" at start of line
	pageHeaderRe = regexp.MustCompile(`^(RFC \d+|Internet-Draft)\s+`)
	// Section heading: "N.  Title" with TWO spaces (IETF style)
	// Must start at column 0, not be a ToC entry (no trailing dots+page num)
	sectionHeadingRe = regexp.MustCompile(`^(\d+(?:\.\d+)*)\.\s{2,}([A-Z].*)$`)
	// Appendix heading: "Appendix A.  Title" with two spaces
	appendixHeadingRe = regexp.MustCompile(`^(Appendix [A-Z](?:\.\d+)*)\.\s{2,}([A-Z].*)$`)
	// ToC entry pattern (to exclude)
	tocEntryRe = regexp.MustCompile(`\.{3,}\s*\d+\s*$`)
	// Authors' Addresses, Acknowledgments, References (back matter)
	backMatterRe = regexp.MustCompile(`^(Authors?' Addresses?|Acknowledge?ments?)\s*$`)
)

func main() {
	dir, err := os.Getwd()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to get working directory: %v\n", err)
		os.Exit(1)
	}

	for _, spec := range specs {
		fmt.Printf("Fetching %s...\n", spec.name)

		content, err := fetch(spec.url)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to fetch %s: %v\n", spec.name, err)
			os.Exit(1)
		}

		// Clean up page breaks
		cleaned := cleanPageBreaks(content)

		// Save full cleaned version
		fullPath := filepath.Join(dir, spec.name+".txt")
		if err := os.WriteFile(fullPath, []byte(cleaned), 0644); err != nil {
			fmt.Fprintf(os.Stderr, "failed to write %s: %v\n", fullPath, err)
			os.Exit(1)
		}
		fmt.Printf("  -> saved %s.txt\n", spec.name)

		// Split into chapters
		specDir := filepath.Join(dir, spec.name)
		if err := os.MkdirAll(specDir, 0755); err != nil {
			fmt.Fprintf(os.Stderr, "failed to create directory %s: %v\n", specDir, err)
			os.Exit(1)
		}

		chapters := splitChapters(cleaned)
		for _, ch := range chapters {
			chPath := filepath.Join(specDir, ch.filename)
			if err := os.WriteFile(chPath, []byte(ch.content), 0644); err != nil {
				fmt.Fprintf(os.Stderr, "failed to write %s: %v\n", chPath, err)
				os.Exit(1)
			}
		}
		fmt.Printf("  -> split into %d chapters in %s/\n", len(chapters), spec.name)
	}

	fmt.Println("Done.")
}

func fetch(url string) (string, error) {
	resp, err := http.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d: %s", resp.StatusCode, resp.Status)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(data), nil
}

// cleanPageBreaks removes IETF-style page breaks from the document.
// Page breaks typically consist of:
// - Several blank lines
// - A footer line ending with [Page N]
// - A form feed character (optional)
// - A header line with RFC number or "Internet-Draft"
// - More blank lines
func cleanPageBreaks(content string) string {
	lines := strings.Split(content, "\n")
	var result []string
	var skipNext int

	for i := 0; i < len(lines); i++ {
		line := lines[i]

		// Skip lines we've marked for skipping (post-page-break headers)
		if skipNext > 0 {
			skipNext--
			continue
		}

		// Remove form feed characters
		line = strings.ReplaceAll(line, "\f", "")

		// Detect page footer
		if pageFooterRe.MatchString(line) {
			// Remove trailing blank lines we may have added
			for len(result) > 0 && strings.TrimSpace(result[len(result)-1]) == "" {
				result = result[:len(result)-1]
			}

			// Skip the footer and subsequent header/blank lines
			skipNext = countHeaderLines(lines, i+1)
			continue
		}

		result = append(result, line)
	}

	// Normalize multiple consecutive blank lines to at most 2
	return normalizeBlankLines(strings.Join(result, "\n"))
}

// countHeaderLines counts how many lines to skip after a page footer
func countHeaderLines(lines []string, start int) int {
	count := 0
	for i := start; i < len(lines) && i < start+5; i++ {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			count++
			continue
		}
		// Check if it's a page header line
		if pageHeaderRe.MatchString(line) {
			count++
			continue
		}
		break
	}
	return count
}

// normalizeBlankLines reduces runs of 3+ blank lines to 2
func normalizeBlankLines(content string) string {
	lines := strings.Split(content, "\n")
	var result []string
	blankCount := 0

	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			blankCount++
			if blankCount <= 2 {
				result = append(result, line)
			}
		} else {
			blankCount = 0
			result = append(result, line)
		}
	}

	// Trim leading/trailing blank lines
	text := strings.Join(result, "\n")
	return strings.TrimSpace(text) + "\n"
}

type chapter struct {
	filename string
	content  string
}

// splitChapters splits a cleaned RFC into separate chapter files
func splitChapters(content string) []chapter {
	var chapters []chapter
	scanner := bufio.NewScanner(strings.NewReader(content))

	var currentChapter strings.Builder
	currentFilename := "00-front-matter.txt"
	var currentTitle string

	for scanner.Scan() {
		line := scanner.Text()

		// Check for section heading
		if filename, title, ok := parseSectionHeading(line); ok {
			// Save previous chapter if it has content
			if currentChapter.Len() > 0 {
				chapters = append(chapters, chapter{
					filename: currentFilename,
					content:  strings.TrimSpace(currentChapter.String()) + "\n",
				})
			}
			currentFilename = filename
			currentTitle = title
			currentChapter.Reset()
		}

		currentChapter.WriteString(line)
		currentChapter.WriteString("\n")
		_ = currentTitle // Title is embedded in the chapter content
	}

	// Don't forget the last chapter
	if currentChapter.Len() > 0 {
		chapters = append(chapters, chapter{
			filename: currentFilename,
			content:  strings.TrimSpace(currentChapter.String()) + "\n",
		})
	}

	// Generate index
	chapters = append([]chapter{generateIndex(chapters)}, chapters...)

	return chapters
}

func parseSectionHeading(line string) (filename, title string, ok bool) {
	// Section headings must start at column 0 (no leading whitespace)
	if len(line) == 0 || line[0] == ' ' || line[0] == '\t' {
		return "", "", false
	}

	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return "", "", false
	}

	// Skip Table of Contents entries (have trailing dots and page numbers)
	if tocEntryRe.MatchString(trimmed) {
		return "", "", false
	}

	// Check for numbered section: "1.  Introduction", "5.1.  Foo"
	if m := sectionHeadingRe.FindStringSubmatch(line); m != nil {
		num := m[1]
		title = strings.TrimSpace(m[2])
		filename = fmt.Sprintf("%s-%s.txt", padSectionNumber(num), slugify(title))
		return filename, title, true
	}

	// Check for appendix: "Appendix A.  Title"
	if m := appendixHeadingRe.FindStringSubmatch(line); m != nil {
		appendix := m[1]
		appendix = strings.ReplaceAll(appendix, " ", "-")
		title = strings.TrimSpace(m[2])
		filename = fmt.Sprintf("%s-%s.txt", appendix, slugify(title))
		return filename, title, true
	}

	// Check for special back matter sections
	if m := backMatterRe.FindStringSubmatch(trimmed); m != nil {
		title = m[1]
		filename = fmt.Sprintf("99-%s.txt", slugify(title))
		return filename, title, true
	}

	return "", "", false
}

// padSectionNumber pads section numbers for proper sorting
// "1" -> "01", "5.1" -> "05.01", "10.2.3" -> "10.02.03"
func padSectionNumber(num string) string {
	parts := strings.Split(num, ".")
	var padded []string
	for _, p := range parts {
		if len(p) == 1 {
			padded = append(padded, "0"+p)
		} else {
			padded = append(padded, p)
		}
	}
	return strings.Join(padded, ".")
}

// slugify converts a title to a filename-safe slug
func slugify(s string) string {
	s = strings.ToLower(s)
	s = strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			return r
		}
		if r == ' ' || r == '-' || r == '_' {
			return '-'
		}
		return -1
	}, s)
	// Collapse multiple dashes
	for strings.Contains(s, "--") {
		s = strings.ReplaceAll(s, "--", "-")
	}
	s = strings.Trim(s, "-")
	// Truncate long names
	if len(s) > 50 {
		s = s[:50]
		// Don't end with a dash
		s = strings.TrimRight(s, "-")
	}
	return s
}

func generateIndex(chapters []chapter) chapter {
	var idx strings.Builder
	idx.WriteString("Index of Chapters\n")
	idx.WriteString("=================\n\n")

	for _, ch := range chapters {
		idx.WriteString(fmt.Sprintf("- %s\n", ch.filename))
	}

	return chapter{
		filename: "00-index.txt",
		content:  idx.String(),
	}
}
