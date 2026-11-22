// Command vexgen synthesizes an OpenVEX document from review conclusions and
// Trivy scan results, then verifies the document through the unmodified Trivy
// VEX consumer. Everything runs offline and produces reproducible output.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	openvex "github.com/openvex/go-vex/pkg/vex"

	"github.com/aquasecurity/trivy/pkg/vexgen"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "generate":
		err = runGenerate(os.Args[2:])
	case "roundtrip":
		err = runRoundTrip(os.Args[2:])
	case "all":
		err = runAll(os.Args[2:])
	case "-h", "--help", "help":
		usage()
	default:
		usage()
		err = fmt.Errorf("unknown subcommand %q", os.Args[1])
	}
	if err != nil {
		var issues vexgen.Issues
		if errors.As(err, &issues) {
			fmt.Fprintln(os.Stderr, issues.Error())
			os.Exit(3)
		}
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `vexgen - review-conclusion to OpenVEX synthesizer

Usage:
  vexgen generate   --scans scans.json --reviews a.json,b.json --out openvex.json [--reconcile reconcile.json]
  vexgen roundtrip  --scans scans.json --document openvex.json [--report roundtrip.json]
  vexgen all        --scans scans.json --reviews a.json,b.json --out openvex.json [--reconcile r.json] [--report roundtrip.json]

Reproducibility:
  SOURCE_DATE_EPOCH   unix seconds or RFC3339; sets the document timestamp
  VEXGEN_AUTHOR       document author (default: "security-review-team")
`)
}

type flags struct {
	scans     string
	reviews   string
	out       string
	reconcile string
	document  string
	report    string
	author    string
}

func parseFlags(fs *flag.FlagSet) *flags {
	c := &flags{}
	fs.StringVar(&c.scans, "scans", "", "path to scan results JSON (array)")
	fs.StringVar(&c.reviews, "reviews", "", "comma-separated review sheet JSON files (arrays)")
	fs.StringVar(&c.out, "out", "", "output OpenVEX document path")
	fs.StringVar(&c.reconcile, "reconcile", "", "output reconciliation report path")
	fs.StringVar(&c.document, "document", "", "input OpenVEX document for roundtrip")
	fs.StringVar(&c.report, "report", "", "output round-trip comparison report path")
	fs.StringVar(&c.author, "author", envOr("VEXGEN_AUTHOR", "security-review-team"), "document author")
	return c
}

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func documentTime() (time.Time, error) {
	v := os.Getenv("SOURCE_DATE_EPOCH")
	if v == "" {
		return time.Time{}, errors.New("SOURCE_DATE_EPOCH is required for reproducible timestamps (unix seconds or RFC3339)")
	}
	if sec, err := strconv.ParseInt(v, 10, 64); err == nil {
		return time.Unix(sec, 0).UTC(), nil
	}
	t, err := time.Parse(time.RFC3339, v)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid SOURCE_DATE_EPOCH %q: %w", v, err)
	}
	return t.UTC(), nil
}

func loadScans(path string) ([]vexgen.ScanResult, error) {
	var scans []vexgen.ScanResult
	if err := loadJSON(path, &scans); err != nil {
		return nil, err
	}
	if len(scans) == 0 {
		return nil, errors.New("scan results file contains no products")
	}
	return scans, nil
}

func loadReviews(paths string) ([]vexgen.ReviewEntry, error) {
	var all []vexgen.ReviewEntry
	for _, p := range strings.Split(paths, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		var rows []vexgen.ReviewEntry
		if err := loadJSON(p, &rows); err != nil {
			return nil, err
		}
		for i := range rows {
			rows[i].SourceFile = filepath.Base(p)
			rows[i].Row = i + 2 // header is row 1 in the originating sheet
		}
		all = append(all, rows...)
	}
	if len(all) == 0 {
		return nil, errors.New("no review rows loaded")
	}
	return all, nil
}

func loadJSON(path string, v any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("parse %s: %w", path, err)
	}
	return nil
}

func loadDocument(path string) (*openvex.VEX, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read document %s: %w", path, err)
	}
	var doc openvex.VEX
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, fmt.Errorf("parse document %s: %w", path, err)
	}
	return &doc, nil
}

func writeJSON(path string, v any) error {
	if path == "" {
		return errors.New("output path is required")
	}
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	if dir := filepath.Dir(path); dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	return os.WriteFile(path, b, 0o644)
}

func runGenerate(args []string) error {
	fs := flag.NewFlagSet("generate", flag.ContinueOnError)
	c := parseFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if c.scans == "" || c.reviews == "" || c.out == "" {
		usage()
		return errors.New("generate requires --scans, --reviews and --out")
	}
	scans, err := loadScans(c.scans)
	if err != nil {
		return err
	}
	reviews, err := loadReviews(c.reviews)
	if err != nil {
		return err
	}
	ts, err := documentTime()
	if err != nil {
		return err
	}
	res, reconcile, issues := vexgen.Build(scans, reviews, vexgen.Options{Author: c.author, DocumentTimestamp: ts})
	if issues != nil {
		if c.reconcile != "" {
			_ = writeJSON(c.reconcile, map[string]any{"reconciliation": reconcile, "blocked": true})
		}
		return issues
	}
	if err := writeJSON(c.out, res.Document); err != nil {
		return err
	}
	if c.reconcile != "" {
		if err := writeJSON(c.reconcile, map[string]any{"reconciliation": reconcile, "blocked": false}); err != nil {
			return err
		}
	}
	fmt.Printf("generated %s: %d converged conclusions (%d consumer-trusted), %d reconciliation rows\n",
		c.out, res.ConvergedCount, res.TrustedCount, len(reconcile))
	return nil
}

func runRoundTrip(args []string) error {
	fs := flag.NewFlagSet("roundtrip", flag.ContinueOnError)
	c := parseFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if c.scans == "" || c.document == "" {
		usage()
		return errors.New("roundtrip requires --scans and --document")
	}
	scans, err := loadScans(c.scans)
	if err != nil {
		return err
	}
	doc, err := loadDocument(c.document)
	if err != nil {
		return err
	}
	converged := vexgen.ExpectationsFromDocument(scans, doc)
	return doRoundTrip(scans, doc, converged, c.document, c.report)
}

func runAll(args []string) error {
	fs := flag.NewFlagSet("all", flag.ContinueOnError)
	c := parseFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if c.scans == "" || c.reviews == "" || c.out == "" {
		usage()
		return errors.New("all requires --scans, --reviews and --out")
	}
	scans, err := loadScans(c.scans)
	if err != nil {
		return err
	}
	reviews, err := loadReviews(c.reviews)
	if err != nil {
		return err
	}
	ts, err := documentTime()
	if err != nil {
		return err
	}
	res, reconcile, issues := vexgen.Build(scans, reviews, vexgen.Options{Author: c.author, DocumentTimestamp: ts})
	if issues != nil {
		if c.reconcile != "" {
			_ = writeJSON(c.reconcile, map[string]any{"reconciliation": reconcile, "blocked": true})
		}
		return issues
	}
	if err := writeJSON(c.out, res.Document); err != nil {
		return err
	}
	if c.reconcile != "" {
		if err := writeJSON(c.reconcile, map[string]any{"reconciliation": reconcile, "blocked": false}); err != nil {
			return err
		}
	}
	fmt.Printf("generated %s: %d converged conclusions (%d consumer-trusted), %d reconciliation rows\n",
		c.out, res.ConvergedCount, res.TrustedCount, len(reconcile))
	return doRoundTrip(scans, res.Document, res.Converged, c.out, c.report)
}

func doRoundTrip(scans []vexgen.ScanResult, doc *openvex.VEX, converged map[vexgen.FindingKey]vexgen.ConvergedConclusion, docPath, reportPath string) error {
	report, err := vexgen.RoundTrip(context.Background(), scans, doc, converged, docPath)
	if err != nil {
		return err
	}
	if reportPath != "" {
		if err := writeJSON(reportPath, report); err != nil {
			return err
		}
	}
	fmt.Printf("round-trip: expected=%d observed=%d missing=%d unexpected=%d statusMismatch=%d -> %s\n",
		report.ExpectedCount, report.ObservedCount, len(report.MissingHits), len(report.UnexpectedHits), len(report.StatusMismatch),
		map[bool]string{true: "PASS", false: "FAIL"}[report.OK()])
	if !report.OK() {
		return errors.New("round-trip verification failed")
	}
	return nil
}
