package layerprovenance

import (
	"context"
	"encoding/json"
	"io"

	"golang.org/x/xerrors"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/types"
)

// Options configures the provenance writer.
type Options struct {
	Output io.Writer

	// Previous, when set, is the report to compare the current scan against.
	Previous *Previous
}

// Writer emits a layer-provenance report as JSON Lines.
//
// Findings are encoded one at a time. Neither the current findings nor the
// whole document are held in memory: the summaries are accumulated while the
// findings stream out. With a previous report, only its findings are held, as
// they are the side of the comparison that must be looked up by identity.
type Writer struct {
	opts Options
}

func NewWriter(opts Options) *Writer {
	return &Writer{opts: opts}
}

// Write emits the report. When a previous report is supplied, the current
// findings are matched against it by identity to classify them as added,
// removed or unchanged.
func (w *Writer) Write(_ context.Context, report types.Report) error {
	enc := json.NewEncoder(w.opts.Output)
	enc.SetEscapeHTML(false)

	if err := enc.Encode(headerFrom(report, w.opts.Previous)); err != nil {
		return xerrors.Errorf("failed to write provenance header: %w", err)
	}

	idx := newLayerIndex(report)
	cmp := w.newComparison()

	layerTotals := newLayerTotals()
	var totals FindingBreakdown
	roleTotals := make(map[ftypes.LayerRole]*Counts)

	emit := func(f Finding) error {
		totals.add(f)
		if f.LayerChanged {
			totals.LayerChanged++
		}
		layerTotals.add(f)
		role := roleOf(f)
		b, ok := roleTotals[role]
		if !ok {
			b = &Counts{}
			roleTotals[role] = b
		}
		b.add(f)

		if err := enc.Encode(f); err != nil {
			return xerrors.Errorf("failed to write provenance finding: %w", err)
		}
		return nil
	}

	for _, result := range report.Results {
		// Sort each result's findings before writing them. A result is one
		// target, so this is bounded by the findings of a single target rather
		// than the whole image, and it makes the output independent of the
		// order the scanner produced them in.
		batch := make([]Finding, 0, len(result.Vulnerabilities))
		for _, v := range result.Vulnerabilities {
			entry := newFinding(idx, result, v)
			if cmp != nil {
				cmp.match(&entry)
			}
			batch = append(batch, entry)
		}
		sortFindings(batch)
		for _, entry := range batch {
			if err := emit(entry); err != nil {
				return err
			}
		}
	}

	if cmp != nil {
		// Every previous finding that was not matched has disappeared. It is
		// reported on its own, with the layer it had in the previous scan, so a
		// package upgrade records a removal and an addition rather than a
		// single net change.
		for _, f := range cmp.unmatched() {
			if err := emit(f); err != nil {
				return err
			}
		}
	}

	for _, ls := range layerTotals.sorted() {
		if err := enc.Encode(ls); err != nil {
			return xerrors.Errorf("failed to write layer summary: %w", err)
		}
	}

	byRole := make(map[string]Counts, len(roleTotals))
	for role, b := range roleTotals {
		byRole[string(role)] = *b
	}
	summary := Summary{
		Type:       RecordTypeSummary,
		Findings:   totals,
		ByRole:     byRole,
		Reconciled: totals.Total == layerTotals.total,
	}
	if err := enc.Encode(summary); err != nil {
		return xerrors.Errorf("failed to write provenance summary: %w", err)
	}
	return nil
}

func newFinding(idx *layerIndex, result types.Result, v types.DetectedVulnerability) Finding {
	f := Finding{
		Type:          RecordTypeFinding,
		Status:        StatusUnchanged,
		Identity:      identity(string(result.Class), string(result.Type), v),
		Vulnerability: vulnInfo(v),
		Package:       pkgInfo(v),
		Class:         string(result.Class),
		TargetType:    string(result.Type),
	}
	layer := unknownLayer()
	if l, ok := idx.lookup(v.Layer); ok {
		layer = l
	}
	f.Layer = &layer
	return f
}

// comparison matches current findings against a previous report.
type comparison struct {
	byIdentity map[string][]Finding
	matched    map[string]int
}

func (w *Writer) newComparison() *comparison {
	if w.opts.Previous == nil {
		return nil
	}
	c := &comparison{
		byIdentity: make(map[string][]Finding, len(w.opts.Previous.Findings)),
		matched:    make(map[string]int, len(w.opts.Previous.Findings)),
	}
	for _, f := range w.opts.Previous.Findings {
		c.byIdentity[f.Identity] = append(c.byIdentity[f.Identity], f)
	}
	return c
}

// match fills in the previous layer information for an unchanged finding and
// classifies it as added when no counterpart exists.
func (c *comparison) match(f *Finding) {
	matches := c.byIdentity[f.Identity]
	n := c.matched[f.Identity]
	if n >= len(matches) {
		f.Status = StatusAdded
		return
	}
	c.matched[f.Identity] = n + 1

	previous := matches[n]
	f.Status = StatusUnchanged
	f.PreviousLayers = previous.PreviousLayers
	if previous.Layer != nil {
		if !containsLayer(f.PreviousLayers, *previous.Layer) {
			f.PreviousLayers = append(f.PreviousLayers, *previous.Layer)
		}
		f.LayerChanged = f.Layer == nil ||
			f.Layer.DiffID != previous.Layer.DiffID ||
			f.Layer.Digest != previous.Layer.Digest
	}
}

// unmatched returns the previous findings that had no counterpart, as removed
// findings carrying their previous layer.
func (c *comparison) unmatched() []Finding {
	var out []Finding
	for id, matches := range c.byIdentity {
		for i := c.matched[id]; i < len(matches); i++ {
			f := matches[i]
			f.Type = RecordTypeFinding
			f.Status = StatusRemoved
			f.Layer = nil
			if len(f.PreviousLayers) == 0 && matches[i].Layer != nil {
				f.PreviousLayers = []LayerInfo{*matches[i].Layer}
			}
			f.LayerChanged = false
			out = append(out, f)
		}
	}
	sortFindings(out)
	return out
}

func containsLayer(ls []LayerInfo, target LayerInfo) bool {
	for _, l := range ls {
		if l.Index == target.Index && l.DiffID == target.DiffID && l.Digest == target.Digest {
			return true
		}
	}
	return false
}

// layerTotals accumulates per-layer counts keyed by layer identity.
type layerTotals struct {
	byKey map[string]*LayerSummary
	total int
}

func newLayerTotals() *layerTotals {
	return &layerTotals{byKey: make(map[string]*LayerSummary)}
}

func layerKey(l LayerInfo) string {
	return layerIdentity(l)
}

func (t *layerTotals) add(f Finding) {
	// A finding belongs to exactly one layer: its current layer when it is
	// part of the current scan, and its previous layer only when it was
	// removed.
	var l LayerInfo
	inCurrent := f.Status != StatusRemoved
	if inCurrent {
		if f.Layer == nil {
			return
		}
		l = *f.Layer
	} else {
		if len(f.PreviousLayers) == 0 {
			return
		}
		l = f.PreviousLayers[0]
	}

	t.total++
	key := layerKey(l)
	ls, ok := t.byKey[key]
	if !ok {
		ls = &LayerSummary{
			Type:      RecordTypeLayerSummary,
			Layer:     l,
			InCurrent: inCurrent,
		}
		t.byKey[key] = ls
	}
	ls.InCurrent = ls.InCurrent || inCurrent
	ls.InPrevious = ls.InPrevious || f.Status != StatusAdded
	ls.Findings.add(f)
}

func (t *layerTotals) sorted() []LayerSummary {
	out := make([]LayerSummary, 0, len(t.byKey))
	for _, ls := range t.byKey {
		out = append(out, *ls)
	}
	sortLayerSummary(out)
	return out
}
