package store

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/xerrors"
)

// Delta file format
//
// A delta is a single self-describing file:
//
//	magic "TRVDBDLT" (8 bytes)
//	uint32 big-endian header length
//	header JSON
//	payload: the concatenated bytes of all new blobs, in entry order
//
// The header records the base digest, the full manifest of the resulting
// version, and per-file recipes made of "copy from base at offset" and "copy
// the next payload blob" entries. Applying a delta never trusts the result:
// every reconstructed file is hashed and compared with the header before it is
// installed.
const (
	deltaMagic      = "TRVDBDLT"
	deltaFormat     = 1
	deltaChunkID    = "gear-cdc"
	deltaMinSize    = 2 * 1024
	deltaMaxSize    = 64 * 1024
	deltaMaskBits   = 13 // target average chunk size 8 KiB
	deltaMaxHeaderC = 64 << 20
)

// ErrDeltaBaseMismatch indicates that the delta was built for a different base
// version than the one available locally.
var ErrDeltaBaseMismatch = errors.New("delta base mismatch")

type deltaHeader struct {
	Format      int         `json:"format"`
	BaseVersion string      `json:"base_version"`
	BaseDigest  string      `json:"base_digest"`
	BaseSchema  int         `json:"base_schema"`
	Chunking    string      `json:"chunking"`
	Result      Manifest    `json:"result"`
	Files       []deltaFile `json:"files"`
	PayloadSize int64       `json:"payload_size"`
	PayloadSum  string      `json:"payload_digest"`
}

type deltaFile struct {
	Name    string       `json:"name"`
	Size    int64        `json:"size"`
	Digest  string       `json:"digest"`
	Entries []deltaEntry `json:"entries"`
}

// deltaEntry is one piece of an output file. Exactly one of the base range and
// the payload blob is meaningful.
type deltaEntry struct {
	// BaseOffset/BaseLength copy a range from the same-named file in the base
	// version.
	BaseOffset int64 `json:"base_offset,omitempty"`
	BaseLength int64 `json:"base_length,omitempty"`
	// Blob is the digest of the new bytes, which follow in the payload.
	Blob       string `json:"blob,omitempty"`
	BlobLength int64  `json:"blob_length,omitempty"`
}

// CreateDelta builds a delta transforming the version in baseDir into the
// version in targetDir, writing it to w. Both directories must contain
// trivy.db (and optionally metadata.json). The delta can only be applied to the
// exact base content it was built from.
func CreateDelta(baseDir, targetDir string, w io.Writer) (int64, error) {
	baseManifest, err := manifestFromDir(baseDir, InstallOptions{})
	if err != nil {
		return 0, xerrors.Errorf("invalid base directory: %w", err)
	}
	targetManifest, err := manifestFromDir(targetDir, InstallOptions{})
	if err != nil {
		return 0, xerrors.Errorf("invalid target directory: %w", err)
	}
	// The activation time is assigned locally when the delta is applied, so
	// that building the same delta twice yields identical bytes.
	baseManifest.CreatedAt = time.Time{}
	targetManifest.CreatedAt = time.Time{}

	h := deltaHeader{
		Format:      deltaFormat,
		BaseVersion: baseManifest.Version,
		BaseDigest:  baseManifest.DBDigest,
		BaseSchema:  baseManifest.SchemaVersion,
		Chunking:    deltaChunkID,
		Result:      targetManifest,
	}

	var payload bytes.Buffer
	for _, tf := range targetManifest.Files {
		newData, err := os.ReadFile(filepath.Join(targetDir, tf.Name))
		if err != nil {
			return 0, xerrors.Errorf("failed to read %s: %w", tf.Name, err)
		}

		var baseData []byte
		if bf, ok := baseManifest.file(tf.Name); ok {
			baseData, err = os.ReadFile(filepath.Join(baseDir, bf.Name))
			if err != nil {
				return 0, xerrors.Errorf("failed to read base %s: %w", bf.Name, err)
			}
		}

		baseIndex := chunkIndex(baseData)
		df := deltaFile{Name: tf.Name, Size: tf.Size, Digest: tf.Digest}
		forEachChunk(newData, func(chunk []byte) {
			sum := digestBytes(chunk)
			if offsets, ok := baseIndex[sum]; ok && len(offsets) > 0 {
				df.Entries = append(df.Entries, deltaEntry{
					BaseOffset: offsets[0],
					BaseLength: int64(len(chunk)),
				})
				return
			}
			df.Entries = append(df.Entries, deltaEntry{
				Blob:       sum,
				BlobLength: int64(len(chunk)),
			})
			payload.Write(chunk)
		})
		h.Files = append(h.Files, df)
	}

	h.PayloadSize = int64(payload.Len())
	h.PayloadSum = digestBytes(payload.Bytes())

	hb, err := json.Marshal(h)
	if err != nil {
		return 0, xerrors.Errorf("failed to encode delta header: %w", err)
	}

	var out bytes.Buffer
	out.WriteString(deltaMagic)
	if err = binary.Write(&out, binary.BigEndian, uint32(len(hb))); err != nil {
		return 0, xerrors.Errorf("failed to encode delta header length: %w", err)
	}
	out.Write(hb)
	out.Write(payload.Bytes())

	n, err := w.Write(out.Bytes())
	if err != nil {
		return int64(n), xerrors.Errorf("failed to write delta: %w", err)
	}
	return int64(n), nil
}

// applyDelta reconstructs the target version from baseDir into dstDir.
func applyDelta(baseDir, dstDir string, r io.Reader, tmpDir string) (err error) {
	h, payload, cleanup, err := readDelta(r, tmpDir)
	if err != nil {
		return err
	}
	defer cleanup()

	// Check the base before touching anything.
	baseManifest, err := readManifest(filepath.Join(baseDir, manifestFile))
	if err != nil {
		return versionMismatch("delta base manifest is missing or unreadable")
	}
	if baseManifest.DBDigest != h.BaseDigest {
		return &Error{
			Kind:     KindVersionMismatch,
			Msg:      fmt.Sprintf("delta was built for base %s but the local base is %s", h.BaseDigest, baseManifest.DBDigest),
			Expected: h.BaseDigest,
			Actual:   baseManifest.DBDigest,
			Err:      ErrDeltaBaseMismatch,
		}
	}

	for _, df := range h.Files {
		if err = reconstructFile(baseDir, dstDir, df, payload); err != nil {
			return err
		}
	}
	// Verify the reconstructed directory against the manifest recorded in the
	// delta. This is the byte-for-byte guarantee.
	if err = verifyDir(dstDir, h.Result); err != nil {
		return wrapKind(KindIntegrity, err,
			"the reconstructed database does not match the expected version %q; refusing to install", h.Result.Version)
	}
	// Persist the manifest so that the staging directory is a complete version
	// ready to be moved into place.
	return writeManifest(dstDir, h.Result)
}

func reconstructFile(baseDir, dstDir string, df deltaFile, payload io.Reader) error {
	dst := filepath.Join(dstDir, df.Name)
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return xerrors.Errorf("failed to create %s: %w", df.Name, err)
	}
	defer out.Close()

	var base *os.File
	defer func() {
		if base != nil {
			_ = base.Close()
		}
	}()

	var written int64
	for _, e := range df.Entries {
		if e.Blob != "" {
			n, err := io.CopyN(out, payload, e.BlobLength)
			if err != nil {
				return wrapKind(KindIntegrity, err,
					"delta payload is truncated or corrupt while rebuilding %s", df.Name)
			}
			written += n
			continue
		}

		if base == nil {
			base, err = os.Open(filepath.Join(baseDir, df.Name))
			if err != nil {
				return xerrors.Errorf("failed to open base %s: %w", df.Name, err)
			}
		}
		sr := io.NewSectionReader(base, e.BaseOffset, e.BaseLength)
		n, err := io.Copy(out, sr)
		if err != nil {
			return xerrors.Errorf("failed to copy base range for %s: %w", df.Name, err)
		}
		if n != e.BaseLength {
			return integrityError(df.Digest, "",
				"base range for %s is shorter than expected", df.Name)
		}
		written += n
	}

	if err = out.Sync(); err != nil {
		return xerrors.Errorf("failed to sync %s: %w", df.Name, err)
	}
	if err = out.Close(); err != nil {
		return xerrors.Errorf("failed to close %s: %w", df.Name, err)
	}
	if written != df.Size {
		return integrityError(df.Digest, "",
			"rebuilt %s has an unexpected size: expected %d, got %d", df.Name, df.Size, written)
	}
	return nil
}

// readDelta parses the header and spools the payload to a temp file so that a
// large database delta does not need to fit in memory. The returned reader is
// positioned at the start of the payload; the caller must invoke cleanup.
func readDelta(r io.Reader, tmpDir string) (deltaHeader, io.Reader, func(), error) {
	var h deltaHeader
	noop := func() {}

	magic := make([]byte, len(deltaMagic))
	if _, err := io.ReadFull(r, magic); err != nil {
		return h, nil, noop, wrapKind(KindInvalid, err, "delta file is truncated")
	}
	if string(magic) != deltaMagic {
		return h, nil, noop, invalid("not a Trivy database delta file")
	}
	var hlen uint32
	if err := binary.Read(r, binary.BigEndian, &hlen); err != nil {
		return h, nil, noop, wrapKind(KindInvalid, err, "delta file is truncated")
	}
	if hlen == 0 || hlen > deltaMaxHeaderC {
		return h, nil, noop, invalid("delta header length %d is out of range", hlen)
	}
	hb := make([]byte, hlen)
	if _, err := io.ReadFull(r, hb); err != nil {
		return h, nil, noop, wrapKind(KindInvalid, err, "delta header is truncated")
	}
	if err := json.Unmarshal(hb, &h); err != nil {
		return h, nil, noop, wrapKind(KindInvalid, err, "delta header is corrupt")
	}
	if h.Format != deltaFormat {
		return h, nil, noop, invalid("unsupported delta format %d", h.Format)
	}
	if h.PayloadSize < 0 {
		return h, nil, noop, invalid("negative delta payload size")
	}
	if err := h.Result.validate(); err != nil {
		return h, nil, noop, err
	}

	tmp, err := os.CreateTemp(tmpDir, ".delta-payload-*")
	if err != nil {
		return h, nil, noop, xerrors.Errorf("failed to create delta payload file: %w", err)
	}
	cleanup := func() {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
	}

	hash := sha256.New()
	n, err := io.Copy(io.MultiWriter(tmp, hash), io.LimitReader(r, h.PayloadSize+1))
	if err != nil {
		cleanup()
		return h, nil, noop, wrapKind(KindInterrupted, err, "failed to read delta payload")
	}
	if n != h.PayloadSize {
		cleanup()
		return h, nil, noop, integrityError(h.PayloadSum, "",
			"delta payload is incomplete: expected %d bytes, got %d", h.PayloadSize, n)
	}
	got := DigestPrefix + hex.EncodeToString(hash.Sum(nil))
	if got != h.PayloadSum {
		cleanup()
		return h, nil, noop, integrityError(h.PayloadSum, got, "delta payload digest mismatch")
	}
	if _, err = tmp.Seek(0, io.SeekStart); err != nil {
		cleanup()
		return h, nil, noop, xerrors.Errorf("failed to rewind delta payload: %w", err)
	}
	return h, tmp, cleanup, nil
}

// forEachChunk splits data into content-defined chunks.
func forEachChunk(data []byte, fn func([]byte)) {
	const mask = uint64(1<<deltaMaskBits) - 1
	for len(data) > 0 {
		if len(data) <= deltaMinSize {
			fn(data)
			return
		}
		end := deltaMinSize
		var hash uint64
		limit := len(data)
		if limit > deltaMaxSize {
			limit = deltaMaxSize
		}
		for end < limit {
			hash = (hash << 1) + gearTable[data[end]]
			end++
			if hash&mask == 0 {
				break
			}
		}
		fn(data[:end])
		data = data[end:]
	}
}

// chunkIndex maps a chunk digest to the offsets where it occurs in base.
func chunkIndex(base []byte) map[string][]int64 {
	index := make(map[string][]int64)
	var off int64
	forEachChunk(base, func(chunk []byte) {
		sum := digestBytes(chunk)
		index[sum] = append(index[sum], off)
		off += int64(len(chunk))
	})
	return index
}

// gearTable is a fixed, deterministically generated table so that producer and
// consumer agree without exchanging data.
var gearTable = newGearTable()

func newGearTable() [256]uint64 {
	var t [256]uint64
	x := uint64(0x9e3779b97f4a7c15)
	for i := range t {
		x += 0x9e3779b97f4a7c15
		z := x
		z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9
		z = (z ^ (z >> 27)) * 0x94d049bb133111eb
		z ^= z >> 31
		t[i] = z
	}
	return t
}
