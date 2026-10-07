// STATUS: DIAMANT VGT SUPREME
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Typed Chronos Error Hierarchy (Section 1.5.A Compliance)
type ChronosException struct {
	Message string
	Err     error
}

func (e *ChronosException) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %v", e.Message, e.Err)
	}
	return e.Message
}

func (e *ChronosException) Unwrap() error { return e.Err }

type ChronosValidationException struct{ ChronosException }
type ChronosStorageException struct{ ChronosException }

func NewChronosValidationException(msg string, err error) *ChronosValidationException {
	return &ChronosValidationException{ChronosException{Message: msg, Err: err}}
}

func NewChronosStorageException(msg string, err error) *ChronosStorageException {
	return &ChronosStorageException{ChronosException{Message: msg, Err: err}}
}

type ChronosCheckpoint struct {
	ScanID           string            `json:"scan_id"`
	Roots            []string          `json:"roots"`
	CurrentRootIndex int               `json:"current_root_index"`
	LastVisitedPath  string            `json:"last_visited_path"`
	FilesScanned     uint64            `json:"files_scanned"`
	BytesScanned     uint64            `json:"bytes_scanned"`
	FileHashes       map[string]string `json:"file_hashes"`
	MerkleRoot       string            `json:"merkle_root"`
	Phase            string            `json:"phase"` // RUNNING, PAUSED, COMPLETED
	StartedAt        time.Time         `json:"started_at"`
	UpdatedAt        time.Time         `json:"updated_at"`
}

type ChronosScanner struct {
	mu             sync.Mutex
	roots          []string
	checkpointPath string
	batchSize      int
	yieldDuration  time.Duration
	checkpoint     *ChronosCheckpoint
	storage        *StorageCipher
	policy         chronosPolicy
}

// chronosPurpose binds a sealed checkpoint to this store and node.
const chronosPurpose = "chronos-checkpoint"

func NewChronosScanner(
	roots []string,
	checkpointPath string,
	batchSize int,
	yieldDuration time.Duration,
	storage ...*StorageCipher,
) (*ChronosScanner, error) {
	if len(roots) == 0 {
		return nil, NewChronosValidationException("at least one root path must be specified", nil)
	}
	if batchSize <= 0 {
		batchSize = 100
	}
	cleanRoots := make([]string, 0, len(roots))
	for _, r := range roots {
		cleanRoots = append(cleanRoots, filepath.Clean(r))
	}
	var cipher *StorageCipher
	if len(storage) > 0 {
		cipher = storage[0]
	}

	defaults := defaultIntegrityFabricSettings(Config{}).Chronos
	return &ChronosScanner{
		roots:          cleanRoots,
		checkpointPath: filepath.Clean(checkpointPath),
		batchSize:      batchSize,
		yieldDuration:  yieldDuration,
		storage:        cipher,
		policy:         defaults.policy(),
	}, nil
}

// Encrypted reports whether the checkpoint is sealed with the storage cipher.
func (c *ChronosScanner) Encrypted() bool {
	if c == nil {
		return false
	}
	return c.storage != nil
}

// ComputeMerkleRoot builds an authenticated binary Merkle tree over sorted file hash entries.
func ComputeMerkleRoot(fileHashes map[string]string) string {
	if len(fileHashes) == 0 {
		return strings.Repeat("0", 64)
	}

	// 1. Sort canonical paths
	paths := make([]string, 0, len(fileHashes))
	for p := range fileHashes {
		paths = append(paths, p)
	}
	sort.Strings(paths)

	// 2. Hash leaf pairs: SHA256("CHRONOS_LEAF:" + path + ":" + hash)
	var currentLevel [][]byte
	for _, p := range paths {
		h := sha256.New()
		h.Write([]byte("CHRONOS_LEAF:"))
		h.Write([]byte(p))
		h.Write([]byte(":"))
		h.Write([]byte(fileHashes[p]))
		currentLevel = append(currentLevel, h.Sum(nil))
	}

	// 3. Ascend Merkle Tree levels
	for len(currentLevel) > 1 {
		var nextLevel [][]byte
		for i := 0; i < len(currentLevel); i += 2 {
			if i+1 < len(currentLevel) {
				h := sha256.New()
				h.Write([]byte("CHRONOS_NODE:"))
				h.Write(currentLevel[i])
				h.Write(currentLevel[i+1])
				nextLevel = append(nextLevel, h.Sum(nil))
			} else {
				// Odd leaf: duplicate hash to complete binary tree
				h := sha256.New()
				h.Write([]byte("CHRONOS_NODE:"))
				h.Write(currentLevel[i])
				h.Write(currentLevel[i])
				nextLevel = append(nextLevel, h.Sum(nil))
			}
		}
		currentLevel = nextLevel
	}

	return hex.EncodeToString(currentLevel[0])
}

// SaveCheckpoint serializes the current progress to atomic disk storage.
func (c *ChronosScanner) SaveCheckpoint() error {
	if c.checkpointPath == "" || c.checkpoint == nil {
		return nil
	}
	c.checkpoint.UpdatedAt = time.Now().UTC()

	data, err := json.MarshalIndent(c.checkpoint, "", "  ")
	if err != nil {
		return NewChronosStorageException("failed to marshal checkpoint", err)
	}
	// File-path digests are operational state, not public data. When a storage
	// cipher is configured the checkpoint is sealed exactly like the FIM
	// baseline, the evidence ledger and the policy document.
	if c.storage != nil {
		sealed, sealErr := c.storage.Encrypt(c.checkpointPath, chronosPurpose, 0, data)
		if sealErr != nil {
			return NewChronosStorageException("failed to seal checkpoint", sealErr)
		}
		data = sealed
	}

	// The shared atomic writer refuses a symlinked target, creates the staging
	// file exclusively and flushes file and directory, so a link planted at the
	// checkpoint path cannot redirect the write and a crash cannot leave a
	// half-written inventory.
	if err := atomicWriteFile(c.checkpointPath, data, 0o600); err != nil {
		return NewChronosStorageException("failed to persist checkpoint", err)
	}
	return nil
}

// LoadCheckpoint recovers a previously interrupted scan state.
func (c *ChronosScanner) LoadCheckpoint() (*ChronosCheckpoint, error) {
	if c.checkpointPath == "" {
		return nil, nil
	}
	data, err := os.ReadFile(c.checkpointPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, NewChronosStorageException("failed to read checkpoint file", err)
	}

	if c.storage != nil {
		plaintext, legacy, decryptErr := c.storage.Decrypt(c.checkpointPath, chronosPurpose, data, nil)
		if decryptErr != nil {
			return nil, NewChronosStorageException("checkpoint authentication failed", decryptErr)
		}
		if legacy {
			return nil, NewChronosStorageException("unencrypted Chronos checkpoint is rejected", nil)
		}
		data = plaintext
	}
	var cp ChronosCheckpoint
	if err := json.Unmarshal(data, &cp); err != nil {
		return nil, NewChronosStorageException("invalid checkpoint json format", err)
	}
	c.checkpoint = &cp
	return &cp, nil
}

// Scan processes directory trees incrementally, yielding between batches to prevent I/O starvation.
func (c *ChronosScanner) Scan(ctx context.Context, resume bool) (*ChronosCheckpoint, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now().UTC()
	if resume && c.checkpoint == nil {
		_, _ = c.LoadCheckpoint()
	}

	if c.checkpoint == nil || !resume {
		scanID := fmt.Sprintf("SCAN-%d", now.UnixNano())
		c.checkpoint = &ChronosCheckpoint{
			ScanID:           scanID,
			Roots:            c.roots,
			CurrentRootIndex: 0,
			LastVisitedPath:  "",
			FilesScanned:     0,
			BytesScanned:     0,
			FileHashes:       make(map[string]string),
			Phase:            "RUNNING",
			StartedAt:        now,
			UpdatedAt:        now,
		}
	} else {
		c.checkpoint.Phase = "RUNNING"
	}

	filesInBatch := 0
	resumedPastLast := (c.checkpoint.LastVisitedPath == "")
	policy := c.policy
	if policy.maxFiles <= 0 {
		policy = defaultIntegrityFabricSettings(Config{}).Chronos.policy()
	}
	if policy.batchSize > 0 {
		c.batchSize = policy.batchSize
	}
	if policy.yieldMillis >= 0 {
		c.yieldDuration = time.Duration(policy.yieldMillis) * time.Millisecond
	}
	bounded := false

	for rIdx := c.checkpoint.CurrentRootIndex; rIdx < len(c.roots); rIdx++ {
		root := c.roots[rIdx]
		c.checkpoint.CurrentRootIndex = rIdx

		// A checkpoint walk must be bounded. Without a file and byte budget an
		// operator-supplied root could keep the walker busy indefinitely and grow
		// the in-memory digest map without limit.
		if c.checkpoint.FilesScanned >= uint64(policy.maxFiles) || c.checkpoint.BytesScanned >= uint64(policy.maxTotalBytes) {
			bounded = true
			break
		}

		err := filepath.Walk(root, func(path string, info os.FileInfo, walkErr error) error {
			if walkErr != nil {
				return nil // Skip unreadable entries gracefully
			}
			select {
			case <-ctx.Done():
				c.checkpoint.Phase = "PAUSED"
				_ = c.SaveCheckpoint()
				return ctx.Err()
			default:
			}

			if info.IsDir() || !info.Mode().IsRegular() {
				return nil
			}
			if c.checkpoint.FilesScanned >= uint64(policy.maxFiles) || c.checkpoint.BytesScanned >= uint64(policy.maxTotalBytes) {
				bounded = true
				return filepath.SkipAll
			}

			// If resuming, skip paths until we pass the last visited path
			if !resumedPastLast {
				if path == c.checkpoint.LastVisitedPath {
					resumedPastLast = true
				}
				return nil
			}

			// Hash file contents in dedicated frame to ensure immediate descriptor release
			digest, written, hashErr := hashRegularFile(path)
			if hashErr == nil {
				c.checkpoint.FileHashes[path] = digest
				c.checkpoint.FilesScanned++
				c.checkpoint.BytesScanned += uint64(written)
				c.checkpoint.LastVisitedPath = path
			}

			filesInBatch++
			if filesInBatch >= c.batchSize {
				filesInBatch = 0
				_ = c.SaveCheckpoint()
				if c.yieldDuration > 0 {
					time.Sleep(c.yieldDuration)
				}
			}

			return nil
		})

		if err != nil {
			if ctx.Err() != nil {
				return c.checkpoint, ctx.Err()
			}
			return nil, err
		}
		if ctx.Err() != nil {
			return c.checkpoint, ctx.Err()
		}
	}

	if bounded {
		c.checkpoint.Phase = "BOUNDED"
		c.checkpoint.MerkleRoot = ComputeMerkleRoot(c.checkpoint.FileHashes)
		_ = c.SaveCheckpoint()
		return c.checkpoint, NewChronosValidationException(
			fmt.Sprintf("Chronos traversal budget exhausted after %d files and %d bytes; the digest set is partial",
				c.checkpoint.FilesScanned, c.checkpoint.BytesScanned), nil)
	}

	c.checkpoint.Phase = "COMPLETED"
	c.checkpoint.MerkleRoot = ComputeMerkleRoot(c.checkpoint.FileHashes)
	_ = c.SaveCheckpoint()

	return c.checkpoint, nil
}

// hashRegularFile hashes a single regular file, guaranteeing immediate close of the descriptor.
func hashRegularFile(path string) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()

	hasher := sha256.New()
	written, err := io.Copy(hasher, f)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(hasher.Sum(nil)), written, nil
}
