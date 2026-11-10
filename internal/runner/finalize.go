package runner

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// Finalize adds server artifact hashes after the operator has stopped
// all writers and placed their completed files at the configured paths.
// No network activity is performed. On failure run.json remains intact.
func Finalize(cfg Config, configPath string) error {
	path := filepath.Join(filepath.Dir(configPath), "run.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read run record: %w", err)
	}
	var rec RunRecord
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&rec); err != nil {
		return fmt.Errorf("decode run record: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("run record contains trailing data")
	}
	if rec.ExperimentID != cfg.ExperimentID || rec.QuestionID != cfg.QuestionID {
		return errors.New("run record does not match experiment and question IDs")
	}
	expectedConfig, err := filepath.Abs(rec.ConfigFile)
	if err != nil {
		return fmt.Errorf("resolve recorded config: %w", err)
	}
	actualConfig, err := filepath.Abs(configPath)
	if err != nil {
		return fmt.Errorf("resolve config: %w", err)
	}
	if rec.ConfigFile == "" || expectedConfig != actualConfig {
		return errors.New("run record does not match config path")
	}
	paths := []string{cfg.Capture.Server}
	if cfg.HelperLog != "" {
		paths = append(paths, cfg.HelperLog)
	}
	if cfg.Capture.Server == "" {
		return errors.New("server capture path is required")
	}
	seen := make(map[string]bool)
	for _, p := range []string{cfg.Capture.Client, cfg.RunnerLog, configPath, path} {
		if p != "" {
			abs, err := filepath.Abs(p)
			if err != nil {
				return fmt.Errorf("resolve artifact path: %w", err)
			}
			seen[abs] = true
		}
	}
	if rec.Artifacts == nil {
		rec.Artifacts = make(map[string]string)
	}
	type checkedFile struct {
		path string
		info os.FileInfo
	}
	var checked []checkedFile
	for _, p := range paths {
		abs, err := filepath.Abs(p)
		if err != nil {
			return fmt.Errorf("resolve artifact path: %w", err)
		}
		if seen[abs] {
			return fmt.Errorf("artifact paths overlap: %s", p)
		}
		seen[abs] = true
		sum, info, err := hashStableFile(p)
		if err != nil {
			return err
		}
		rec.Artifacts[p] = sum
		checked = append(checked, checkedFile{p, info})
	}
	for _, entry := range checked {
		current, err := os.Stat(entry.path)
		if err != nil || !sameStableFile(entry.info, current) {
			return fmt.Errorf("artifact changed while finalizing: %s", entry.path)
		}
	}
	return writeRunAtomic(path, rec)
}

func sameStableFile(a, b os.FileInfo) bool {
	return a != nil && b != nil && os.SameFile(a, b) && a.Size() == b.Size() && a.ModTime().Equal(b.ModTime())
}

func hashStableFile(path string) (string, os.FileInfo, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", nil, fmt.Errorf("open server artifact %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()
	before, err := f.Stat()
	if err != nil {
		return "", nil, fmt.Errorf("stat server artifact %s: %w", path, err)
	}
	if !before.Mode().IsRegular() {
		return "", nil, fmt.Errorf("server artifact is not a regular file: %s", path)
	}
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", nil, fmt.Errorf("hash server artifact %s: %w", path, err)
	}
	after, err := f.Stat()
	if err != nil || !sameStableFile(before, after) {
		return "", nil, fmt.Errorf("artifact changed while hashing: %s", path)
	}
	return hex.EncodeToString(h.Sum(nil)), after, nil
}

func writeRunAtomic(path string, rec RunRecord) error {
	data, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal run record: %w", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("stat run record: %w", err)
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".run-finalize-*")
	if err != nil {
		return fmt.Errorf("create temporary run record: %w", err)
	}
	tmp := f.Name()
	defer func() { _ = os.Remove(tmp) }()
	defer func() { _ = f.Close() }()
	if err := f.Chmod(info.Mode().Perm()); err != nil {
		return fmt.Errorf("set run record permissions: %w", err)
	}
	if _, err := f.Write(data); err != nil {
		return fmt.Errorf("write run record: %w", err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("sync run record: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close run record: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("replace run record: %w", err)
	}
	return nil
}
