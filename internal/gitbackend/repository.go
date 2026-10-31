package gitbackend

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/osman/sylva/internal/limits"
	"github.com/osman/sylva/internal/storage"
	"github.com/osman/sylva/internal/vault"
)

type entry struct {
	object  string
	size    int64
	profile string
}

// A view is an immutable remote commit plus lazily decoded record blobs.
// Index maps record IDs to blind indexes; neither contains secret identifiers.
type view struct {
	head      string
	directory string
	meta      *vault.Snapshot
	index     map[string]string
	files     map[string]entry
	loaded    map[string]*vault.EncryptedRecord
	dirty     map[string]*vault.EncryptedRecord
}

func emptyView(directory string) *view {
	return &view{directory: directory, meta: &vault.Snapshot{Records: []*vault.EncryptedRecord{}},
		index: map[string]string{}, files: map[string]entry{}, loaded: map[string]*vault.EncryptedRecord{}, dirty: map[string]*vault.EncryptedRecord{}}
}

// UseCommandSnapshot reuses the first live fetch until this client is closed.
// No snapshot is reused across CLI commands, and a failed fetch never reads cache.
func (c *Client) UseCommandSnapshot() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.command = true
}

func (c *Client) withView(ctx context.Context, write bool, action func(context.Context, *view) error) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, c.cfg.Timeout)
	defer cancel()
	directory, lock, err := c.repository(ctx)
	if err != nil {
		return err
	}
	defer lock.Close()
	v := c.current
	if v == nil {
		v, err = c.fetch(ctx, directory)
		if err != nil {
			return err
		}
		if v.meta.KDF != nil {
			kdf := *v.meta.KDF
			c.kdf.Store(&kdf)
		}
		if c.command {
			c.current = v
		}
	}
	if write {
		generation, _ := c.generation.Load().(string)
		if generation != v.meta.Generation {
			return storage.ErrVaultChanged
		}
		if v.meta.Revision == math.MaxInt64 {
			return errors.New("git vault revision exhausted")
		}
		v = v.copy()
	}
	if err := action(ctx, v); err != nil {
		return err
	}
	if !write {
		return nil
	}
	v.meta.Revision++
	if err := c.publish(ctx, v); err != nil {
		c.current = nil
		return err
	}
	if c.command {
		c.current = v
	}
	return nil
}

func (c *Client) repository(ctx context.Context) (string, *os.File, error) {
	root, err := filepath.Abs(c.cfg.GitCacheDir)
	if err != nil {
		return "", nil, err
	}
	if err := privateDirectory(root); err != nil {
		return "", nil, err
	}
	id := sha256.Sum256([]byte(c.cfg.GitRemote + "\x00" + c.cfg.GitBranch))
	directory := filepath.Join(root, hex.EncodeToString(id[:])+".git")
	lock, err := lockRepository(ctx, directory+".lock")
	if err != nil {
		return "", nil, err
	}
	ok := false
	defer func() {
		if !ok {
			_ = lock.Close()
		}
	}()
	if err := privateDirectory(directory); err != nil {
		return "", nil, err
	}
	if _, err := os.Stat(filepath.Join(directory, "HEAD")); errors.Is(err, os.ErrNotExist) {
		if _, err := c.run(ctx, directory, nil, "init", "--bare", "--quiet", "--template=", "--object-format=sha1", directory); err != nil {
			return "", nil, err
		}
	} else if err != nil {
		return "", nil, err
	}
	ok = true
	return directory, lock, nil
}

func privateDirectory(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("git cache directory must be private (0700), without symlinks: %s", path)
	}
	return nil
}

func (c *Client) fetch(ctx context.Context, directory string) (*view, error) {
	v := emptyView(directory)
	_, err := c.run(ctx, directory, nil, "fetch", "--quiet", "--no-tags", "--depth=1", "--", c.cfg.GitRemote, c.ref)
	if err != nil {
		if strings.Contains(err.Error(), "couldn't find remote ref "+c.ref) {
			return v, nil
		}
		return nil, err
	}
	head, err := c.run(ctx, directory, nil, "rev-parse", "--verify", "FETCH_HEAD^{commit}")
	if err != nil {
		return nil, err
	}
	v.head = strings.TrimSpace(string(head))
	raw, err := c.run(ctx, directory, nil, "ls-tree", "-r", "-l", "-z", v.head)
	if err != nil {
		return nil, err
	}
	files := map[string]entry{}
	var total int64
	for _, line := range strings.Split(strings.TrimSuffix(string(raw), "\x00"), "\x00") {
		header, path, ok := strings.Cut(line, "\t")
		fields := strings.Fields(header)
		if !ok || len(fields) != 4 || fields[0] != "100644" || fields[1] != "blob" {
			return nil, errors.New("git vault tree contains an unsupported entry")
		}
		size, err := strconv.ParseInt(fields[3], 10, 64)
		if err != nil || size < 0 || size > c.cfg.MaxVaultBytes-total {
			return nil, &limits.SizeError{Scope: "Git vault", Setting: "max_vault_bytes", Limit: c.cfg.MaxVaultBytes}
		}
		total += size
		files[path] = entry{object: fields[2], size: size}
	}
	if legacy, ok := files[snapshotFile]; ok && len(files) == 1 {
		var doc document
		if err := c.decodeBlob(ctx, directory, legacy, &doc); err != nil {
			return nil, err
		}
		if doc.Format != legacyFormat || doc.Snapshot == nil {
			return nil, errors.New("unsupported or incomplete Git vault")
		}
		if err := c.validate(doc.Snapshot); err != nil {
			return nil, err
		}
		v.replace(doc.Snapshot)
		return v, nil
	}
	metadata, ok := files[metadataFile]
	if !ok {
		return nil, errors.New("git vault requires a dedicated branch containing only vault.json and records/*.json")
	}
	var doc document
	if err := c.decodeBlob(ctx, directory, metadata, &doc); err != nil {
		return nil, err
	}
	if doc.Format != format || doc.Snapshot == nil || len(doc.Snapshot.Records) != 0 || doc.Index == nil {
		return nil, errors.New("unsupported or incomplete Git vault metadata")
	}
	doc.Snapshot.Records = []*vault.EncryptedRecord{}
	if err := c.validate(doc.Snapshot); err != nil {
		return nil, err
	}
	v.meta, v.index = doc.Snapshot, doc.Index
	delete(files, metadataFile)
	for id, index := range v.index {
		if id == "" || !validIndex(index) {
			return nil, errors.New("invalid Git vault record index")
		}
		profile := doc.Profiles[index]
		if !vault.ValidProfileID(profile) {
			return nil, errors.New("invalid Git profile ID")
		}
		path := profileRecordPath(index, profile)
		file, ok := files[path]
		if !ok || file.size > c.cfg.MaxBodyBytes {
			return nil, errors.New("missing, duplicate or oversized Git vault record")
		}
		file.profile = profile
		v.files[index] = file
		delete(files, path)
	}
	for index, profile := range doc.Profiles {
		if _, ok := v.files[index]; !ok || profile == "" {
			return nil, errors.New("invalid Git profile mapping")
		}
	}
	if len(files) != 0 {
		return nil, errors.New("git vault branch contains unrelated files")
	}
	return v, nil
}

func validIndex(index string) bool {
	decoded, err := hex.DecodeString(index)
	return err == nil && len(decoded) == 32 && index == strings.ToLower(index)
}

func recordPath(index string) string { return "records/" + index + ".json" }

func (c *Client) decodeBlob(ctx context.Context, directory string, file entry, target any) error {
	raw, err := c.run(ctx, directory, nil, "cat-file", "blob", file.object)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("decode Git vault: %w", err)
	}
	if decoder.Decode(new(any)) != io.EOF {
		return errors.New("invalid trailing Git vault data")
	}
	return nil
}

func (c *Client) record(ctx context.Context, v *view, index string) (*vault.EncryptedRecord, error) {
	if rec, ok := v.loaded[index]; ok {
		return rec, nil
	}
	file, ok := v.files[index]
	if !ok {
		return nil, storage.ErrNotFound
	}
	var rec vault.EncryptedRecord
	if err := c.decodeBlob(ctx, v.directory, file, &rec); err != nil {
		return nil, err
	}
	if rec.BlindIndex != index || v.index[rec.ID] != index || rec.ProfileID != file.profile {
		return nil, errors.New("git record does not match its index")
	}
	if err := c.validate(&vault.Snapshot{Records: []*vault.EncryptedRecord{&rec}}); err != nil {
		return nil, err
	}
	v.loaded[index] = &rec
	return &rec, nil
}

func (c *Client) snapshot(ctx context.Context, v *view) (*vault.Snapshot, error) {
	s := *v.meta
	s.Records = []*vault.EncryptedRecord{}
	for _, index := range sortedIndexes(v.index) {
		rec, err := c.record(ctx, v, index)
		if err != nil {
			return nil, err
		}
		s.Records = append(s.Records, cloneRecord(rec))
	}
	return &s, nil
}

func sortedIndexes(index map[string]string) []string {
	values := make([]string, 0, len(index))
	for _, value := range index {
		values = append(values, value)
	}
	sort.Strings(values)
	return values
}

func (v *view) copy() *view {
	copy := emptyView(v.directory)
	copy.head = v.head
	*copy.meta = *v.meta
	for id, index := range v.index {
		copy.index[id] = index
	}
	for index, file := range v.files {
		copy.files[index] = file
	}
	for index, rec := range v.loaded {
		copy.loaded[index] = rec
	}
	for index, rec := range v.dirty {
		copy.dirty[index] = rec
	}
	return copy
}

func (v *view) replace(s *vault.Snapshot) {
	meta := *s
	meta.Records = []*vault.EncryptedRecord{}
	v.meta = &meta
	v.index, v.files, v.loaded, v.dirty = map[string]string{}, map[string]entry{}, map[string]*vault.EncryptedRecord{}, map[string]*vault.EncryptedRecord{}
	for _, rec := range s.Records {
		v.index[rec.ID] = rec.BlindIndex
		v.loaded[rec.BlindIndex], v.dirty[rec.BlindIndex] = rec, rec
	}
}

// Whole-vault changes retain the same atomic commit/lease as record changes.
func (c *Client) transact(ctx context.Context, change func(*vault.Snapshot) error) (*vault.Snapshot, error) {
	snapshot := new(vault.Snapshot)
	err := c.withView(ctx, change != nil, func(ctx context.Context, v *view) error {
		loaded, err := c.snapshot(ctx, v)
		if err != nil {
			return err
		}
		*snapshot = *loaded
		if change == nil {
			return nil
		}
		if err := change(snapshot); err != nil {
			return err
		}
		if err := c.validate(snapshot); err != nil {
			return err
		}
		v.replace(snapshot)
		return nil
	})
	return snapshot, err
}

func (c *Client) publish(ctx context.Context, v *view) error {
	if err := c.validate(v.meta); err != nil {
		return err
	}
	var total int64
	for index, rec := range v.dirty {
		if !validIndex(index) {
			return errors.New("invalid Git vault blind index")
		}
		if err := c.validate(&vault.Snapshot{Records: []*vault.EncryptedRecord{rec}}); err != nil {
			return err
		}
		file, err := c.writeBlob(ctx, v.directory, rec)
		if err != nil {
			return err
		}
		file.profile = rec.ProfileID
		v.files[index] = file
	}

	profiles := map[string]string{}
	paths := map[string]entry{}
	for _, index := range sortedIndexes(v.index) {
		file, ok := v.files[index]
		if !ok {
			return errors.New("missing Git record blob")
		}
		if file.profile != "" {
			profiles[index] = file.profile
		}
		paths[profileRecordPath(index, file.profile)] = file
	}
	metadata := *v.meta
	metadata.Records = nil
	file, err := c.writeBlob(ctx, v.directory, document{Format: format, Snapshot: &metadata, Index: v.index, Profiles: profiles})
	if err != nil {
		return err
	}
	total = file.size
	for _, file := range paths {
		if file.size > c.cfg.MaxVaultBytes-total {
			return &limits.SizeError{Scope: "Git vault", Setting: "max_vault_bytes", Limit: c.cfg.MaxVaultBytes}
		}
		total += file.size
	}
	paths[metadataFile] = file
	tree, err := c.writeTree(ctx, v.directory, paths)
	if err != nil {
		return err
	}
	args := []string{"commit-tree", tree}
	if v.head != "" {
		args = append(args, "-p", v.head)
	}
	commit, err := c.run(ctx, v.directory, strings.NewReader("Update encrypted Sylva vault\n"), args...)
	if err != nil {
		return err
	}
	next := strings.TrimSpace(string(commit))
	_, err = c.run(ctx, v.directory, nil, "push", "--porcelain", "--force-with-lease="+c.ref+":"+v.head, "--", c.cfg.GitRemote, next+":"+c.ref)
	if err != nil && (strings.Contains(err.Error(), "[rejected]") || strings.Contains(err.Error(), "stale info") || strings.Contains(err.Error(), "(incorrect old value provided)") || strings.Contains(err.Error(), "(reference already exists)")) {
		return fmt.Errorf("%w: Git branch changed; fetch the latest state and retry", storage.ErrConflict)
	}
	if err != nil {
		return err
	}
	v.head = next
	v.dirty = map[string]*vault.EncryptedRecord{}
	return nil
}

func (c *Client) writeBlob(ctx context.Context, directory string, value any) (entry, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return entry{}, err
	}
	if int64(len(raw)) > c.cfg.MaxVaultBytes {
		return entry{}, &limits.SizeError{Scope: "Git vault", Setting: "max_vault_bytes", Limit: c.cfg.MaxVaultBytes}
	}
	object, err := c.run(ctx, directory, strings.NewReader(string(raw)), "hash-object", "-w", "--stdin")
	return entry{object: strings.TrimSpace(string(object)), size: int64(len(raw))}, err
}
