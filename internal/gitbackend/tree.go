package gitbackend

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
)

func profileRecordPath(index, profile string) string {
	if profile == "" {
		return recordPath(index)
	}
	return "profiles/" + profile + "/" + recordPath(index)
}

// Build Git trees directly from existing/new blob IDs. No worktree or plaintext
// filesystem paths are involved, and unchanged record objects are reused.
func (c *Client) writeTree(ctx context.Context, directory string, paths map[string]entry) (string, error) {
	files := map[string]entry{}
	dirs := map[string]map[string]entry{}
	for path, file := range paths {
		name, tail, nested := strings.Cut(path, "/")
		if name == "" || name == "." || name == ".." || strings.ContainsAny(name, "\t\r\n\x00") {
			return "", errors.New("invalid Git record path")
		}
		if !nested {
			files[name] = file
			continue
		}
		if dirs[name] == nil {
			dirs[name] = map[string]entry{}
		}
		dirs[name][tail] = file
	}
	var lines []string
	for name, file := range files {
		if dirs[name] != nil {
			return "", errors.New("conflicting Git record paths")
		}
		lines = append(lines, fmt.Sprintf("100644 blob %s\t%s\n", file.object, name))
	}
	for name, paths := range dirs {
		tree, err := c.writeTree(ctx, directory, paths)
		if err != nil {
			return "", err
		}
		lines = append(lines, fmt.Sprintf("040000 tree %s\t%s\n", tree, name))
	}
	sort.Strings(lines)
	tree, err := c.run(ctx, directory, strings.NewReader(strings.Join(lines, "")), "mktree")
	return strings.TrimSpace(string(tree)), err
}
