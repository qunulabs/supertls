package supertls

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// allowedModules is the whole set of modules go.mod may name, direct or
// indirect. Every entry is one a consumer inherits, so widening this list is a
// decision about every consumer's build, never a convenience.
var allowedModules = map[string]bool{
	"google.golang.org/grpc":                    true,
	"google.golang.org/protobuf":                true,
	"golang.org/x/net":                          true,
	"golang.org/x/sys":                          true,
	"golang.org/x/text":                         true,
	"google.golang.org/genproto/googleapis/rpc": true,
}

func readGoMod(t *testing.T) []string {
	t.Helper()
	data, err := os.ReadFile("go.mod")
	if err != nil {
		t.Fatalf("read go.mod: %v", err)
	}
	var lines []string
	for _, line := range strings.Split(string(data), "\n") {
		lines = append(lines, strings.TrimSpace(line))
	}
	return lines
}

// TestOnlyAllowedDependencies keeps the module graph a consumer inherits down
// to the transport and its own dependencies.
func TestOnlyAllowedDependencies(t *testing.T) {
	inBlock := false
	for _, line := range readGoMod(t) {
		switch {
		case line == "require (":
			inBlock = true
			continue
		case line == ")":
			inBlock = false
			continue
		case line == "" || strings.HasPrefix(line, "//"):
			continue
		}
		var entry string
		switch {
		case inBlock:
			entry = line
		case strings.HasPrefix(line, "require "):
			entry = strings.TrimPrefix(line, "require ")
		default:
			continue
		}
		fields := strings.Fields(entry)
		if len(fields) == 0 {
			continue
		}
		if !allowedModules[fields[0]] {
			t.Errorf("unexpected dependency in go.mod: %q", line)
		}
	}
}

// TestGRPCFloorIsPinned guards the one version every consumer is forced to.
func TestGRPCFloorIsPinned(t *testing.T) {
	for _, line := range readGoMod(t) {
		line = strings.TrimPrefix(line, "require ")
		if line == "google.golang.org/grpc v1.81.1" {
			return
		}
	}
	t.Error("go.mod must require exactly google.golang.org/grpc v1.81.1: " +
		"this is the minimum version of gRPC every program that imports " +
		"supertls is forced to, so raising it raises every consumer's floor; " +
		"change it only as a deliberate, released decision")
}

// TestGoDirectiveIsTheFloor keeps the language floor where the module claims it
// and stops a tool from quietly pinning a toolchain on every consumer.
func TestGoDirectiveIsTheFloor(t *testing.T) {
	found := false
	for _, line := range readGoMod(t) {
		if strings.HasPrefix(line, "toolchain") {
			t.Errorf("go.mod must not carry a toolchain line: %q", line)
		}
		if strings.HasPrefix(line, "go ") {
			found = true
			if line != "go 1.25" && line != "go 1.25.0" {
				t.Errorf("go directive must be go 1.25 or go 1.25.0, got %q", line)
			}
		}
	}
	if !found {
		t.Error("go.mod has no go directive")
	}
}

// TestNoDashes keeps the em dash and en dash out of the repository in every
// spelling: raw bytes, HTML entities and backslash-u escapes. The needles are
// built by concatenation so this file does not match itself.
func TestNoDashes(t *testing.T) {
	needles := [][]byte{
		[]byte("\xe2\x80\x94"),
		[]byte("\xe2\x80\x93"),
		[]byte("&" + "mdash;"),
		[]byte("&" + "ndash;"),
		[]byte("\\" + "u2014"),
		[]byte("\\" + "u2013"),
	}
	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			// .superpowers is the gitignored scratch workspace, not the repository.
			if d.Name() == ".git" || d.Name() == ".superpowers" {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for i, line := range bytes.Split(data, []byte("\n")) {
			for _, n := range needles {
				if bytes.Contains(line, n) {
					t.Errorf("%s:%d contains a banned dash spelling %q", path, i+1, n)
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk repository: %v", err)
	}
}
