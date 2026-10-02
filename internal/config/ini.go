package config

import (
	"fmt"
	"iter"
	"slices"
	"strings"
)

// section is one INI section: a bracketed header and its key/value
// entries in file order. Repeated sections stay separate.
type section struct {
	name    string // as written, e.g. "Interface"
	line    int    // line number of the [header]
	entries []entry
}

type entry struct {
	key   string // as written, matched case-insensitively
	value string
	line  int
}

// parseINI splits src into [Name] headers, Key = Value pairs, blank lines,
// and # comments to end of line.
func parseINI(src []byte) ([]section, error) {
	var sections []section
	for i, raw := range strings.Split(string(src), "\n") {
		lineNo := i + 1
		line, _, _ := strings.Cut(raw, "#")
		if line = strings.TrimSpace(line); line == "" {
			continue
		}
		if line[0] == '[' {
			if !strings.HasSuffix(line, "]") {
				return nil, fmt.Errorf("line %d: malformed section header", lineNo)
			}
			name := strings.TrimSpace(line[1 : len(line)-1])
			if name == "" {
				return nil, fmt.Errorf("line %d: empty section header", lineNo)
			}
			sections = append(sections, section{name: name, line: lineNo})
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("line %d: expected Key = Value", lineNo)
		}
		if len(sections) == 0 {
			return nil, fmt.Errorf("line %d: key outside of any section", lineNo)
		}
		s := &sections[len(sections)-1]
		s.entries = append(
			s.entries,
			entry{key: strings.TrimSpace(k), value: strings.TrimSpace(v), line: lineNo},
		)
	}
	return sections, nil
}

// get returns the value and line of the single entry named key (case
// insensitive), or ok=false if absent. Duplicate keys are an error.
func (s *section) get(key string) (value string, line int, ok bool, err error) {
	for _, e := range s.entries {
		if !strings.EqualFold(e.key, key) {
			continue
		}
		if ok {
			return "", 0, false, fmt.Errorf("line %d: duplicate key %q in [%s]", e.line, e.key, s.name)
		}
		value, line, ok = e.value, e.line, true
	}
	return value, line, ok, nil
}

// values yields each comma-separated entry of every line named key (case
// insensitive) with its line number, for keys that may repeat. Address and DNS
// also accept whitespace separators. Empty comma items remain visible to
// validation.
func (s *section) values(key string) iter.Seq2[int, string] {
	return func(yield func(int, string) bool) {
		for _, e := range s.entries {
			if !strings.EqualFold(e.key, key) {
				continue
			}
			for v := range strings.SplitSeq(e.value, ",") {
				items := []string{strings.TrimSpace(v)}
				if items[0] != "" &&
					(strings.EqualFold(key, "Address") || strings.EqualFold(key, "DNS")) {
					items = strings.Fields(v)
				}
				for _, item := range items {
					if !yield(e.line, item) {
						return
					}
				}
			}
		}
	}
}

// require is get for keys that must be present and non-empty.
func (s *section) require(key string) (value string, line int, err error) {
	value, line, ok, err := s.get(key)
	if err != nil {
		return "", 0, err
	}
	if !ok || value == "" {
		return "", 0, fmt.Errorf("line %d: [%s] missing %s", s.line, s.name, key)
	}
	return value, line, nil
}

// optional hands the value of key to set when it is present, locating set's
// error by line and key.
func (s *section) optional(key string, set func(string) error) error {
	value, line, ok, err := s.get(key)
	if err != nil || !ok {
		return err
	}
	if err := set(value); err != nil {
		return fmt.Errorf("line %d: %s: %w", line, key, err)
	}
	return nil
}

// checkKnownKeys errors on any entry whose key is not in allowed, so
// unknown fields are rejected.
func (s *section) checkKnownKeys(allowed ...string) error {
	fold := func(key string) func(string) bool {
		return func(a string) bool { return strings.EqualFold(key, a) }
	}
	for _, e := range s.entries {
		if !slices.ContainsFunc(allowed, fold(e.key)) {
			return fmt.Errorf("line %d: unknown key", e.line)
		}
	}
	return nil
}
