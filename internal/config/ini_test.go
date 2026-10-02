package config

import (
	"reflect"
	"strings"
	"testing"
)

// TestINI covers the reader, which deliberately rejects duplicate scalar keys
// and empty list items.
func TestINI(t *testing.T) {
	sections, err := parseINI([]byte("# comment\r\n [ Interface ] # header\r\n Key = a=b== # tail\r\n\r\n[Peer]\n[Peer]"))
	if err != nil {
		t.Fatal(err)
	}
	want := []section{
		{name: "Interface", line: 2, entries: []entry{{key: "Key", value: "a=b==", line: 3}}},
		{name: "Peer", line: 5},
		{name: "Peer", line: 6},
	}
	if !reflect.DeepEqual(sections, want) {
		t.Fatalf("got %#v, want %#v", sections, want)
	}
	value, line, ok, err := sections[0].get("kEy")
	if value != "a=b==" || line != 3 || !ok || err != nil {
		t.Fatalf("get: %q %d %v %v", value, line, ok, err)
	}
	if _, _, ok, err := sections[0].get("absent"); ok || err != nil {
		t.Fatalf("absent: %v %v", ok, err)
	}
}

func TestINIErrors(t *testing.T) {
	for _, tt := range []struct{ src, want string }{
		{"\n[", "line 2: malformed section header"},
		{"[]", "line 1: empty section header"},
		{"[Peer]\nkey", "line 2: expected Key = Value"},
		{"key=value", "line 1: key outside of any section"},
		{"; comment", "line 1: expected Key = Value"},
	} {
		t.Run(tt.src, func(t *testing.T) {
			_, err := parseINI([]byte(tt.src))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("got %v, want %q", err, tt.want)
			}
		})
	}
}

func TestINIValidation(t *testing.T) {
	for _, tt := range []struct{ src, key, want string }{
		{"Key=a\nKEY=b", "key", "line 3: duplicate key"},
		{"", "Key", "line 1: [Peer] missing Key"},
		{"Key=", "Key", "line 1: [Peer] missing Key"},
	} {
		t.Run(tt.src, func(t *testing.T) {
			ss, err := parseINI([]byte("[Peer]\n" + tt.src))
			if err != nil {
				t.Fatal(err)
			}
			_, _, err = ss[0].require(tt.key)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("got %v, want %q", err, tt.want)
			}
		})
	}
	ss, err := parseINI([]byte("[Peer]\nUnknown=1"))
	if err != nil {
		t.Fatal(err)
	}
	if err = ss[0].checkKnownKeys("PublicKey"); err == nil || !strings.Contains(err.Error(), "unknown key") {
		t.Fatalf("got %v, want unknown key", err)
	}
	ss, err = parseINI([]byte("[Peer]\npublickey=x"))
	if err != nil {
		t.Fatal(err)
	}
	if err = ss[0].checkKnownKeys("PublicKey"); err != nil {
		t.Fatal(err)
	}
	if value, line, err := ss[0].require("PublicKey"); value != "x" || line != 2 || err != nil {
		t.Fatalf("require: %q %d %v", value, line, err)
	}
}

func TestINIValues(t *testing.T) {
	for _, name := range []string{"aDdReSs", "DNS", "AllowedIPs", "AllowIn"} {
		ss, err := parseINI([]byte("[Interface]\n" + name + "=a b, ,c\n" + name + "=d\n"))
		if err != nil {
			t.Fatal(err)
		}
		var got []entry
		for line, value := range ss[0].values(name) {
			got = append(got, entry{value: value, line: line})
		}
		want := []entry{
			{value: "a b", line: 2},
			{value: "", line: 2},
			{value: "c", line: 2},
			{value: "d", line: 3},
		}
		if name == "aDdReSs" || name == "DNS" {
			want = append([]entry{{value: "a", line: 2}, {value: "b", line: 2}}, want[1:]...)
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("%s: got %v, want %v", name, got, want)
		}
		count := 0
		for range ss[0].values(name) {
			count++
			break
		}
		if count != 1 {
			t.Fatal(count)
		}
	}
}
