package config

import (
	"fmt"
	"os"
	"path/filepath"
)

// Dir holds NAME.conf files.
var Dir = filepath.Join(os.Getenv("ProgramData"), "Headwire")

// Private reports a mode fit for key material. Go exposes no Windows ACL in
// a FileMode, so every file passes.
func Private(os.FileMode) bool { return true }

// checkDir requires Dir to be a directory, with the ACL unchecked as in
// Private.
func checkDir(fi os.FileInfo) error {
	if !fi.IsDir() {
		return fmt.Errorf("%s: must be a directory", Dir)
	}
	return nil
}

// warnAccess reports nothing, for the reason Private gives.
func warnAccess(string, os.FileInfo, func(string)) {}
