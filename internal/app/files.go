package app

import (
	"errors"
	"fmt"
	"os"
	"strings"
)

func validateDirectoryName(name string) error {
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, `/\:`) {
		return fmt.Errorf("use a single target or agent name without path separators")
	}
	for _, c := range name {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') {
			return fmt.Errorf("name contains unsupported character %q", c)
		}
	}
	return nil
}

func ensureDirectory(path string) error {
	if info, err := os.Lstat(path); err == nil {
		if !info.IsDir() {
			return fmt.Errorf("%s is not a directory (symlinks are not followed)", path)
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return os.MkdirAll(path, 0700)
}

func writeNewFile(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, writeErr := f.Write(data)
	err = errors.Join(writeErr, f.Close())
	if err != nil {
		return errors.Join(err, os.Remove(path))
	}
	return nil
}
