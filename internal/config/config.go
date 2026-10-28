package config

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/s41r4j/cybot/internal/policy"
	"gopkg.in/yaml.v3"
)

type Config struct {
	DataDir string        `yaml:"data_dir"`
	Policy  policy.Config `yaml:"policy"`
	Packs   PackConfig    `yaml:"packs"`
}

type PackConfig struct {
	UpdateInterval time.Duration `yaml:"update_interval"`
	AutoUpdate     bool          `yaml:"auto_update"`
	UpdateTimeout  time.Duration `yaml:"update_timeout"`
}

func Default() Config {
	return Config{
		DataDir: ".cybot",
		Packs:   PackConfig{UpdateInterval: 24 * time.Hour, AutoUpdate: true, UpdateTimeout: 45 * time.Second},
		Policy: policy.Config{
			AllowedTargets:      []string{"*"},
			BlockedTargets:      []string{},
			ApprovalRequired:    false,
			Concurrency:         1,
			Timeout:             30 * time.Minute,
			MaxRate:             100,
			AllowedCapabilities: []string{"*"},
			EnforcementMode:     "suggestive",
		},
	}
}

func Load(path string) (Config, error) {
	c := Default()
	if path == "" {
		return c, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return c, fmt.Errorf("read config %q: %w", path, err)
	}
	decoder := yaml.NewDecoder(bytes.NewReader(b))
	decoder.KnownFields(true)
	if err = decoder.Decode(&c); err != nil {
		return c, err
	}
	if c.DataDir == "" || c.Policy.Timeout <= 0 || c.Policy.Concurrency < 1 || c.Policy.MaxRate < 0 {
		return c, fmt.Errorf("data_dir, positive timeout/concurrency, and nonnegative max_rate are required")
	}
	if c.Policy.EnforcementMode != "suggestive" && c.Policy.EnforcementMode != "strict" {
		return c, fmt.Errorf("enforcement_mode must be suggestive (warnings only) or strict")
	}
	if c.Packs.UpdateInterval <= 0 {
		return c, fmt.Errorf("packs.update_interval must be positive")
	}
	if c.Packs.UpdateTimeout <= 0 {
		return c, fmt.Errorf("packs.update_timeout must be positive")
	}
	return c, nil
}

func (c Config) Prepare() (string, string, error) {
	root := c.DataDir
	if !filepath.IsAbs(root) {
		abs, err := filepath.Abs(root)
		if err != nil {
			return "", "", err
		}
		root = abs
	}
	evidence := filepath.Join(root, "evidence")
	if err := os.MkdirAll(evidence, 0700); err != nil {
		return "", "", err
	}
	return filepath.Join(root, "cybot.db"), evidence, nil
}
