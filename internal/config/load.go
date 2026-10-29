package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Load reads path, resolves ${env:NAME} and ${file:PATH} references, and
// returns the configuration. A missing referenced secret is an error.
// Warnings report world-readable secret files; they do not block startup.
func Load(path string) (*Config, []Warning, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("read config: %w", err)
	}
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return nil, nil, fmt.Errorf("parse config: %w", err)
	}

	var warnings []Warning
	var secrets secretSet
	if err := resolveNode(&root, "", &secrets, &warnings); err != nil {
		return nil, nil, err
	}

	var cfg Config
	if err := root.Decode(&cfg); err != nil {
		return nil, nil, fmt.Errorf("parse config: %w", err)
	}
	if err := cfg.validate(secrets); err != nil {
		return nil, nil, err
	}
	cfg.secrets = secrets
	return &cfg, warnings, nil
}

func (c *Config) validate(secrets secretSet) error {
	if _, ok := secrets.paths["elasticsearch.api_key"]; !ok || c.Elasticsearch.APIKey == "" {
		return fmt.Errorf("elasticsearch.api_key must be ${env:NAME} or ${file:PATH}")
	}
	return nil
}
