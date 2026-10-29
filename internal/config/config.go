// Package config loads YAML configuration and resolves secret references.
package config

// Config is the process configuration. Secret fields hold resolved values.
type Config struct {
	Listen        string        `yaml:"listen" json:"listen"`
	Elasticsearch Elasticsearch `yaml:"elasticsearch" json:"elasticsearch"`

	secrets secretSet
}

// Elasticsearch is the upstream cluster. APIKey comes from a secret reference.
type Elasticsearch struct {
	URL    string `yaml:"url" json:"url"`
	APIKey string `yaml:"api_key" json:"api_key"`
}

// Warning is a non-fatal configuration problem, such as a world-readable secret file.
type Warning struct {
	Message string
}

func (w Warning) String() string { return w.Message }

type secretSet struct {
	paths  map[string]struct{}
	values []string
}

func (s *secretSet) add(path, value string) {
	if s.paths == nil {
		s.paths = map[string]struct{}{}
	}
	s.paths[path] = struct{}{}
	s.values = append(s.values, value)
}
