package config

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// A secret reference is the entire scalar: ${env:NAME} or ${file:PATH}.
var secretRef = regexp.MustCompile(`^\$\{(env|file):([^}]*)\}$`)

func resolveNode(n *yaml.Node, path string, secrets *secretSet, warnings *[]Warning) error {
	if n == nil {
		return nil
	}
	switch n.Kind {
	case yaml.DocumentNode:
		for _, c := range n.Content {
			if err := resolveNode(c, path, secrets, warnings); err != nil {
				return err
			}
		}
		return nil
	case yaml.MappingNode:
		if len(n.Content)%2 != 0 {
			return fmt.Errorf("parse config: invalid mapping at %s", pathLabel(path))
		}
		for i := 0; i < len(n.Content); i += 2 {
			key := n.Content[i].Value
			child := key
			if path != "" {
				child = path + "." + key
			}
			if err := resolveNode(n.Content[i+1], child, secrets, warnings); err != nil {
				return err
			}
		}
		return nil
	case yaml.SequenceNode:
		for i, c := range n.Content {
			child := fmt.Sprintf("%s[%d]", path, i)
			if err := resolveNode(c, child, secrets, warnings); err != nil {
				return err
			}
		}
		return nil
	case yaml.ScalarNode:
		return resolveScalar(n, path, secrets, warnings)
	case yaml.AliasNode:
		return fmt.Errorf("parse config: aliases are not supported")
	default:
		return fmt.Errorf("parse config: unsupported node at %s", pathLabel(path))
	}
}

func resolveScalar(n *yaml.Node, path string, secrets *secretSet, warnings *[]Warning) error {
	if n.Tag != "" && n.Tag != "!!str" && n.Tag != "!" {
		if strings.Contains(n.Value, "${") {
			return fmt.Errorf("malformed secret reference at %s", pathLabel(path))
		}
		return nil
	}
	if !strings.Contains(n.Value, "${") {
		return nil
	}
	m := secretRef.FindStringSubmatch(n.Value)
	if m == nil {
		return fmt.Errorf("malformed secret reference at %s", pathLabel(path))
	}
	kind, arg := m[1], strings.TrimSpace(m[2])
	if arg == "" {
		return fmt.Errorf("malformed secret reference at %s", pathLabel(path))
	}
	value, err := resolveRef(kind, arg, warnings)
	if err != nil {
		return err
	}
	n.Tag = "!!str"
	n.Value = value
	secrets.add(path, value)
	return nil
}

func resolveRef(kind, arg string, warnings *[]Warning) (string, error) {
	switch kind {
	case "env":
		v, ok := os.LookupEnv(arg)
		if !ok || v == "" {
			return "", fmt.Errorf("secret env:%s missing", arg)
		}
		return v, nil
	case "file":
		info, err := os.Stat(arg)
		if err != nil {
			return "", fmt.Errorf("secret file:%s missing", arg)
		}
		if info.Mode().Perm()&0o004 != 0 {
			*warnings = append(*warnings, Warning{Message: "secret file world-readable: " + arg})
		}
		b, err := os.ReadFile(arg)
		if err != nil {
			return "", fmt.Errorf("secret file:%s missing", arg)
		}
		v := strings.TrimSpace(string(b))
		if v == "" {
			return "", fmt.Errorf("secret file:%s missing", arg)
		}
		return v, nil
	default:
		return "", fmt.Errorf("malformed secret reference")
	}
}

func pathLabel(path string) string {
	if path == "" {
		return "root"
	}
	return path
}
