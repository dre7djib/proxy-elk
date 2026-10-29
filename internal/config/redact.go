package config

import (
	"fmt"
	"reflect"
	"sort"
	"strings"
)

const redacted = "***"

// Redacted returns a copy safe to log: every resolved secret is replaced with ***.
func (c *Config) Redacted() Config {
	if c == nil {
		return Config{}
	}
	out := *c
	out.secrets = secretSet{}
	redactStrings(reflect.ValueOf(&out).Elem(), "", c.secrets.paths)
	return out
}

// Mask replaces known secret values in s. Used by logs and audit.
func (c *Config) Mask(s string) string {
	if c == nil || len(c.secrets.values) == 0 {
		return s
	}
	vals := append([]string(nil), c.secrets.values...)
	sort.Slice(vals, func(i, j int) bool { return len(vals[i]) > len(vals[j]) })
	for _, secret := range vals {
		if secret == "" {
			continue
		}
		s = strings.ReplaceAll(s, secret, redacted)
	}
	return s
}

func redactStrings(v reflect.Value, path string, paths map[string]struct{}) {
	switch v.Kind() {
	case reflect.Pointer:
		if v.IsNil() {
			return
		}
		redactStrings(v.Elem(), path, paths)
	case reflect.Struct:
		t := v.Type()
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			if !f.IsExported() {
				continue
			}
			name := strings.Split(f.Tag.Get("yaml"), ",")[0]
			if name == "" || name == "-" {
				continue
			}
			child := name
			if path != "" {
				child = path + "." + name
			}
			redactStrings(v.Field(i), child, paths)
		}
	case reflect.Slice, reflect.Array:
		for i := 0; i < v.Len(); i++ {
			redactStrings(v.Index(i), fmt.Sprintf("%s[%d]", path, i), paths)
		}
	case reflect.String:
		if _, ok := paths[path]; ok {
			v.SetString(redacted)
		}
	}
}
