// Package config loads .pathwise.yaml, the project policy file.
//
// Two of the four finding kinds cannot fire without it: PathWise has no way
// to derive which column discriminates tenants or which fields a given
// endpoint is permitted to return. Rather than guessing silently, the
// unconfigured state is explicit and reported.
package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/YarKhan02/PathWise/internal/model"
)

// FileName is the conventional config file name at a project root.
const FileName = ".pathwise.yaml"

// Config is project policy. Every field is optional; an absent field disables
// the checks that depend on it.
type Config struct {
	// Framework pins the router adapter. Empty means autodetect.
	Framework string `yaml:"framework"`

	// DatabaseURL is the PostgreSQL connection URL, authoritative for schema.
	// Only used when --db is not passed. os.ExpandEnv runs on it, so a value
	// like ${DATABASE_URL} keeps the credential out of the committed file.
	DatabaseURL string `yaml:"database_url"`

	// Store is where PathWise keeps its own SQLite database, as a file path
	// relative to the project root unless absolute. Only used when --store is
	// not passed. Default: .pathwise/pathwise.db.
	Store string `yaml:"store"`

	// MigrationsDir holds golang-migrate SQL files, used for schema
	// provenance and for the degraded migrations-only mode.
	MigrationsDir string `yaml:"migrations_dir"`

	// Tenancy declares how multi-tenancy is expressed in the schema.
	Tenancy Tenancy `yaml:"tenancy"`

	// SensitiveColumns lists columns that must not appear in a response
	// outside an endpoint's declared scope, as "table.column".
	SensitiveColumns []string `yaml:"sensitive_columns"`

	// EndpointScopes declares, per normalized route, which sensitive fields
	// that endpoint is permitted to return.
	EndpointScopes []EndpointScope `yaml:"endpoint_scopes"`

	// IdentityFuncs are qualified function names that return the
	// authenticated principal, e.g. "myapp/auth.CurrentUser". Seeds the
	// identity-provenance analysis; the analyzer also detects common shapes.
	IdentityFuncs []string `yaml:"identity_funcs"`

	// AuthCheckFuncs are qualified function names to treat as authorization
	// checks even if their names do not match the built-in patterns.
	AuthCheckFuncs []string `yaml:"auth_check_funcs"`
}

// Tenancy describes the tenant discriminator.
type Tenancy struct {
	// Column is the tenant discriminator column name, e.g. "org_id".
	Column string `yaml:"column"`

	// Tables are the tables that must always be filtered by Column. Empty
	// means "every table that has a column of that name".
	Tables []string `yaml:"tables"`
}

// EndpointScope is the permitted sensitive-field set for one route.
type EndpointScope struct {
	// Endpoint is "METHOD /path", normalized on load.
	Endpoint string `yaml:"endpoint"`

	// AllowFields are sensitive columns this endpoint may return.
	AllowFields []string `yaml:"allow_fields"`
}

// Load reads config from a project root. A missing file is not an error: it
// yields a zero Config whose DisabledFindings reports what that costs.
func Load(projectRoot string) (*Config, error) {
	path := filepath.Join(projectRoot, FileName)
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return &Config{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}

	var c Config
	if err := yaml.Unmarshal(raw, &c); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	c.normalize()
	return &c, nil
}

func (c *Config) normalize() {
	// Expand env refs so credentials can stay in the environment, not the file.
	c.DatabaseURL = os.ExpandEnv(c.DatabaseURL)
	for i := range c.EndpointScopes {
		parts := strings.Fields(c.EndpointScopes[i].Endpoint)
		if len(parts) == 2 {
			c.EndpointScopes[i].Endpoint = model.RouteSubject(parts[0], parts[1])
		}
	}
}

// TenancyConfigured reports whether tenant-filter analysis can run.
func (c *Config) TenancyConfigured() bool {
	return strings.TrimSpace(c.Tenancy.Column) != ""
}

// ScopeConfigured reports whether response-scope analysis can run. It needs
// sensitive columns declared; without them there is nothing to exceed.
func (c *Config) ScopeConfigured() bool {
	return len(c.SensitiveColumns) > 0
}

// DisabledFindings lists finding kinds that cannot fire under this config,
// so the CLI can state plainly that a clean scan was a partial scan.
func (c *Config) DisabledFindings() []model.FindingKind {
	var out []model.FindingKind
	if !c.TenancyConfigured() {
		out = append(out, model.FindingMissingTenantFilter)
	}
	if !c.ScopeConfigured() {
		out = append(out, model.FindingResponseFieldExceedsScope)
	}
	return out
}

// AllowedFields returns the sensitive fields permitted for a normalized
// endpoint subject.
func (c *Config) AllowedFields(endpointSubject string) []string {
	for _, s := range c.EndpointScopes {
		if s.Endpoint == endpointSubject {
			return s.AllowFields
		}
	}
	return nil
}

// ScopeDeclared reports whether an endpoint has a declared scope. An endpoint
// with no scope entry has no scope to exceed, so response-scope analysis skips
// it — the finding is about returning a field outside a *declared* scope, not
// about every endpoint that happens to return a sensitive field.
func (c *Config) ScopeDeclared(endpointSubject string) bool {
	for _, s := range c.EndpointScopes {
		if s.Endpoint == endpointSubject {
			return true
		}
	}
	return false
}
