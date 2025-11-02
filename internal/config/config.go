// Package config provides configuration loading and validation for ZASK.
//
// Configuration is loaded via YAML files, environment variables, and CLI
// flags (in that priority order). The package validates all settings
// against the expected schema before the daemon starts.
package config
