package authstore

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/kayushkin/llm-bridge/servicesettings"
)

// The registry gives the command what its two os.Getenv reads gave it before
// 2026-09-20: no token and a localhost callback on the listen port with nothing
// set, and the operator's values when they are.
func TestTheRegistryReadsTheSameValuesTheCommandAlwaysDid(t *testing.T) {
	unset, err := NewSettingsRegistry(8303, servicesettings.MapEnvironment(map[string]string{"HOME": "/home/someone"}))
	if err != nil {
		t.Fatal(err)
	}
	if got := unset.String(SettingBearerToken); got != "" {
		t.Errorf("token with nothing set = %q, want none", got)
	}
	if got := unset.String(SettingOAuthCallbackURL); got != "http://localhost:8303/oauth/callback" {
		t.Errorf("callback with nothing set = %q, want http://localhost:8303/oauth/callback", got)
	}
	// The default follows the --port flag, as the command's Sprintf did.
	moved, err := NewSettingsRegistry(9000, servicesettings.MapEnvironment(map[string]string{}))
	if err != nil {
		t.Fatal(err)
	}
	if got := moved.String(SettingOAuthCallbackURL); got != "http://localhost:9000/oauth/callback" {
		t.Errorf("callback with --port 9000 = %q", got)
	}

	set, err := NewSettingsRegistry(8303, servicesettings.MapEnvironment(map[string]string{
		"AUTHSTORE_TOKEN":        "a-token",
		"AUTHSTORE_CALLBACK_URL": "https://example.com/api/authstore/callback",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if set.String(SettingBearerToken) != "a-token" || set.String(SettingOAuthCallbackURL) != "https://example.com/api/authstore/callback" {
		t.Errorf("token set=%t callback=%q", set.String(SettingBearerToken) != "", set.String(SettingOAuthCallbackURL))
	}

	// A variable set to the empty string is the same as unset, as it was when
	// the command compared os.Getenv to "".
	empty, err := NewSettingsRegistry(8303, servicesettings.MapEnvironment(map[string]string{"AUTHSTORE_TOKEN": "", "AUTHSTORE_CALLBACK_URL": ""}))
	if err != nil {
		t.Fatal(err)
	}
	if empty.String(SettingBearerToken) != "" || empty.String(SettingOAuthCallbackURL) != "http://localhost:8303/oauth/callback" {
		t.Errorf("empty variables: token set=%t callback=%q", empty.String(SettingBearerToken) != "", empty.String(SettingOAuthCallbackURL))
	}
}

// AUTH_STORE_URL and AUTH_STORE_TOKEN are what callers read to find this
// service. They are not under AUTHSTORE_ and must never stop it from starting.
func TestTheRegistryRefusesAnAuthstoreVariableNobodyDeclared(t *testing.T) {
	_, err := NewSettingsRegistry(8303, servicesettings.MapEnvironment(map[string]string{"AUTHSTORE_CALLBACK": "https://example.com"}))
	if err == nil || !strings.Contains(err.Error(), "AUTHSTORE_CALLBACK is set and auth-store declares no such setting") {
		t.Fatalf("NewSettingsRegistry = %v, want a refusal naming the misspelled variable", err)
	}
	if strings.Contains(err.Error(), "https://example.com") {
		t.Errorf("the refusal quotes the variable's value: %v", err)
	}
	if _, err := NewSettingsRegistry(8303, servicesettings.MapEnvironment(map[string]string{"AUTHSTORE_TOKEN": "t", "AUTH_STORE_URL": "http://127.0.0.1:8303", "AUTH_STORE_TOKEN": "t", "PATH": "/bin"})); err != nil {
		t.Errorf("a declared variable and the callers' variables were refused: %v", err)
	}
}

// Every environment variable the service's own code reads by name is declared.
// A read that is not declared is invisible on the settings page and escapes the
// startup check.
func TestEveryEnvironmentVariableTheServiceReadsIsDeclared(t *testing.T) {
	declared := map[string]bool{}
	for _, definition := range SettingDefinitions(DefaultListenPort) {
		declared[definition.EnvironmentVariable] = true
	}
	// Read by name and not settings of this service.
	notSettings := map[string]bool{}

	filesRead := 0
	err := filepath.WalkDir(".", func(path string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return err
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			return err
		}
		filesRead++
		ast.Inspect(file, func(node ast.Node) bool {
			call, isCall := node.(*ast.CallExpr)
			if !isCall || len(call.Args) == 0 {
				return true
			}
			selector, isSelector := call.Fun.(*ast.SelectorExpr)
			if !isSelector {
				return true
			}
			packageName, isIdentifier := selector.X.(*ast.Ident)
			if !isIdentifier || packageName.Name != "os" || (selector.Sel.Name != "Getenv" && selector.Sel.Name != "LookupEnv") {
				return true
			}
			literal, isLiteral := call.Args[0].(*ast.BasicLit)
			if !isLiteral {
				t.Errorf("%s reads an environment variable whose name is computed, which no declaration can be held to", path)
				return true
			}
			name, _ := strconv.Unquote(literal.Value)
			if !declared[name] && !notSettings[name] {
				t.Errorf("%s reads %s, which SettingDefinitions does not declare", path, name)
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// The walk starts at the package directory, which is the repository root. If
	// the package moves, the walk would read nothing and pass.
	if _, err := os.Stat(filepath.Join("cmd", "auth-store", "main.go")); err != nil {
		t.Fatalf("the scan starts somewhere that is not the repository root: %v", err)
	}
	if filesRead < 3 {
		t.Fatalf("the scan read %d files; it is not looking at the service", filesRead)
	}
}
