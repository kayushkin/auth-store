package main

import (
	"fmt"

	authstore "github.com/kayushkin/auth-store"
)

// Phase 3 stubs — actual import logic ships with the deploy phase.

func migrateAiauth(_ *authstore.Store, _ bool) error {
	return fmt.Errorf("aiauth import not yet implemented (Phase 3)")
}

func migrateApiauth(_ *authstore.Store, _ bool) error {
	return fmt.Errorf("apiauth import not yet implemented (Phase 3)")
}

func migrateMailstack(_ *authstore.Store, _ bool) error {
	return fmt.Errorf("mailstack import not yet implemented (Phase 3)")
}
