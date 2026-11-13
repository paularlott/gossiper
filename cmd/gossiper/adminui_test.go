package main

import (
	"path/filepath"
	"testing"
)

// The status page is on by default; the flag, the environment and the config file turn it off.
func TestAdminUISetting(t *testing.T) {
	none := filepath.Join(t.TempDir(), "none.toml")
	if s := parse(t, "--config", none); !s.AdminUI {
		t.Error("admin-ui is off by default")
	}
	if s := parse(t, "--config", none, "--admin-ui=false"); s.AdminUI {
		t.Error("--admin-ui=false left it on")
	}
	if s := parse(t, "--config", writeConfig(t, "admin_ui = false")); s.AdminUI {
		t.Error("admin_ui = false left it on")
	}
	t.Setenv("GOSSIPER_ADMIN_UI", "false")
	if s := parse(t, "--config", none); s.AdminUI {
		t.Error("GOSSIPER_ADMIN_UI=false left it on")
	}
}
