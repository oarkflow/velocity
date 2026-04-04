package commands

import (
	"testing"
)

func TestSetBuildInfo(t *testing.T) {
	oldVersion := versionProvider
	oldBuild := buildProvider
	oldCommit := commitProvider
	defer func() {
		versionProvider = oldVersion
		buildProvider = oldBuild
		commitProvider = oldCommit
	}()

	SetBuildInfo("1.2.3", "2026-04-04T11:00:00Z", "abc123")
	if got := versionProvider(); got != "1.2.3" {
		t.Fatalf("expected version 1.2.3, got %q", got)
	}
	if got := buildProvider(); got != "2026-04-04T11:00:00Z" {
		t.Fatalf("expected build time, got %q", got)
	}
	if got := commitProvider(); got != "abc123" {
		t.Fatalf("expected commit abc123, got %q", got)
	}
}
