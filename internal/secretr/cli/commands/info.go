package commands

import (
	"context"
	"os"
	"path/filepath"
	"runtime"

	"github.com/oarkflow/velocity/internal/secretr/securitymode"
	"github.com/urfave/cli/v3"
)

var (
	versionProvider = func() string { return "unknown" }
	buildProvider   = func() string { return "unknown" }
	commitProvider  = func() string { return "unknown" }
)

func SetBuildInfo(version, buildTime, gitCommit string) {
	versionProvider = func() string { return version }
	buildProvider = func() string { return buildTime }
	commitProvider = func() string { return gitCommit }
}

type infoStatus struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	BuildTime string `json:"build_time"`
	GitCommit string `json:"git_commit"`
	Mode      string `json:"mode"`
	GoVersion string `json:"go_version"`
	OS        string `json:"os"`
	Arch      string `json:"arch"`
	DataDir   string `json:"data_dir"`
	VaultPath string `json:"vault_path"`
}

func Info(ctx context.Context, cmd *cli.Command) error {
	_ = ctx
	homeDir, _ := os.UserHomeDir()
	dataDir := filepath.Join(homeDir, ".secretr")
	mode := "production"
	if securitymode.IsDevBuild() {
		mode = "development"
	}

	report := infoStatus{
		Name:      "secretr",
		Version:   versionProvider(),
		BuildTime: buildProvider(),
		GitCommit: commitProvider(),
		Mode:      mode,
		GoVersion: runtime.Version(),
		OS:        runtime.GOOS,
		Arch:      runtime.GOARCH,
		DataDir:   dataDir,
		VaultPath: filepath.Join(dataDir, "data"),
	}

	return output(cmd, report)
}
