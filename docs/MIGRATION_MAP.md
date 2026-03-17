# Secretr-v2 to Velocity Migration Map

## Source to Target

- `/Users/sujit/Sites/secretr-v2/internal/*` -> `internal/secretr/*`
- `/Users/sujit/Sites/secretr-v2/cmd/secretr/main.go` -> `cmd/secretr/main.go`
- `/Users/sujit/Sites/secretr-v2/gui/*` -> `internal/secretr/gui/*`
- `/Users/sujit/Sites/secretr-v2/examples/*` -> `internal/secretr/examples/*`
- `/Users/sujit/Sites/secretr-v2/scripts/*` -> `internal/secretr/scripts/*`
- `/Users/sujit/Sites/secretr-v2/README.md` -> `internal/secretr/README.md`
- `/Users/sujit/Sites/secretr-v2/USECASES.md` -> `internal/secretr/USECASES.md`

## Runtime Binaries

- Existing Velocity CLI remains: `cmd/velocity`
- New Secretr-compatible CLI added: `cmd/secretr`

## Import Path Rule

All migrated internal references use:

- `github.com/oarkflow/velocity/internal/secretr/...`

No imports should remain pointing to `github.com/oarkflow/secretr/internal/...`.

## Compatibility Intent

- Preserve Secretr command groups and flags.
- Preserve Secretr API route shape (`/api/v1/*`, `/health`, `/ready`).
- Reuse existing Velocity CLI command wrappers where Secretr integrates Velocity primitives.

