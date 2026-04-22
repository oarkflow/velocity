# secretr exec env demo

This demo shows how `.env` values are used by default and how `secretr exec`
overrides them at runtime from vault secrets.

## Files

- `.env` contains a placeholder:

```env
ENV_SECRET=your-32-byte-secrets-here
```

- `main.go` prints the current `ENV_SECRET` and indicates if it came from the
placeholder or a runtime override.

## Run with `.env` only

```bash
cd examples/secretr_exec_env_demo
go run .
```

Expected output includes:

```text
ENV_SECRET=your-32-byte-secrets-here
source=.env placeholder
```

## Put real secret in vault

Store a real secret value for the `clear` environment/namespace:

```bash
secretr secret set --name="ENV_SECRET" --env="clear" --value="0123456789abcdef0123456789abcdef"
```

## Run with `secretr exec`

From the demo folder:

```bash
secretr exec --ns="clear" go run .
```

Expected output includes the vault value instead of the placeholder:

```text
ENV_SECRET=0123456789abcdef0123456789abcdef
source=runtime override (e.g., secretr exec vault value)
```

Because `main.go` does not overwrite already-set environment variables when
loading `.env`, the value injected by `secretr exec` takes precedence.
