# secrets_and_crypto

Demonstrates Velocity v2's secrets surface (`api.SecretService`) — set,
get, versioning, rotate, delete — plus using the underlying
`CryptoProvider` (XChaCha20-Poly1305) directly to encrypt/decrypt a
payload and prove the AEAD authentication tag is actually checked (a
wrong AAD is rejected, not silently accepted).

## Run

```sh
go run ./examples/secrets_and_crypto
```

Uses a temp directory for storage and a fixed 32-byte demo encryption
key (real deployments must load a real key from an environment variable,
KMS, or secret manager — never hardcode one). Cleaned up automatically on
exit.
