# auth_stack

Demonstrates Velocity v2's auth stack: JWT issue/authenticate/authorize via
`auth-jwt` (including tamper rejection), and TOTP second-factor enrollment
and validation via `auth-mfa` (RFC 6238).

Run:

```sh
go run ./examples/auth_stack
```

Expected output: a token is issued and authenticated, a tampered token is
rejected, an admin-role principal is authorized for a `delete` action while
a viewer-role principal is denied, and a TOTP secret is enrolled and its
current 30-second code is accepted while `000000` is rejected.
