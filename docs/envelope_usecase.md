# Velocity Envelope — Secure Data Sharing for Businesses, Banks & Government

Velocity provides two complementary envelope systems designed for secure, auditable data exchange across organizational boundaries. Together they cover the full spectrum — from encrypted secret delivery between individuals to tamper-proof evidence management with legal-grade chain of custody.

---

## System 1: Cryptographic Envelope (Secretr)

End-to-end encrypted envelopes for sharing secrets, files, and messages between identities. No intermediary — not even the platform operator — can read the payload.

### How It Works

```
Sender                                          Recipient
  │                                                │
  ├─ Serialize payload (secrets + files + message) │
  ├─ Generate random 256-bit DEK                   │
  ├─ Encrypt payload with DEK (AES-256-GCM)        │
  ├─ Generate ephemeral X25519 key pair             │
  ├─ ECDH: ephemeral private × recipient public     │
  ├─ Encrypt DEK with shared secret                 │
  ├─ Pack: [ephemeral_pub(32)] [encrypted_DEK]      │
  ├─ Append genesis custody entry (signed)          │
  ├─ Sign envelope with Ed25519 private key         │
  ├─ Transmit envelope ──────────────────────────► │
  │                                                ├─ Verify envelope signature
  │                                                ├─ Verify custody chain hashes + signatures
  │                                                ├─ Validate business rules (MFA, trust, time)
  │                                                ├─ Check expiry
  │                                                ├─ ECDH: recipient private × ephemeral pub
  │                                                ├─ Decrypt DEK, then decrypt payload
  │                                                └─ Zeroize DEK from memory
```

### Cryptographic Primitives

| Purpose | Algorithm | Details |
|---|---|---|
| Payload encryption | AES-256-GCM | Random nonce prepended; authenticated encryption |
| Alternative cipher | ChaCha20-Poly1305 | Configurable per engine instance |
| Key exchange | X25519 (Curve25519 ECDH) | Ephemeral key pair per envelope for forward secrecy |
| Digital signatures | Ed25519 | Envelope-level + per-custody-entry signatures |
| Key derivation (password) | Argon2id | 3 iterations, 64 MB memory, 4 threads (OWASP) |
| Key derivation (HKDF) | HKDF-SHA256 | For deriving sub-keys from shared secrets |
| Hashing | SHA-256 / SHA-512 | Chain integrity, fingerprints, HMAC |
| Secure memory | SecureBytes | Explicit `.Free()` zeroization after use |

### Envelope Structure

```json
{
  "id": "a1b2c3...",
  "version": 1,
  "header": {
    "sender_id": "identity-abc",
    "recipient_id": "identity-xyz",
    "policy_id": "policy-001",
    "business_rules": {
      "allowed_time_windows": [{"days": [1,2,3,4,5], "start_time": "09:00", "end_time": "17:00"}],
      "allowed_ip_ranges": ["10.0.0.0/8"],
      "required_trust_level": 0.8,
      "require_mfa": true,
      "max_access_count": 5
    },
    "created_at": 1745000000000000000,
    "expires_at": 1745086400000000000
  },
  "encrypted_key": "<ephemeral_pub_32_bytes><encrypted_DEK>",
  "payload": "<AES-256-GCM encrypted EnvelopePayload>",
  "signature": "<Ed25519 signature over header + encrypted_key + payload>",
  "custody": [
    {
      "hash": "<SHA-256 chain hash>",
      "prev_hash": "<previous entry signature hash>",
      "action": "create",
      "actor_id": "identity-abc",
      "timestamp": 1745000000000000000,
      "location": "local",
      "signature": "<Ed25519 actor signature>"
    }
  ]
}
```

### Payload Types

An envelope can carry any combination of:

- **Secrets** — Named key-value pairs (`name:value`) for API keys, credentials, tokens, certificates
- **Files** — Binary file content with metadata; folders are automatically tar+gzip archived
- **Messages** — Free-text messages accompanying the delivery

### Business Rules Engine

Rules are evaluated at open time. Failure blocks decryption entirely.

| Rule | Enforcement | Description |
|---|---|---|
| `require_mfa` | Enforced | Recipient must have an MFA-verified session |
| `required_trust_level` | Enforced | Minimum trust score (0.0–1.0) required |
| `allowed_time_windows` | Enforced | Day-of-week + time range restrictions |
| `allowed_ip_ranges` | Declared | IP CIDR restrictions (ready for enforcement) |
| `max_access_count` | Declared | Maximum number of opens (ready for enforcement) |

### Signed Custody Chain

Every envelope carries a blockchain-like custody chain:

- Each entry is individually signed by the acting identity's Ed25519 private key
- Hash linkage: `SHA-256(prev_signature_hash + action + actor + timestamp + location)`
- Genesis entry uses a 32-byte zero hash
- Actions tracked: `create`, `send`, `open`, `reject`, `acl_update`
- Verification checks both hash continuity and per-actor cryptographic signatures

### CLI Commands

```bash
# Create an encrypted envelope for a recipient
secretr envelope create \
  --recipient <identity-id> \
  --secret "db_password:s3cret" \
  --secret "api_key:tok_abc123" \
  --file ./contracts/agreement.pdf \
  --file ./evidence/photos/ \
  --message "Q2 credentials rotation" \
  --expires-in 72h \
  --require-mfa \
  --output envelope.json

# Open and decrypt (recipient only)
secretr envelope open --file envelope.json

# Inspect metadata without decrypting
secretr envelope open --file envelope.json --inspect

# Verify custody chain integrity
secretr envelope verify --file envelope.json

# Tighten security (force MFA, raise trust level)
secretr envelope lock --file envelope.json

# Remove MFA requirement
secretr envelope unlock --file envelope.json

# Update access control rules
secretr envelope acl --file envelope.json \
  --allow-ip "10.0.0.0/8" \
  --require-mfa \
  --trust-level 0.9
```

### Audit Trail

Every operation emits structured audit events with `audit_family: "envelope"`:

- `envelope_create` — with file path and SHA-256 hash
- `envelope_open` / `envelope_open_denied` — with payload hash and dependency refs
- `envelope_inspect` — metadata-only access
- `envelope_verify` / `envelope_verify_failed` — chain integrity checks
- `envelope_lock` / `envelope_unlock` / `envelope_acl` — policy modifications
- `envelope_access_chain` — actor and recipient tracking
- `envelope_dependency_chain` — secret and file dependency refs
- `envelope_custody_chain` — chain length tracking
- `envelope_event_log` — event-level logging

---

## System 2: Evidence Envelope (Velocity Core)

Tamper-proof digital evidence wrappers with chain-of-custody tracking, time-lock encryption, fingerprint access control, offline AI tamper detection, and cold storage archival. Designed for legal, forensic, and regulatory use cases.

### Envelope Types

| Type | Use Case |
|---|---|
| `court_evidence` | Digital evidence for court proceedings |
| `investigation_record` | Investigation files and case documentation |
| `custody_proof` | Chain-of-custody certification |
| `cctv_forensic_archive` | CCTV footage and forensic video archives |

### Payload Kinds

| Kind | Fields | Use Case |
|---|---|---|
| `file` | `object_path`, `inline_data`, `encoding_hint`, `metadata` | Documents, videos, images |
| `kv` | `key`, `value`, `metadata` | Structured data, configuration |
| `secret` | `secret_reference`, `metadata` | References to vault-stored secrets |

### Policy Framework

#### Time-Lock Policy

Prevents access to sealed evidence until legal or temporal conditions are met.

```go
TimeLockPolicy{
    Mode:            "legal_delay",
    UnlockNotBefore: courtDate,          // Absolute date gate
    MinDelaySeconds: 7 * 24 * 3600,      // Minimum 7 days from creation
    LegalCondition:  "Court order required for early access",
    EscrowSigners:   []string{"judge@court.gov", "prosecutor@da.gov"},
}
```

Enforcement: `ApproveTimeLockUnlock()` checks both `UnlockNotBefore` and `MinDelaySeconds` from creation time. Generates a `TimeSealProof` — a SHA-256 commitment hash over payload + random salt + legal condition.

#### Fingerprint Access Control

Biometric gating for authorized personnel only.

```go
FingerprintPolicy{
    Required:               true,
    MatchingStrategy:       "threshold_90",
    AuthorizedFingerprints: []string{"fp:detective-john-doe", "fp:prosecutor-jane-smith"},
}
```

#### Tamper Detection (Offline AI)

Offline AI analyzers scan envelopes and produce tamper signals with score/threshold verdicts.

```go
TamperSignal{
    Analyzer:        "velocity-ml-v1",
    AnalyzerVersion: "1.2.3",
    Score:           0.05,    // Low = no tampering
    Threshold:       0.75,    // Above = flagged
    Offline:         true,
    Notes:           []string{"Hash chain integrity verified", "Timestamp sequence valid"},
}
```

#### Cold Storage Policy

Automated offline archival for long-term preservation.

```go
ColdStoragePolicy{
    Enabled:      true,
    StorageClass: "evidence_archive",
    Interval:     "daily",
}
```

### Dual Hash Chains

Evidence envelopes maintain two independent append-only hash chains:

**Custody Ledger** — tracks physical/digital custody transfers:
- `EventID`, `Sequence` (monotonic), `Actor`, `ActorFingerprint`
- `Action`, `Location`, `EvidenceState`, `Notes`, `Attachments`
- `PrevHash` → `EventHash` (SHA-256 chain)

**Audit Log** — tracks administrative and access actions:
- `EntryID`, `Actor`, `Action`, `Reason`, `Signature`
- `PrevHash` → `EntryHash` (SHA-256 chain)

Both chains feed into `EnvelopeIntegrity`:
- `PayloadHash` — SHA-256 digest of the sealed payload
- `LedgerRoot` — latest custody event hash
- `AuditRoot` — latest audit entry hash
- `TimeSeal` — delayed-hash commitment proof
- `LastTamperState` — most recent AI analysis result
- `ColdStorageHash` — archive integrity hash

### Lifecycle Operations

```go
// Create — seal payload, compute integrity, initialize chains
envelope, _ := db.CreateEnvelope(ctx, &EnvelopeRequest{...})

// Export — write to portable JSON file (0600 permissions), auto-log in audit + custody
db.ExportEnvelope(ctx, envelopeID, "./transfer/evidence.envelope")

// Import — load from JSON, validate, store locally, auto-log
envelope, _ := db.ImportEnvelope(ctx, "./transfer/evidence.envelope")

// Load — retrieve with automatic access logging
envelope, _ := db.LoadEnvelope(ctx, envelopeID)

// Extend custody chain
db.AppendCustodyEvent(ctx, envelopeID, &CustodyEvent{
    Actor:         "detective-doe",
    Action:        "evidence.reviewed",
    Location:      "Forensics Lab B",
    EvidenceState: "under_analysis",
})

// Record tamper analysis
db.RecordTamperSignal(ctx, envelopeID, &TamperSignal{...})

// Release time-lock (after legal approval)
db.ApproveTimeLockUnlock(ctx, envelopeID, "judge@court.gov", "Court Order #CO-2026-5678")
```

### Storage & Concurrency

- Envelopes stored as individual JSON files: `<vault>/envelopes/<envelope_id>.json`
- Atomic writes: write to temp file → fsync → rename
- Concurrent access protected by `envelopeMu` read-write mutex
- File permissions: `0600` (owner read/write only)
- Context-based actor tracking via `WithEnvelopeActor(ctx, actor)`

### Security Tests Coverage

The test suite validates against:

- Custody chain integrity across export/import round-trips
- Corruption detection via hash mismatch
- Unauthorized fingerprint rejection
- Time-lock violation prevention
- Tampered payload detection
- Broken custody chain detection
- Sequence number violation detection
- Replay attack detection (duplicate event IDs/hashes)
- Concurrent access safety
- Large payload handling (1 MB+)

---

## Use Cases by Sector

### Banking & Financial Services

**Inter-bank credential rotation**
Use cryptographic envelopes to deliver rotated API keys, HSM credentials, and certificates between institutions. The envelope expires after 72 hours, requires MFA, and the custody chain proves exactly who accessed the credentials and when — satisfying SOX and PCI-DSS audit requirements.

**Regulatory submissions**
Seal financial reports, transaction logs, and compliance documents in evidence envelopes with time-locks aligned to filing deadlines. The tamper detection layer provides regulators with cryptographic proof that submitted data hasn't been altered since creation.

**Fraud investigation evidence**
Package transaction records, account snapshots, and communication logs in `investigation_record` envelopes. The dual hash chain (custody + audit) creates an unbroken chain of evidence from the fraud analyst who flagged the case through to the legal team presenting in court.

**Secure wire transfer authorization**
Deliver wire transfer approval documents with fingerprint-gated access, ensuring only authorized signatories can view and act on high-value transfers. Time windows restrict access to business hours only.

### Government & Law Enforcement

**Digital evidence management**
CCTV footage, forensic images, and digital artifacts sealed in `court_evidence` or `cctv_forensic_archive` envelopes. Time-locks prevent premature access before court dates. Fingerprint policies restrict access to authorized investigators and prosecutors. Every access is logged in the custody ledger with location, actor, and timestamp.

**Classified document sharing**
Share classified briefings between agencies using cryptographic envelopes with X25519 forward secrecy. Each envelope is encrypted specifically for the recipient's identity — even if the transport channel is compromised, the payload remains protected. Business rules enforce trust levels and MFA.

**Cross-agency investigation coordination**
Export evidence envelopes from one agency's system, transfer via secure channel, and import into the receiving agency's system. The custody chain travels with the envelope, maintaining an unbroken record across organizational boundaries.

**Court order and warrant delivery**
Seal court orders in time-locked envelopes with escrow signers (judge + prosecutor). The `LegalCondition` field documents the legal basis, and the `TimeSealProof` provides cryptographic evidence of when the seal was created.

### Enterprise & Technology

**Secret rotation across microservices**
Deliver database credentials, API tokens, and TLS certificates to service teams via cryptographic envelopes. The envelope carries multiple secrets in a single atomic delivery, with expiry ensuring old credentials aren't reused.

**M&A due diligence rooms**
Seal financial models, IP documentation, and contracts in evidence envelopes with time-locks aligned to deal milestones. Cold storage policies ensure long-term archival. The audit log tracks exactly which parties accessed which documents and when.

**Vendor credential onboarding**
Share production credentials with new vendors using envelopes that require MFA, enforce business-hours-only access windows, and expire after the onboarding period. The custody chain provides a complete audit trail for vendor access reviews.

**Incident response evidence preservation**
During security incidents, seal logs, memory dumps, and network captures in `investigation_record` envelopes. The tamper detection layer ensures forensic integrity, and the time-lock prevents premature disclosure during active investigation.

### Healthcare & Life Sciences

**Patient record transfers**
Share medical records between institutions using cryptographic envelopes. The recipient-specific encryption ensures HIPAA compliance, while the custody chain documents every access for audit purposes.

**Clinical trial data submission**
Seal trial results in evidence envelopes with time-locks aligned to regulatory submission windows. The `TimeSealProof` provides cryptographic evidence that data existed at a specific point in time, preventing post-hoc manipulation.

**Pharmaceutical IP exchange**
Deliver formulation data and research findings between partners using envelopes with trust-level requirements and MFA. The cold storage policy ensures long-term preservation of the exchange record.

---

## Architecture Summary

```
┌─────────────────────────────────────────────────────────────┐
│                    Velocity Envelope System                   │
├──────────────────────────┬──────────────────────────────────┤
│   Cryptographic Envelope │      Evidence Envelope            │
│   (Secretr)              │      (Velocity Core)              │
├──────────────────────────┼──────────────────────────────────┤
│ E2E encrypted delivery   │ Tamper-proof evidence wrapper     │
│ X25519 + AES-256-GCM     │ SHA-256 dual hash chains          │
│ Ed25519 signed custody   │ Time-lock + fingerprint policies  │
│ Forward secrecy per msg  │ Offline AI tamper detection        │
│ Business rules at open   │ Cold storage archival              │
│ CLI-driven workflow       │ Go API + file-based exchange      │
│ Identity-to-identity      │ Multi-party custody tracking      │
├──────────────────────────┴──────────────────────────────────┤
│                    Shared Concepts                            │
│  • Append-only custody chains with hash linkage              │
│  • SHA-256 integrity verification                            │
│  • Structured audit logging                                  │
│  • Atomic file storage with restricted permissions           │
│  • Context-based actor tracking                              │
│  • RBAC + entitlement gating                                 │
└─────────────────────────────────────────────────────────────┘
```

---

## Key Differentiators

1. **Zero-trust delivery** — Payload is encrypted for a specific recipient. No server, admin, or intermediary can read it.
2. **Forward secrecy** — Ephemeral X25519 key pairs per envelope. Compromising a long-term key doesn't expose past envelopes.
3. **Cryptographic non-repudiation** — Ed25519 signatures on the envelope and every custody entry. Every action is attributable.
4. **Legal-grade chain of custody** — Dual hash chains (custody + audit) with sequence numbers, replay detection, and tamper-evident linking.
5. **Time-lock enforcement** — Evidence can be sealed until a court date, with escrow signers and legal condition documentation.
6. **Offline tamper detection** — AI analyzers produce scored verdicts without requiring network connectivity.
7. **Portable exchange** — Envelopes are self-contained JSON files. Export from one system, transfer by any means, import into another. The integrity travels with the data.
8. **Secure memory handling** — DEKs and private keys are held in `SecureBytes` with explicit zeroization. No key material lingers in memory after use.
