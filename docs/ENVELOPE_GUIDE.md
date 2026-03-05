# Velocity Secure Envelope System

A tamper-proof digital evidence cabinet with chain-of-custody tracking, time-lock encryption, and offline AI tamper detection.

## Use Cases

- **Court Evidence**: Tamper-proof digital evidence with chain-of-custody
- **Investigation Records**: Secure case files with access control
- **CCTV Forensic Archives**: Time-stamped video evidence
- **Legal Documents**: Time-locked contracts and agreements

## Quick Start

### 1. Sender Creates and Exports Envelope

```go
// Initialize sender's database
db, _ := velocity.NewWithConfig(velocity.Config{
    Path: "./sender_vault",
})
defer db.Close()

// Create evidence envelope
request := &velocity.EnvelopeRequest{
    Label:          "Evidence - Case 2026-001234",
    Type:           velocity.EnvelopeTypeCourtEvidence,
    EvidenceClass:  "digital_video",
    CreatedBy:      "officer-smith",
    CaseReference:  "CR-2026-001234",
    FingerprintSignature: "fp:officer-smith",
    IntakeLocation: "Evidence Room 3",

    Payload: velocity.EnvelopePayload{
        Kind:       "file",
        ObjectPath: "evidence/video.mp4",
        Metadata: map[string]string{
            "duration": "180s",
            "hash":     "sha256:abc...",
        },
    },

    Policies: velocity.EnvelopePolicies{
        TimeLock: velocity.TimeLockPolicy{
            UnlockNotBefore: time.Now().Add(30 * 24 * time.Hour),
            LegalCondition:  "Court order required",
        },
        Fingerprint: velocity.FingerprintPolicy{
            Required: true,
            AuthorizedFingerprints: []string{"fp:detective-doe"},
        },
        Tamper: velocity.TamperPolicy{
            Analyzer:    "velocity-ml-v1",
            Sensitivity: "high",
            Offline:     true,
        },
        ColdStorage: velocity.ColdStoragePolicy{
            Enabled:      true,
            StorageClass: "evidence_archive",
        },
    },
}

envelope, err := db.CreateEnvelope(context.Background(), request)

// Export envelope to file for sharing with recipient
exportPath := "./evidence_transfer/" + envelope.EnvelopeID + ".envelope"
err = db.ExportEnvelope(ctx, envelope.EnvelopeID, exportPath)
// Share this file with authorized recipients via secure channel
```

### 2. Recipient Imports and Accesses Envelope

```go
// Initialize recipient's database (separate system)
recipientDB, _ := velocity.NewWithConfig(velocity.Config{
    Path: "./recipient_vault",
})
defer recipientDB.Close()

// Import envelope from file
envelope, err := recipientDB.ImportEnvelope(ctx, "./received/evidence.envelope")

// Check time-lock status
if envelope.TimeLockStatus.Active {
    fmt.Println("⏰ Time-locked until:", envelope.TimeLockStatus.UnlockNotBefore)
    fmt.Println("Legal condition:", envelope.Policies.TimeLock.LegalCondition)
}

// Verify fingerprint requirement
if envelope.Policies.Fingerprint.Required {
    // Verify recipient's fingerprint matches authorized list
    authorized := false
    for _, fp := range envelope.Policies.Fingerprint.AuthorizedFingerprints {
        if fp == recipientFingerprint {
            authorized = true
            break
        }
    }
}

// Record access in custody chain
accessEvent := &velocity.CustodyEvent{
    Actor:            "detective-doe",
    ActorFingerprint: "fp:detective-doe",
    Action:           "envelope.accessed",
    Location:         "Detective Office",
    Notes:            "Initial review",
    EvidenceState:    "under_review",
}

envelope, err = db.AppendCustodyEvent(ctx, envelopeID, accessEvent)
```

### 3. Verify Integrity

```go
// Check payload integrity
fmt.Println("Payload Hash:", envelope.Integrity.PayloadHash)
fmt.Println("Ledger Root:", envelope.Integrity.LedgerRoot)
fmt.Println("Time Seal:", envelope.Integrity.TimeSeal.Hash)

// Review custody chain
for i, event := range envelope.CustodyLedger {
    fmt.Printf("[%d] %s - %s by %s\n",
        i+1,
        event.Timestamp.Format("2006-01-02 15:04:05"),
        event.Action,
        event.Actor)
    fmt.Printf("    Hash: %s\n", event.EventHash)
}
```

### 4. Run Tamper Detection

```go
// Offline AI tamper analysis
signal := &velocity.TamperSignal{
    Analyzer:        "velocity-ml-v1",
    AnalyzerVersion: "1.2.3",
    Score:           0.05,  // Low = no tampering
    Threshold:       0.75,
    Offline:         true,
    Notes: []string{
        "Hash chain verified",
        "No anomalies detected",
    },
}

envelope, err = db.RecordTamperSignal(ctx, envelopeID, signal)

if signal.Score < signal.Threshold {
    fmt.Println("✅ No tampering detected")
} else {
    fmt.Println("⚠️ Possible tampering")
}
```

### 5. Release Time-Lock

```go
// Legal authority approves early access
envelope, err := db.ApproveTimeLockUnlock(
    ctx,
    envelopeID,
    "judge-wilson@court.gov",
    "Court Order #CO-2026-5678: Emergency access granted",
)

if err == velocity.ErrTimeLockActive {
    fmt.Println("⏰ Time constraints not met yet")
} else {
    fmt.Println("✅ Time-lock released")
    fmt.Println("Approved by:", envelope.TimeLockStatus.UnlockApprovedBy)
    fmt.Println("Reason:", envelope.TimeLockStatus.UnlockReason)
}
```

## File-Based Envelope Sharing

### Sender: Export Envelope to File

```go
// After creating the envelope
envelope, err := db.CreateEnvelope(ctx, request)

// Export to portable JSON file
exportPath := "./evidence/" + envelope.EnvelopeID + ".envelope"
err = db.ExportEnvelope(ctx, envelope.EnvelopeID, exportPath)

// Share the .envelope file with authorized recipients via:
// - Secure email attachment
// - Encrypted USB drive
// - Evidence transfer portal
// - Court filing system
```

### Recipient: Import Envelope from File

```go
// Recipient receives .envelope file
// Initialize their own database (separate system)
recipientDB, _ := velocity.NewWithConfig(velocity.Config{
    Path: "./my_evidence_vault",
})

// Import envelope from received file
envelope, err := recipientDB.ImportEnvelope(ctx, "./received/evidence.envelope")

// Envelope is now accessible in recipient's local database
// All policies, time-locks, and custody events are preserved
// Recipient can add new custody events to track their access

// Record that recipient imported the envelope
recipientDB.AppendCustodyEvent(ctx, envelope.EnvelopeID, &velocity.CustodyEvent{
    Actor:  "detective-doe",
    Action: "envelope.imported",
})
```

### Envelope File Format

The exported `.envelope` file is a JSON document containing:
- Complete envelope metadata
- All custody events with cryptographic hashes
- Audit log entries
- Tamper analysis results
- Time-lock status and policies
- Fingerprint access control lists
- Integrity checksums (payload, ledger, audit roots)

**File Example:**
```json
{
  "envelope_id": "env-282534cbf212b3c5e0361964",
  "label": "CCTV Evidence - Case CR-2026-001234",
  "type": "cctv_forensic_archive",
  "status": "sealed",
  "created_at": "2026-01-24T11:08:13Z",
  "policies": {
    "time_lock": {
      "unlock_not_before": "2026-02-23T16:53:13Z",
      "legal_condition": "Court order required"
    },
    "fingerprint": {
      "required": true,
      "authorized_fingerprints": ["fp:detective-john-doe"]
    }
  },
  "custody_ledger": [...],
  "integrity": {...}
}
```

## Envelope Types

```go
velocity.EnvelopeTypeCourtEvidence       // Court evidence
velocity.EnvelopeTypeInvestigationRecord // Investigation records
velocity.EnvelopeTypeCustodyProof        // Chain-of-custody proofs
velocity.EnvelopeTypeCCTVArchive         // CCTV forensic archives
```

## Security Features

### 1. Chain of Custody
Every access creates an immutable custody event:
- Actor identification
- Fingerprint verification
- Location tracking
- Timestamp with hash linking
- Merkle tree accumulator

### 2. Time-Lock Encryption
Data locked until legal conditions met:
- Minimum delay period
- Unlock date/time
- Legal condition description
- Escrow signer requirements
- VDF-based seal proofs

### 3. Tamper Detection
Offline AI monitors integrity:
- Hash chain verification
- Access pattern analysis
- Timestamp sequence validation
- Anomaly scoring
- Signed tamper reports

### 4. Cold Storage
Immutable offline archiving:
- Scheduled snapshots
- Dual hash verification (fast + slow)
- Time-sealed commitments
- Notary service integration

### 5. Fingerprint Access
Biometric authentication:
- Template storage (encrypted)
- Match threshold configuration
- Multi-factor requirements
- Authorized fingerprint lists

## Run Example

```bash
# Build and run the workflow demo
go run -tags velocity_examples examples/envelope_workflow.go
```

## JSON Storage

Envelopes are stored as JSON files in `<vault>/envelopes/`:

```
vault_data/
├── envelopes/
│   ├── env-abc123.json    # Envelope with full audit trail
│   ├── env-def456.json
│   └── env-ghi789.json
├── objects/               # Referenced files
└── master.key            # Encryption key
```

Each envelope contains:
- Full custody ledger (append-only)
- Complete audit log
- Tamper analysis history
- Time-lock status
- Integrity proofs
- Policy configurations

## API Reference

### Core Methods

```go
// Create new envelope
CreateEnvelope(ctx, *EnvelopeRequest) (*Envelope, error)

// Load envelope for reading
LoadEnvelope(ctx, envelopeID) (*Envelope, error)

// Add custody event
AppendCustodyEvent(ctx, envelopeID, *CustodyEvent) (*Envelope, error)

// Record tamper analysis
RecordTamperSignal(ctx, envelopeID, *TamperSignal) (*Envelope, error)

// Approve time-lock release
ApproveTimeLockUnlock(ctx, envelopeID, approver, reason) (*Envelope, error)
```

### Errors

```go
velocity.ErrEnvelopeNotFound  // Envelope ID doesn't exist
velocity.ErrTimeLockActive    // Time-lock constraints not met
```

## Best Practices

1. **Always use fingerprints** for custody events
2. **Record location** for every access
3. **Run tamper scans** periodically
4. **Enable cold storage** for archival evidence
5. **Use time-locks** for sensitive legal documents
6. **Verify integrity hashes** before court submission
7. **Keep audit trails** for compliance

## Legal Compliance

The envelope system provides:
- ✅ Tamper-evident chain of custody
- ✅ Cryptographic integrity proofs
- ✅ Audit trails with timestamps
- ✅ Access control and authentication
- ✅ Cold storage for long-term preservation
- ✅ Time-locked evidence protection
