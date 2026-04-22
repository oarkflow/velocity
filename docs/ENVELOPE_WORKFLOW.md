# Envelope File-Based Workflow

## Overview

The Velocity envelope system allows **senders** to create tamper-proof evidence packages and **recipients** to access them using portable `.envelope` files. This enables secure evidence transfer across different systems without requiring a shared database.

## Complete Workflow

### Step 1: Sender Creates & Exports Evidence

```go
package main

import (
    "context"
    "github.com/oarkflow/velocity"
)

func main() {
    // Initialize sender's database
    senderDB, _ := velocity.NewWithConfig(velocity.Config{
        Path: "./sender_vault",
        MasterKeyConfig: velocity.MasterKeyConfig{
            Source: velocity.SystemFile,
        },
    })
    defer senderDB.Close()

    ctx := context.Background()

    // Create envelope with policies
    request := &velocity.EnvelopeRequest{
        Label:          "CCTV Evidence - Case CR-2026-001234",
        Type:           velocity.EnvelopeTypeCCTVArchive,
        CreatedBy:      "officer-smith-badge-5678",
        CaseReference:  "CR-2026-001234",

        Payload: velocity.EnvelopePayload{
            Kind:       "file",
            ObjectPath: "evidence/cctv/camera5.mp4",
        },

        Policies: velocity.EnvelopePolicies{
            TimeLock: velocity.TimeLockPolicy{
                UnlockNotBefore: time.Now().Add(30 * 24 * time.Hour),
                LegalCondition:  "Court order required for early access",
            },
            Fingerprint: velocity.FingerprintPolicy{
                Required: true,
                AuthorizedFingerprints: []string{
                    "fp:detective-john-doe",
                    "fp:prosecutor-jane-smith",
                },
            },
        },
    }

    envelope, _ := senderDB.CreateEnvelope(ctx, request)

    // Export to file for sharing
    exportPath := "./evidence_transfer/" + envelope.EnvelopeID + ".envelope"
    senderDB.ExportEnvelope(ctx, envelope.EnvelopeID, exportPath)

    // Share the .envelope file with authorized recipients
    println("📦 Envelope exported to:", exportPath)
}
```

### Step 2: Transfer the File

The sender shares the `.envelope` file with authorized recipients via:
- 🔐 Encrypted email attachment
- 💾 Encrypted USB drive
- 🌐 Secure file transfer portal
- ⚖️ Court filing system
- 📡 Evidence management network

### Step 3: Recipient Imports & Accesses Evidence

```go
package main

import (
    "context"
    "github.com/oarkflow/velocity"
)

func main() {
    // Initialize recipient's database (completely separate system)
    recipientDB, _ := velocity.NewWithConfig(velocity.Config{
        Path: "./recipient_vault",
        MasterKeyConfig: velocity.MasterKeyConfig{
            Source: velocity.SystemFile,
        },
    })
    defer recipientDB.Close()

    ctx := context.Background()

    // Import envelope from received file
    envelopeFile := "./received/env-282534cbf212b3c5e0361964.envelope"
    envelope, _ := recipientDB.ImportEnvelope(ctx, envelopeFile)

    println("✅ Envelope imported:", envelope.EnvelopeID)
    println("📋 Label:", envelope.Label)
    println("🔒 Status:", envelope.Status)

    // Check access requirements
    if envelope.TimeLockStatus.Active {
        println("⏰ Time-locked until:", envelope.TimeLockStatus.UnlockNotBefore)
    }

    // Record recipient's access in custody chain
    recipientDB.AppendCustodyEvent(ctx, envelope.EnvelopeID, &velocity.CustodyEvent{
        Actor:            "detective-john-doe",
        ActorFingerprint: "fp:detective-john-doe",
        Action:           "envelope.imported",
        Location:         "Detective Office, Terminal 42",
        Notes:            "Imported for case review",
    })

    // Perform tamper analysis
    recipientDB.RecordTamperSignal(ctx, envelope.EnvelopeID, &velocity.TamperSignal{
        Analyzer:  "velocity-ml-v1",
        Score:     0.03,  // Low score = no tampering
        Threshold: 0.75,
        Offline:   true,
    })
}
```

## Run the Demo

```bash
# Build the example
go build -tags velocity_examples -o velocity-envelope-demo examples/envelope_workflow.go

# Run complete sender→recipient workflow
./velocity-envelope-demo
```

**Output:**
```
📤 SENDER: Creating Court Evidence Envelope
✅ Envelope Created
📦 Envelope Exported
   File: ./evidence_transfer/env-282534cbf212b3c5e0361964.envelope

📥 RECIPIENT: Importing Evidence Envelope
📦 Envelope Imported from File
⏰ TIME-LOCK ACTIVE
🔐 FINGERPRINT VERIFICATION REQUIRED
🔒 INTEGRITY VERIFICATION
📝 Custody Event Recorded

🔍 INVESTIGATOR: Recording Tamper Analysis
✅ Tamper Analysis Complete
   Status: ✅ NO TAMPERING DETECTED

📋 AUDITOR: Reviewing Full Chain of Custody
🔗 Custody Ledger (2 events)
📝 Audit Log (3 entries)
🔐 Integrity Status
```

## Envelope File Structure

The `.envelope` file contains (JSON format):

```json
{
  "envelope_id": "env-...",
  "label": "Evidence description",
  "status": "sealed",
  "created_at": "2026-01-24T11:08:13Z",

  "payload": {
    "kind": "file",
    "object_path": "evidence/video.mp4",
    "inline_data": "base64-encoded-data...",
    "metadata": {...}
  },

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

  "custody_ledger": [
    {
      "timestamp": "2026-01-24T11:08:13Z",
      "action": "envelope.created",
      "actor": "officer-smith-badge-5678",
      "event_hash": "deae0b80a7962f76..."
    }
  ],

  "integrity": {
    "payload_hash": "e54f13e7394582b4...",
    "ledger_root": "d50150fdd92e3e7c...",
    "audit_root": "e94b26cf033452ce..."
  }
}
```

## Key Features

✅ **Portable** - Envelope files work across different systems
✅ **Self-Contained** - All metadata, policies, and custody events included
✅ **Tamper-Proof** - Cryptographic hashes detect any modifications
✅ **Access Control** - Fingerprint verification and time-locks preserved
✅ **Chain of Custody** - Complete audit trail maintained
✅ **Offline Capable** - No network connection required

## Security Considerations

1. **File Encryption**: The `.envelope` file itself is JSON (readable). For additional security, encrypt the file during transfer using:
   - GPG encryption
   - AES-256 encryption
   - S/MIME email encryption
   - Encrypted container formats

2. **Integrity Verification**: Recipients should verify:
   - Envelope ID matches expected value
   - Payload hash hasn't changed
   - Custody ledger hash chain is valid
   - Creator fingerprint signature

3. **Access Control**: Time-locks and fingerprint policies are enforced by the recipient's database when accessing the envelope.

## API Reference

### Export Methods

```go
// Export envelope to file
ExportEnvelope(ctx context.Context, envelopeID string, exportPath string) error
```

### Import Methods

```go
// Import envelope from file
ImportEnvelope(ctx context.Context, importPath string) (*Envelope, error)
```

### Custody Tracking

```go
// Record recipient's access
AppendCustodyEvent(ctx context.Context, envelopeID string, event *CustodyEvent) (*Envelope, error)

// Record tamper analysis
RecordTamperSignal(ctx context.Context, envelopeID string, signal *TamperSignal) (*Envelope, error)
```

## See Also

- [ENVELOPE_GUIDE.md](ENVELOPE_GUIDE.md) - Complete API documentation
- [examples/envelope_workflow.go](examples/envelope_workflow.go) - Full working example
