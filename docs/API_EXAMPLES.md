# Secure Institutional Knowledge & Intelligence Platform — API Examples & HTTP Tests

All endpoints are under `/api/doclib` and require JWT authentication via the `Authorization: Bearer <token>` header.

Base URL: `http://localhost:3000/api/doclib`

---

## Table of Contents

1. [Organization Hierarchy](#1-organization-hierarchy)
2. [Documents](#2-documents)
3. [Document Lifecycle](#3-document-lifecycle)
4. [Document Sharing](#4-document-sharing)
5. [Audit & Access Chain](#5-audit--access-chain)
6. [Dispatch (Envelopes)](#6-dispatch-envelopes)
7. [Cases / Investigations](#7-cases--investigations)
8. [Evidence & Chain of Custody](#8-evidence--chain-of-custody)
9. [Clearance & Policy](#9-clearance--policy)
10. [Workflow](#10-workflow)
11. [Entities](#11-entities)
12. [Entity Linking](#12-entity-linking)
13. [Graph Intelligence](#13-graph-intelligence)
14. [Visualization](#14-visualization)
15. [Discovery / Search](#15-discovery--search)
16. [Analytics](#16-analytics)
17. [Alerts & Notifications](#17-alerts--notifications)
18. [Webhooks](#18-webhooks)
19. [Connectors](#19-connectors)
20. [ABAC Rules](#20-abac-rules)
21. [Compartments (Need-to-Know)](#21-compartments-need-to-know)
22. [ReBAC (Relationship-Based Access)](#22-rebac-relationship-based-access)
23. [Unified Access Evaluation](#23-unified-access-evaluation)
24. [Shamir Secret Sharing](#24-shamir-secret-sharing)
25. [Indexing](#25-indexing)
26. [Enhanced Audit](#26-enhanced-audit)
27. [Advanced Workflow](#27-advanced-workflow)
28. [Data Governance](#28-data-governance)
29. [Data Ingestion](#29-data-ingestion)
30. [Document Governance (Signatures, Legal Hold, Retention)](#30-document-governance)
31. [Policy Documents](#31-policy-documents)
32. [Org Access Sync](#32-org-access-sync)
33. [Context-Aware Document Access](#33-context-aware-document-access)
34. [Events](#34-events)
35. [Dashboard](#35-dashboard)

---

## 1. Organization Hierarchy

### Create a company

```http
POST /api/doclib/orgs
Content-Type: application/json
Authorization: Bearer {{token}}

{
  "name": "National Security Agency",
  "description": "Intelligence and cybersecurity agency"
}
```

**Response** `201 Created`:
```json
{
  "company_id": "comp_abc123",
  "name": "National Security Agency",
  "description": "Intelligence and cybersecurity agency",
  "created_by": "admin",
  "created_at": "2026-03-16T10:00:00Z"
}
```

### List companies

```http
GET /api/doclib/orgs
Authorization: Bearer {{token}}
```

### Get a company

```http
GET /api/doclib/orgs/comp_abc123
Authorization: Bearer {{token}}
```

### Create a department

```http
POST /api/doclib/orgs/comp_abc123/depts
Content-Type: application/json
Authorization: Bearer {{token}}

{
  "name": "Counter-Intelligence Division",
  "code": "CID",
  "head_user_id": "user_director01"
}
```

### List departments

```http
GET /api/doclib/orgs/comp_abc123/depts
Authorization: Bearer {{token}}
```

### Create a unit

```http
POST /api/doclib/depts/dept_xyz/units
Content-Type: application/json
Authorization: Bearer {{token}}

{
  "company_id": "comp_abc123",
  "name": "Fraud Investigation Unit",
  "code": "FIU",
  "manager_user_id": "user_manager01"
}
```

### Add a member to a unit

```http
POST /api/doclib/units/unit_001/members
Content-Type: application/json
Authorization: Bearer {{token}}

{
  "user_id": "user_agent007",
  "role": "senior_investigator"
}
```

### Remove a member

```http
DELETE /api/doclib/units/unit_001/members/user_agent007
Authorization: Bearer {{token}}
```

### Get user memberships

```http
GET /api/doclib/users/user_agent007/memberships
Authorization: Bearer {{token}}
```

### List all users

```http
GET /api/doclib/users
Authorization: Bearer {{token}}
```

---

## 2. Documents

### Create a document (JSON)

```http
POST /api/doclib/documents
Content-Type: application/json
Authorization: Bearer {{token}}

{
  "title": "Suspicious Activity Report - Case #4521",
  "description": "SAR filed for unusual wire transfers between Jan-Mar 2026",
  "doc_type": "financial_report",
  "classification_level": "confidential",
  "owner_unit_id": "unit_fiu",
  "owner_dept_id": "dept_compliance",
  "owner_company_id": "comp_bank01",
  "tags": ["aml", "wire_transfer", "suspicious"],
  "jurisdiction": "US-Federal",
  "regulatory_category": "BSA/AML",
  "sensitivity_level": "high",
  "source_credibility": "verified",
  "confidence_score": 0.92,
  "entities_mentioned": ["person_john_doe", "org_shell_corp"],
  "related_events": ["evt_wire_001", "evt_wire_002"],
  "validity_from": "2026-01-01T00:00:00Z",
  "validity_to": "2027-01-01T00:00:00Z",
  "disclosure_restrictions": ["law_enforcement_only", "no_export"]
}
```

### Create a document with file upload (multipart)

```http
POST /api/doclib/documents
Content-Type: multipart/form-data
Authorization: Bearer {{token}}

title=Intelligence Briefing Q1 2026
doc_type=intelligence_briefing
classification_level=secret
owner_unit_id=unit_intel
tags=briefing,quarterly
file=@/path/to/briefing.pdf
```

### Query documents with filters

```http
GET /api/doclib/documents?classification=confidential&doc_type=financial_report&tags=aml,suspicious&dept_id=dept_compliance&sort_by=created_at&limit=20&offset=0
Authorization: Bearer {{token}}
```

### Full-text search in documents

```http
GET /api/doclib/documents?q=wire+transfer+suspicious&limit=50
Authorization: Bearer {{token}}
```

### Get document metadata

```http
GET /api/doclib/documents/doc_sar4521
Authorization: Bearer {{token}}
```

### Get document content (binary)

```http
GET /api/doclib/documents/doc_sar4521/content
Authorization: Bearer {{token}}
```

### Update a document

```http
PUT /api/doclib/documents/doc_sar4521
Content-Type: application/json
Authorization: Bearer {{token}}

{
  "title": "SAR - Case #4521 (Updated)",
  "classification_level": "secret",
  "description": "Updated with new transaction evidence"
}
```

### Delete a document

```http
DELETE /api/doclib/documents/doc_sar4521
Authorization: Bearer {{token}}
```

### Get related documents

```http
GET /api/doclib/documents/doc_sar4521/related?limit=10
Authorization: Bearer {{token}}
```

### Add a comment

```http
POST /api/doclib/documents/doc_sar4521/comments
Content-Type: application/json
Authorization: Bearer {{token}}

{
  "content": "Cross-referenced with Case #3892 — same shell company appears in both."
}
```

### List comments

```http
GET /api/doclib/documents/doc_sar4521/comments
Authorization: Bearer {{token}}
```

---

## 3. Document Lifecycle

### Transition document status

```http
PUT /api/doclib/documents/doc_sar4521/status
Content-Type: application/json
Authorization: Bearer {{token}}

{
  "status": "under_review",
  "comment": "Escalated for senior analyst review"
}
```

**Valid status transitions**: `draft` → `under_review` → `approved` → `published` → `archived`

### Get document history

```http
GET /api/doclib/documents/doc_sar4521/history
Authorization: Bearer {{token}}
```

---

## 4. Document Sharing

### Create a share (inter-department)

```http
POST /api/doclib/documents/doc_sar4521/shares
Content-Type: application/json
Authorization: Bearer {{token}}

{
  "grant_to_type": "department",
  "grant_to_id": "dept_legal",
  "permissions": ["read", "annotate"],
  "reason": "Legal review required for regulatory filing",
  "expires_at": "2026-06-01T00:00:00Z"
}
```

### Create a share (inter-agency)

```http
POST /api/doclib/documents/doc_intel01/shares
Content-Type: application/json
Authorization: Bearer {{token}}

{
  "grant_to_type": "company",
  "grant_to_id": "comp_fbi",
  "permissions": ["read"],
  "reason": "Joint investigation per MOU #2026-045"
}
```

### Approve a share

```http
POST /api/doclib/shares/share_001/approve
Authorization: Bearer {{token}}
```

### Reject a share

```http
POST /api/doclib/shares/share_001/reject
Content-Type: application/json
Authorization: Bearer {{token}}

{
  "reason": "Insufficient clearance level for this classification"
}
```

### Revoke a share

```http
DELETE /api/doclib/shares/share_001
Authorization: Bearer {{token}}
```

---

## 5. Audit & Access Chain

### Get full access chain for a document

```http
GET /api/doclib/documents/doc_sar4521/access-chain
Authorization: Bearer {{token}}
```

**Response**:
```json
{
  "doc_id": "doc_sar4521",
  "chain": [
    {
      "event_id": "evt_001",
      "doc_id": "doc_sar4521",
      "actor": "user_analyst01",
      "actor_role": "senior_analyst",
      "action": "create",
      "outcome": "success",
      "ip_address": "10.0.1.45",
      "timestamp": "2026-03-01T09:00:00Z",
      "prev_hash": "",
      "event_hash": "a1b2c3..."
    },
    {
      "event_id": "evt_002",
      "doc_id": "doc_sar4521",
      "actor": "user_supervisor",
      "action": "read",
      "outcome": "success",
      "timestamp": "2026-03-01T10:30:00Z",
      "prev_hash": "a1b2c3...",
      "event_hash": "d4e5f6..."
    }
  ],
  "total": 2
}
```

### Get access chain summary

```http
GET /api/doclib/documents/doc_sar4521/access-chain/summary
Authorization: Bearer {{token}}
```

---

## 6. Dispatch (Envelopes)

### Send a document as a sealed envelope

```http
POST /api/doclib/documents/doc_sar4521/dispatch
Content-Type: application/json
Authorization: Bearer {{token}}

{
  "recipients": [
    {
      "name": "FinCEN Regulatory Office",
      "type": "government_agency",
      "address": "fincen-intake@treasury.gov"
    }
  ],
  "purpose": "Mandatory SAR filing per 31 CFR 1020.320",
  "case_ref": "case_4521",
  "expires_at": "2026-12-31T23:59:59Z",
  "time_lock": true,
  "legal_note": "This document is a regulatory filing under BSA/AML requirements",
  "tags": {
    "filing_type": "SAR",
    "regulation": "BSA"
  }
}
```

### Acknowledge receipt

```http
POST /api/doclib/dispatches/disp_001/acknowledge
Authorization: Bearer {{token}}
```

### Recall a dispatch

```http
POST /api/doclib/dispatches/disp_001/recall
Content-Type: application/json
Authorization: Bearer {{token}}

{
  "note": "Document contained errors in transaction amounts — corrected version to follow"
}
```

### Get envelope (full Velocity envelope with custody chain)

```http
GET /api/doclib/dispatches/disp_001/envelope
Authorization: Bearer {{token}}
```

---

## 7. Cases / Investigations

### Create a case

```http
POST /api/doclib/cases
Content-Type: application/json
Authorization: Bearer {{token}}

{
  "title": "Operation Shadow Wire - Money Laundering Investigation",
  "description": "Multi-jurisdictional investigation into layered wire transfers through shell companies in Panama, Cyprus, and Delaware",
  "case_type": "money_laundering",
  "priority": "critical",
  "department": "dept_fiu",
  "jurisdiction": "US-Federal",
  "assigned_to": ["user_lead_inv", "user_analyst01", "user_analyst02"],
  "tags": ["aml", "shell_companies", "cross_border"]
}
```

### Query cases

```http
GET /api/doclib/cases?status=investigation&type=money_laundering&priority=critical&department=dept_fiu&limit=50
Authorization: Bearer {{token}}
```

### Update case status

```http
PUT /api/doclib/cases/case_shadow_wire/status
Content-Type: application/json
Authorization: Bearer {{token}}

{
  "status": "analysis"
}
```

**Case lifecycle**: `intake` → `investigation` → `analysis` → `legal_review` → `resolution` → `archive`

### Link a document to a case

```http
POST /api/doclib/cases/case_shadow_wire/documents
Content-Type: application/json
Authorization: Bearer {{token}}

{
  "doc_id": "doc_sar4521"
}
```

### Link an entity to a case

```http
POST /api/doclib/cases/case_shadow_wire/entities
Content-Type: application/json
Authorization: Bearer {{token}}

{
  "entity_id": "ent_john_doe"
}
```

### Link cases (cross-case intelligence)

```http
POST /api/doclib/cases/case_shadow_wire/cases
Content-Type: application/json
Authorization: Bearer {{token}}

{
  "linked_case_id": "case_3892"
}
```

### Add a task

```http
POST /api/doclib/cases/case_shadow_wire/tasks
Content-Type: application/json
Authorization: Bearer {{token}}

{
  "title": "Trace beneficial ownership of ShellCorp LLC",
  "description": "Use Panama registry data to trace UBOs through 3 layers",
  "assigned_to": "user_analyst01",
  "priority": "high",
  "due_date": "2026-04-01T00:00:00Z"
}
```

### Add a note

```http
POST /api/doclib/cases/case_shadow_wire/notes
Content-Type: application/json
Authorization: Bearer {{token}}

{
  "content": "Discovered additional wire transfers totaling $2.3M through Cyprus account. Need to request records from Bank of Cyprus via MLAT.",
  "visibility": "investigators_only"
}
```

### Get case timeline

```http
GET /api/doclib/cases/case_shadow_wire/timeline
Authorization: Bearer {{token}}
```

### Find shared entities between cases

```http
GET /api/doclib/cases/case_shadow_wire/shared-entities?other_case_id=case_3892
Authorization: Bearer {{token}}
```

---

## 8. Evidence & Chain of Custody

### Collect evidence

```http
POST /api/doclib/evidence
Content-Type: application/json
Authorization: Bearer {{token}}

{
  "case_id": "case_shadow_wire",
  "type": "digital",
  "subtype": "bank_statement",
  "title": "HSBC Account Statements - Jan to Mar 2026",
  "description": "Monthly statements for account ending 4521, obtained via subpoena #SUB-2026-089",
  "source": "HSBC Legal Department",
  "classification": "confidential",
  "metadata": {
    "account_number": "****4521",
    "bank": "HSBC",
    "period": "2026-Q1",
    "subpoena_ref": "SUB-2026-089"
  }
}
```

### Transfer custody

```http
POST /api/doclib/evidence/ev_hsbc_001/transfer
Content-Type: application/json
Authorization: Bearer {{token}}

{
  "to_user": "user_forensic_analyst",
  "reason": "Transfer for forensic analysis of transaction patterns",
  "approval": "supervisor_approval_ref_123"
}
```

### Get custody chain

```http
GET /api/doclib/evidence/ev_hsbc_001/custody
Authorization: Bearer {{token}}
```

**Response**:
```json
{
  "custody_chain": [
    {
      "from_user": "user_agent007",
      "to_user": "user_agent007",
      "action": "collected",
      "timestamp": "2026-03-10T14:00:00Z",
      "reason": "Initial collection via subpoena"
    },
    {
      "from_user": "user_agent007",
      "to_user": "user_forensic_analyst",
      "action": "transferred",
      "timestamp": "2026-03-11T09:00:00Z",
      "reason": "Transfer for forensic analysis",
      "approval": "supervisor_approval_ref_123"
    }
  ],
  "total": 2
}
```

### Verify evidence integrity

```http
GET /api/doclib/evidence/ev_hsbc_001/verify
Authorization: Bearer {{token}}
```

### List case evidence

```http
GET /api/doclib/cases/case_shadow_wire/evidence
Authorization: Bearer {{token}}
```

---

## 9. Clearance & Policy

### Set user clearance

```http
PUT /api/doclib/clearance/user_agent007
Content-Type: application/json
Authorization: Bearer {{token}}

{
  "clearance_level": "secret",
  "granted_by": "user_director",
  "valid_from": "2026-01-01T00:00:00Z",
  "valid_to": "2027-01-01T00:00:00Z",
  "polygraph_date": "2025-12-15T00:00:00Z",
  "case_assignments": ["case_shadow_wire", "case_3892"],
  "allowed_overlays": ["source_protected", "financial_confidential"],
  "department_scope": ["dept_fiu", "dept_compliance"]
}
```

### Get user clearance

```http
GET /api/doclib/clearance/user_agent007
Authorization: Bearer {{token}}
```

### Create an access policy

```http
POST /api/doclib/policies
Content-Type: application/json
Authorization: Bearer {{token}}

{
  "name": "Top Secret Access Policy",
  "classification_level": "top_secret",
  "required_clearance": "top_secret",
  "required_overlays": ["need_to_know"],
  "require_case_membership": true,
  "allowed_departments": ["dept_intel"],
  "time_restrictions": {
    "valid_from": "08:00",
    "valid_to": "18:00",
    "timezone": "America/New_York"
  }
}
```

### Evaluate access

```http
POST /api/doclib/access/evaluate
Content-Type: application/json
Authorization: Bearer {{token}}

{
  "user_id": "user_agent007",
  "resource_classification": "secret",
  "resource_case_id": "case_shadow_wire",
  "overlays": ["source_protected"],
  "resource_type": "document",
  "resource_id": "doc_sar4521"
}
```

**Response**:
```json
{
  "allowed": true,
  "reasons": [
    "clearance_level: secret >= secret",
    "case_membership: user is assigned to case_shadow_wire",
    "overlay: source_protected covered by user clearance"
  ]
}
```

---

## 10. Workflow

### Create a workflow template

```http
POST /api/doclib/workflows/templates
Content-Type: application/json
Authorization: Bearer {{token}}

{
  "name": "Document Classification Change",
  "description": "Multi-step approval for changing document classification level",
  "steps": [
    {
      "name": "Supervisor Review",
      "approvers": ["role:supervisor"],
      "required_approvals": 1
    },
    {
      "name": "Security Officer Approval",
      "approvers": ["role:security_officer"],
      "required_approvals": 1
    },
    {
      "name": "Classification Authority Final",
      "approvers": ["user:user_class_authority"],
      "required_approvals": 1
    }
  ],
  "escalation": {
    "timeout_hours": 48,
    "escalate_to": "user_director"
  }
}
```

### Start a workflow

```http
POST /api/doclib/workflows
Content-Type: application/json
Authorization: Bearer {{token}}

{
  "template_id": "wf_tmpl_class_change",
  "resource_type": "document",
  "resource_id": "doc_sar4521",
  "data": {
    "current_classification": "confidential",
    "requested_classification": "secret",
    "justification": "Contains newly identified intelligence sources"
  }
}
```

### Approve a workflow step

```http
POST /api/doclib/workflows/wf_inst_001/approve
Content-Type: application/json
Authorization: Bearer {{token}}

{
  "comment": "Approved — classification change is warranted per source protection policy"
}
```

### Reject a workflow step

```http
POST /api/doclib/workflows/wf_inst_001/reject
Content-Type: application/json
Authorization: Bearer {{token}}

{
  "reason": "Insufficient justification — please provide source protection assessment"
}
```

---

## 11. Entities

### Create a person entity

```http
POST /api/doclib/entities/persons
Content-Type: application/json
Authorization: Bearer {{token}}

{
  "name": "John Doe",
  "aliases": ["J. Doe", "Jonathan Doe"],
  "nationality": "US",
  "date_of_birth": "1975-06-15",
  "identification": {
    "ssn_last4": "4521",
    "passport": "US****789"
  },
  "risk_level": "high",
  "pep_status": true,
  "sanctions_list": false,
  "tags": ["suspect", "pep", "beneficial_owner"]
}
```

### Create an organization entity

```http
POST /api/doclib/entities/organizations
Content-Type: application/json
Authorization: Bearer {{token}}

{
  "name": "ShellCorp LLC",
  "type": "llc",
  "jurisdiction": "US-Delaware",
  "registration_number": "DE-2024-78901",
  "status": "active",
  "incorporation_date": "2024-03-01",
  "registered_agent": "CT Corporation",
  "risk_level": "critical",
  "tags": ["shell_company", "suspicious"]
}
```

### Create an account entity

```http
POST /api/doclib/entities/accounts
Content-Type: application/json
Authorization: Bearer {{token}}

{
  "account_number": "****4521",
  "bank": "HSBC",
  "type": "corporate_checking",
  "currency": "USD",
  "holder_entity_id": "ent_shellcorp",
  "opened_date": "2024-04-01",
  "status": "active",
  "jurisdiction": "UK"
}
```

### Create a transaction entity

```http
POST /api/doclib/entities/transactions
Content-Type: application/json
Authorization: Bearer {{token}}

{
  "type": "wire_transfer",
  "amount": 450000.00,
  "currency": "USD",
  "from_account": "ent_acct_4521",
  "to_account": "ent_acct_7890",
  "date": "2026-02-15T14:30:00Z",
  "reference": "WT-2026-02-15-001",
  "status": "completed",
  "suspicious": true,
  "flags": ["structuring", "round_amount", "new_beneficiary"]
}
```

### Create an event entity

```http
POST /api/doclib/entities/events
Content-Type: application/json
Authorization: Bearer {{token}}

{
  "type": "suspicious_activity",
  "title": "Multiple rapid wire transfers detected",
  "description": "5 wire transfers of ~$49,900 each within 2 hours from account ****4521",
  "occurred_at": "2026-02-15T14:30:00Z",
  "severity": "critical",
  "related_entities": ["ent_acct_4521", "ent_john_doe"]
}
```

### Create a location entity

```http
POST /api/doclib/entities/locations
Content-Type: application/json
Authorization: Bearer {{token}}

{
  "name": "ShellCorp Registered Office",
  "address": "1209 Orange Street, Wilmington, DE 19801",
  "country": "US",
  "type": "registered_office",
  "coordinates": {
    "lat": 39.7392,
    "lng": -75.5469
  }
}
```

### Create a device entity

```http
POST /api/doclib/entities/devices
Content-Type: application/json
Authorization: Bearer {{token}}

{
  "type": "computer",
  "identifier": "MAC-AA:BB:CC:DD:EE:FF",
  "ip_address": "203.0.113.42",
  "location": "ent_loc_panama_office",
  "associated_user": "ent_john_doe"
}
```

### Create an asset entity

```http
POST /api/doclib/entities/assets
Content-Type: application/json
Authorization: Bearer {{token}}

{
  "name": "Luxury Yacht 'Sea Shadow'",
  "type": "vessel",
  "value": 2500000.00,
  "currency": "USD",
  "registration": "Panama-YT-2024-001",
  "owner_entity_id": "ent_shellcorp"
}
```

### Get an entity with relations

```http
GET /api/doclib/entities/ent_john_doe?relations=true
Authorization: Bearer {{token}}
```

### Query entities by type

```http
GET /api/doclib/entities?type=person&limit=50&offset=0
Authorization: Bearer {{token}}
```

---

## 12. Entity Linking

### Link entities (person → organization)

```http
POST /api/doclib/entities/link
Content-Type: application/json
Authorization: Bearer {{token}}

{
  "source_id": "ent_john_doe",
  "target_id": "ent_shellcorp",
  "relation_type": "beneficial_owner",
  "bidirectional": false,
  "metadata": {
    "ownership_percentage": "75",
    "since": "2024-03-01",
    "source": "Panama registry records"
  }
}
```

### Link entities (organization → account)

```http
POST /api/doclib/entities/link
Content-Type: application/json
Authorization: Bearer {{token}}

{
  "source_id": "ent_shellcorp",
  "target_id": "ent_acct_4521",
  "relation_type": "owns_account",
  "bidirectional": false
}
```

### Link entities (transaction → account)

```http
POST /api/doclib/entities/link
Content-Type: application/json
Authorization: Bearer {{token}}

{
  "source_id": "ent_txn_001",
  "target_id": "ent_acct_4521",
  "relation_type": "debited_from",
  "bidirectional": false,
  "metadata": {
    "amount": "450000",
    "date": "2026-02-15"
  }
}
```

---

## 13. Graph Intelligence

### Find path between entities

```http
GET /api/doclib/graph/path?from=ent_john_doe&to=ent_acct_7890&max_depth=5
Authorization: Bearer {{token}}
```

### Get entity neighborhood

```http
GET /api/doclib/graph/neighborhood/ent_john_doe?depth=3
Authorization: Bearer {{token}}
```

### Find shortest path

```http
GET /api/doclib/graph/shortest-path?from=ent_john_doe&to=ent_acct_7890&max_depth=6
Authorization: Bearer {{token}}
```

**Response**:
```json
{
  "path": [
    {"source_id": "ent_john_doe", "target_id": "ent_shellcorp", "relation": "beneficial_owner"},
    {"source_id": "ent_shellcorp", "target_id": "ent_acct_4521", "relation": "owns_account"},
    {"source_id": "ent_acct_4521", "target_id": "ent_acct_7890", "relation": "wire_transfer"}
  ],
  "hops": 3
}
```

### Reconstruct entity timeline

```http
GET /api/doclib/graph/timeline/ent_john_doe?from=2025-01-01T00:00:00Z&to=2026-12-31T23:59:59Z
Authorization: Bearer {{token}}
```

### Calculate influence scores

```http
GET /api/doclib/graph/influence/ent_john_doe?entity_type=person&limit=20
Authorization: Bearer {{token}}
```

### Detect entity clusters

```http
GET /api/doclib/graph/clusters?entity_type=person&min_connections=3
Authorization: Bearer {{token}}
```

### Find co-occurrences

```http
GET /api/doclib/graph/co-occurrences?entity_id=ent_john_doe
Authorization: Bearer {{token}}
```

### Detect recurring patterns across cases

```http
GET /api/doclib/graph/patterns?case_ids=case_shadow_wire,case_3892,case_1234
Authorization: Bearer {{token}}
```

**Response**:
```json
{
  "patterns": [
    {
      "entity_ids": ["ent_john_doe", "ent_shellcorp"],
      "case_ids": ["case_shadow_wire", "case_3892"],
      "pattern_type": "shared_suspect_and_company",
      "frequency": 2
    }
  ],
  "total": 1
}
```

### Get entity network (for visualization)

```http
GET /api/doclib/graph/network/ent_john_doe?depth=2
Authorization: Bearer {{token}}
```

**Response** (D3.js-compatible):
```json
{
  "nodes": [
    {"id": "ent_john_doe", "type": "person", "label": "John Doe"},
    {"id": "ent_shellcorp", "type": "organization", "label": "ShellCorp LLC"},
    {"id": "ent_acct_4521", "type": "account", "label": "****4521"}
  ],
  "edges": [
    {"source": "ent_john_doe", "target": "ent_shellcorp", "relation": "beneficial_owner"},
    {"source": "ent_shellcorp", "target": "ent_acct_4521", "relation": "owns_account"}
  ]
}
```

---

## 14. Visualization

### Entity graph visualization

```http
GET /api/doclib/viz/entity-graph/ent_john_doe?depth=3
Authorization: Bearer {{token}}
```

### Transaction flow visualization

```http
GET /api/doclib/viz/transaction-flow/ent_acct_4521?depth=3
Authorization: Bearer {{token}}
```

**Response**:
```json
{
  "nodes": [
    {"id": "ent_acct_4521", "type": "account", "label": "HSBC ****4521"},
    {"id": "ent_acct_7890", "type": "account", "label": "Bank of Cyprus ****7890"},
    {"id": "ent_acct_3456", "type": "account", "label": "Panama National ****3456"}
  ],
  "edges": [
    {"source": "ent_acct_4521", "target": "ent_acct_7890", "relation": "wire_transfer", "metadata": {"amount": "450000", "date": "2026-02-15"}},
    {"source": "ent_acct_7890", "target": "ent_acct_3456", "relation": "wire_transfer", "metadata": {"amount": "445000", "date": "2026-02-16"}}
  ]
}
```

### Case relationship map

```http
GET /api/doclib/viz/case-map/case_shadow_wire
Authorization: Bearer {{token}}
```

### Document similarity clusters

```http
GET /api/doclib/viz/doc-clusters
Authorization: Bearer {{token}}
```

### Investigation board (kanban-style)

```http
GET /api/doclib/viz/investigation-board/case_shadow_wire
Authorization: Bearer {{token}}
```

---

## 15. Discovery / Search

### Full discovery search

```http
POST /api/doclib/discovery/search
Content-Type: application/json
Authorization: Bearer {{token}}

{
  "text": "wire transfer shell company Panama",
  "boolean_query": "(wire AND transfer) AND (Panama OR Cyprus) NOT legitimate",
  "entity_ids": ["ent_john_doe"],
  "case_ids": ["case_shadow_wire"],
  "classification_levels": ["confidential", "secret"],
  "doc_types": ["financial_report", "intelligence_briefing"],
  "date_from": "2025-01-01T00:00:00Z",
  "date_to": "2026-12-31T23:59:59Z",
  "tags": ["aml", "suspicious"],
  "departments": ["dept_fiu"],
  "sort_by": "relevance",
  "limit": 25,
  "offset": 0
}
```

### Save an investigative query

```http
POST /api/doclib/discovery/queries
Content-Type: application/json
Authorization: Bearer {{token}}

{
  "name": "Shadow Wire — All Shell Company Docs",
  "description": "Documents mentioning shell companies linked to the Shadow Wire case",
  "query": {
    "text": "shell company beneficial owner",
    "case_ids": ["case_shadow_wire"],
    "classification_levels": ["confidential", "secret"]
  },
  "case_id": "case_shadow_wire",
  "is_shared": true
}
```

### Execute a saved query

```http
POST /api/doclib/discovery/queries/sq_001/execute
Authorization: Bearer {{token}}
```

### Find near-duplicate documents

```http
GET /api/doclib/discovery/near-duplicates/doc_sar4521?threshold=0.7
Authorization: Bearer {{token}}
```

### Find co-occurring entities in documents

```http
GET /api/doclib/discovery/co-occurrences?min_count=2
Authorization: Bearer {{token}}
```

---

## 16. Analytics

### Case statistics

```http
GET /api/doclib/analytics/cases
Authorization: Bearer {{token}}
```

**Response**:
```json
{
  "total_cases": 47,
  "by_status": {
    "intake": 5,
    "investigation": 18,
    "analysis": 12,
    "legal_review": 7,
    "resolution": 3,
    "archive": 2
  },
  "by_priority": {
    "critical": 8,
    "high": 15,
    "medium": 18,
    "low": 6
  },
  "avg_resolution_days": 45
}
```

### Entity risk scoring

```http
GET /api/doclib/analytics/entity-risk/ent_john_doe
Authorization: Bearer {{token}}
```

**Response**:
```json
{
  "entity_id": "ent_john_doe",
  "risk_score": {
    "overall": 0.87,
    "factors": {
      "case_involvement": 0.9,
      "connection_density": 0.75,
      "suspicious_transactions": 0.95,
      "sanctions_proximity": 0.3
    }
  }
}
```

### Investigation backlog

```http
GET /api/doclib/analytics/backlog
Authorization: Bearer {{token}}
```

---

## 17. Alerts & Notifications

### Create an alert rule

```http
POST /api/doclib/alerts/rules
Content-Type: application/json
Authorization: Bearer {{token}}

{
  "name": "High-value transaction alert",
  "category": "transaction",
  "event_types": ["entity.created", "entity.updated"],
  "conditions": {
    "entity_type": "transaction",
    "amount_threshold": 100000,
    "suspicious": true
  },
  "severity": "critical",
  "notification_channels": ["email", "dashboard"],
  "notify_users": ["user_compliance_officer", "user_supervisor"]
}
```

### Create SLA config

```http
POST /api/doclib/alerts/sla
Content-Type: application/json
Authorization: Bearer {{token}}

{
  "name": "Critical Case SLA",
  "case_priority": "critical",
  "response_time_hours": 4,
  "resolution_time_hours": 72,
  "escalation_contacts": ["user_director", "user_deputy_director"]
}
```

### Trigger a manual alert

```http
POST /api/doclib/alerts/trigger
Content-Type: application/json
Authorization: Bearer {{token}}

{
  "category": "security",
  "severity": "critical",
  "title": "Unauthorized access attempt detected",
  "description": "User user_intern attempted to access Top Secret document doc_ts_001 without clearance",
  "resource_id": "doc_ts_001",
  "metadata": {
    "user_id": "user_intern",
    "clearance": "internal",
    "required": "top_secret",
    "ip_address": "10.0.5.99"
  }
}
```

### List alerts

```http
GET /api/doclib/alerts?status=open&severity=critical&limit=50
Authorization: Bearer {{token}}
```

### Acknowledge an alert

```http
POST /api/doclib/alerts/alert_001/acknowledge
Authorization: Bearer {{token}}
```

### Get notifications

```http
GET /api/doclib/notifications?unread=true
Authorization: Bearer {{token}}
```

### Mark notification as read

```http
POST /api/doclib/notifications/notif_001/read
Authorization: Bearer {{token}}
```

---

## 18. Webhooks

### Register a webhook

```http
POST /api/doclib/webhooks
Content-Type: application/json
Authorization: Bearer {{token}}

{
  "url": "https://siem.internal.bank.com/api/events",
  "event_types": ["document.created", "evidence.collected", "case.status_changed", "alert.triggered"],
  "secret": "webhook_hmac_secret_abc123",
  "headers": {
    "X-Source": "velocity-platform",
    "X-Environment": "production"
  }
}
```

### List webhooks

```http
GET /api/doclib/webhooks
Authorization: Bearer {{token}}
```

### Delete a webhook

```http
DELETE /api/doclib/webhooks/wh_001
Authorization: Bearer {{token}}
```

---

## 19. Connectors

### Create a connector

```http
POST /api/doclib/connectors
Content-Type: application/json
Authorization: Bearer {{token}}

{
  "name": "SWIFT Message Connector",
  "type": "financial",
  "endpoint": "sftp://swift-archive.bank.com/messages",
  "auth_type": "certificate",
  "schedule": "0 */4 * * *",
  "mapping": {
    "message_type": "doc_type",
    "sender_bic": "entities_mentioned",
    "amount": "metadata.amount"
  }
}
```

### List connectors

```http
GET /api/doclib/connectors
Authorization: Bearer {{token}}
```

---

## 20. ABAC Rules

### Create an ABAC rule

```http
POST /api/doclib/abac/rules
Content-Type: application/json
Authorization: Bearer {{token}}

{
  "name": "Deny access outside business hours",
  "description": "Prevent document access between 22:00 and 06:00 for non-admin users",
  "effect": "deny",
  "priority": 100,
  "conditions": [
    {
      "attribute": "environment.hour",
      "operator": "gte",
      "value": "22"
    },
    {
      "attribute": "subject.role",
      "operator": "neq",
      "value": "admin"
    }
  ]
}
```

### Create an ABAC rule (IP-based)

```http
POST /api/doclib/abac/rules
Content-Type: application/json
Authorization: Bearer {{token}}

{
  "name": "Restrict access to internal network",
  "effect": "deny",
  "priority": 200,
  "conditions": [
    {
      "attribute": "environment.ip_address",
      "operator": "cidr",
      "value": "10.0.0.0/8"
    }
  ]
}
```

### Evaluate ABAC decision

```http
POST /api/doclib/abac/evaluate
Content-Type: application/json
Authorization: Bearer {{token}}

{
  "subject": {
    "user_id": "user_agent007",
    "role": "investigator",
    "department": "dept_fiu",
    "clearance": "secret"
  },
  "resource": {
    "doc_id": "doc_sar4521",
    "classification": "confidential",
    "department": "dept_compliance"
  },
  "action": "read",
  "environment": {
    "ip_address": "10.0.1.45",
    "hour": "14",
    "device_type": "workstation"
  }
}
```

**Response**:
```json
{
  "allowed": true,
  "decision": "allow",
  "matched_rules": [
    {"rule_id": "rule_001", "name": "Deny access outside business hours", "effect": "allow"}
  ]
}
```

### List ABAC rules

```http
GET /api/doclib/abac/rules
Authorization: Bearer {{token}}
```

### Delete an ABAC rule

```http
DELETE /api/doclib/abac/rules/rule_001
Authorization: Bearer {{token}}
```

---

## 21. Compartments (Need-to-Know)

### Create a compartment

```http
POST /api/doclib/compartments
Content-Type: application/json
Authorization: Bearer {{token}}

{
  "name": "Operation Shadow Wire — Compartment Alpha",
  "description": "Need-to-know compartment for the core investigation team only",
  "classification": "top_secret"
}
```

### Add a member

```http
POST /api/doclib/compartments/comp_alpha/members
Content-Type: application/json
Authorization: Bearer {{token}}

{
  "user_id": "user_lead_inv"
}
```

### Add a resource to compartment

```http
POST /api/doclib/compartments/comp_alpha/resources
Content-Type: application/json
Authorization: Bearer {{token}}

{
  "resource_id": "doc_ts_intel_brief"
}
```

### Check compartment access

A user can only access a resource if they are a member of the compartment that contains the resource.

### Get user's compartments

```http
GET /api/doclib/compartments/user/user_lead_inv
Authorization: Bearer {{token}}
```

### Remove a member

```http
DELETE /api/doclib/compartments/comp_alpha/members/user_former_inv
Authorization: Bearer {{token}}
```

---

## 22. ReBAC (Relationship-Based Access)

### Check relationship-based access

```http
POST /api/doclib/rebac/check
Content-Type: application/json
Authorization: Bearer {{token}}

{
  "subject_id": "ent_user_agent007",
  "object_id": "ent_doc_sar4521",
  "relation": "can_read"
}
```

**Response**:
```json
{
  "allowed": true,
  "path": [
    {"from": "ent_user_agent007", "relation": "assigned_to", "to": "ent_case_shadow_wire"},
    {"from": "ent_case_shadow_wire", "relation": "contains", "to": "ent_doc_sar4521"}
  ]
}
```

### Check entity permission (transitive)

```http
POST /api/doclib/rebac/entity-permission
Content-Type: application/json
Authorization: Bearer {{token}}

{
  "user_entity_id": "ent_user_agent007",
  "resource_entity_id": "ent_shellcorp",
  "action": "investigate"
}
```

---

## 23. Unified Access Evaluation

This is the **most powerful access check** — it combines RBAC + ABAC + Need-to-Know + ReBAC.

```http
POST /api/doclib/access/unified-evaluate
Content-Type: application/json
Authorization: Bearer {{token}}

{
  "subject": {
    "user_id": "user_agent007",
    "role": "investigator",
    "department": "dept_fiu",
    "clearance": "secret"
  },
  "resource": {
    "doc_id": "doc_ts_intel_brief",
    "classification": "top_secret",
    "department": "dept_intel",
    "case_id": "case_shadow_wire"
  },
  "action": "read",
  "environment": {
    "ip_address": "10.0.1.45",
    "hour": "14"
  }
}
```

**Response (denied)**:
```json
{
  "allowed": false,
  "decision": "deny",
  "evaluations": {
    "rbac": {"allowed": false, "reason": "clearance level secret < top_secret"},
    "abac": {"allowed": true, "reason": "all conditions met"},
    "need_to_know": {"allowed": false, "reason": "user not in compartment for doc_ts_intel_brief"},
    "rebac": {"allowed": true, "reason": "case assignment path exists"}
  },
  "denial_reasons": [
    "RBAC: clearance level secret < top_secret",
    "Need-to-Know: user not in required compartment"
  ]
}
```

---

## 24. Shamir Secret Sharing

### Protect a document with Shamir

```http
POST /api/doclib/shamir/protect
Content-Type: application/json
Authorization: Bearer {{token}}

{
  "doc_id": "doc_nuclear_codes",
  "level": "critical",
  "holder_ids": ["user_director", "user_deputy", "user_secoff1", "user_secoff2", "user_secoff3"]
}
```

**Response**: The encryption key is split into 5 shares (3-of-5 threshold). Each holder receives their share.

### Get protection config

```http
GET /api/doclib/shamir/doc_nuclear_codes/config
Authorization: Bearer {{token}}
```

### Collect your share (as a share holder)

```http
POST /api/doclib/shamir/doc_nuclear_codes/collect
Authorization: Bearer {{token}}
```

### Request access to a protected document

```http
POST /api/doclib/shamir/request-access
Content-Type: application/json
Authorization: Bearer {{token}}

{
  "doc_id": "doc_nuclear_codes",
  "reason": "Required for annual nuclear posture review briefing"
}
```

### Submit a share (as a holder) for a pending request

```http
POST /api/doclib/shamir/requests/req_001/submit-share
Content-Type: application/json
Authorization: Bearer {{token}}

{
  "share": "base64_encoded_share_data"
}
```

### Reconstruct and access the document

```http
POST /api/doclib/shamir/requests/req_001/reconstruct
Authorization: Bearer {{token}}
```

Returns the decrypted document content once the threshold of shares is met.

### Revoke Shamir protection

```http
POST /api/doclib/shamir/doc_nuclear_codes/revoke
Authorization: Bearer {{token}}
```

### Shamir audit log

```http
GET /api/doclib/shamir/doc_nuclear_codes/audit
Authorization: Bearer {{token}}
```

---

## 25. Indexing

### Rebuild all indexes

```http
POST /api/doclib/index/rebuild
Authorization: Bearer {{token}}
```

### Lookup by index

```http
GET /api/doclib/index/lookup?category=doc&field=classification&value=secret
Authorization: Bearer {{token}}
```

```http
GET /api/doclib/index/lookup?category=doc&field=dept&value=dept_fiu
Authorization: Bearer {{token}}
```

```http
GET /api/doclib/index/lookup?category=doc&field=tag&value=aml
Authorization: Bearer {{token}}
```

**Response**:
```json
{
  "index_key": "idx:doc:tag:aml",
  "ids": ["doc_sar4521", "doc_sar4522", "doc_aml_policy"],
  "total": 3
}
```

---

## 26. Enhanced Audit

### Create an anomaly detection rule

```http
POST /api/doclib/audit/anomaly-rules
Content-Type: application/json
Authorization: Bearer {{token}}

{
  "name": "Bulk download detection",
  "rule_type": "bulk_download",
  "threshold": 50,
  "window_minutes": 60,
  "severity": "critical",
  "description": "Alert when a user downloads more than 50 documents in 1 hour"
}
```

### Create off-hours access rule

```http
POST /api/doclib/audit/anomaly-rules
Content-Type: application/json
Authorization: Bearer {{token}}

{
  "name": "Off-hours access detection",
  "rule_type": "off_hours",
  "threshold": 5,
  "window_minutes": 480,
  "severity": "high",
  "description": "Alert when a user accesses more than 5 classified documents outside business hours (10PM-6AM)"
}
```

### Run anomaly detection

```http
POST /api/doclib/audit/detect-anomalies
Authorization: Bearer {{token}}
```

**Response**:
```json
{
  "anomalies": [
    {
      "anomaly_id": "anom_001",
      "rule_id": "rule_bulk_dl",
      "rule_name": "Bulk download detection",
      "actor": "user_intern",
      "doc_id": "doc_sar4521",
      "event_count": 73,
      "severity": "critical",
      "detected_at": "2026-03-16T03:45:00Z",
      "resolved": false
    }
  ],
  "total": 1
}
```

### List anomalies (unresolved only)

```http
GET /api/doclib/audit/anomalies?unresolved=true
Authorization: Bearer {{token}}
```

### Resolve an anomaly

```http
POST /api/doclib/audit/anomalies/anom_001/resolve
Authorization: Bearer {{token}}
```

### Compliance dashboard

```http
GET /api/doclib/audit/compliance-dashboard
Authorization: Bearer {{token}}
```

**Response**:
```json
{
  "compliance_score": 0.94,
  "total_events": 15420,
  "total_documents_audited": 847,
  "anomaly_counts": {
    "bulk_download": 1,
    "off_hours": 3,
    "rapid_queries": 0
  },
  "top_accessed_documents": [
    {"doc_id": "doc_sar4521", "access_count": 142},
    {"doc_id": "doc_policy_aml", "access_count": 98}
  ],
  "top_active_users": [
    {"actor": "user_analyst01", "event_count": 1240},
    {"actor": "user_supervisor", "event_count": 890}
  ]
}
```

### Forensic audit search

```http
POST /api/doclib/audit/forensic-search
Content-Type: application/json
Authorization: Bearer {{token}}

{
  "actor": "user_intern",
  "action": "download",
  "doc_id": "",
  "from": "2026-03-15T00:00:00Z",
  "to": "2026-03-17T00:00:00Z"
}
```

---

## 27. Advanced Workflow

### Create a multi-stage workflow template

```http
POST /api/doclib/adv-workflows/templates
Content-Type: application/json
Authorization: Bearer {{token}}

{
  "name": "Evidence Transfer Workflow",
  "description": "Multi-stage approval for transferring evidence between agencies",
  "category": "evidence_transfer",
  "stages": [
    {
      "name": "Supervisor Approval",
      "type": "approval",
      "required_approvals": 1,
      "approvers": ["role:supervisor"],
      "sla_hours": 24
    },
    {
      "name": "Legal Review",
      "type": "review",
      "required_approvals": 1,
      "approvers": ["role:legal_counsel"],
      "sla_hours": 48
    },
    {
      "name": "Agency Director Sign-off",
      "type": "approval",
      "required_approvals": 2,
      "approvers": ["user:user_director", "user:user_deputy_director"],
      "sla_hours": 72
    },
    {
      "name": "Receiving Agency Notification",
      "type": "notification",
      "approvers": [],
      "sla_hours": 0
    }
  ],
  "escalation_rules": {
    "auto_escalate_after_hours": 96,
    "escalate_to": "user_director"
  }
}
```

### Start an advanced workflow

```http
POST /api/doclib/adv-workflows
Content-Type: application/json
Authorization: Bearer {{token}}

{
  "template_id": "adv_tmpl_evidence_transfer",
  "resource_id": "ev_hsbc_001",
  "resource_type": "evidence",
  "metadata": {
    "from_agency": "FBI",
    "to_agency": "SEC",
    "reason": "Joint investigation into securities fraud"
  }
}
```

### Approve a stage

```http
POST /api/doclib/adv-workflows/adv_inst_001/approve
Content-Type: application/json
Authorization: Bearer {{token}}

{
  "comment": "Approved — legal basis confirmed under MOU #2026-045"
}
```

### Reject a stage

```http
POST /api/doclib/adv-workflows/adv_inst_001/reject
Content-Type: application/json
Authorization: Bearer {{token}}

{
  "reason": "Missing receiving agency's written acknowledgment"
}
```

### Get workflow instance

```http
GET /api/doclib/adv-workflows/adv_inst_001
Authorization: Bearer {{token}}
```

### List all workflow instances

```http
GET /api/doclib/adv-workflows
Authorization: Bearer {{token}}
```

---

## 28. Data Governance

### Create a retention schedule

```http
POST /api/doclib/governance/retention-schedules
Content-Type: application/json
Authorization: Bearer {{token}}

{
  "name": "Financial Records - 7 Year Retention",
  "description": "BSA/AML requires 7-year retention of transaction records",
  "classification_filter": "confidential",
  "doc_type_filter": "financial_report",
  "retention_days": 2555,
  "action": "archive",
  "regulation": "BSA/AML 31 CFR 1010.430"
}
```

### Create a destruction schedule

```http
POST /api/doclib/governance/retention-schedules
Content-Type: application/json
Authorization: Bearer {{token}}

{
  "name": "Internal Memos - 2 Year Destruction",
  "classification_filter": "internal",
  "doc_type_filter": "memo",
  "retention_days": 730,
  "action": "destroy"
}
```

### Evaluate retention (find expired documents)

```http
POST /api/doclib/governance/evaluate-retention
Authorization: Bearer {{token}}
```

**Response**:
```json
{
  "actions": [
    {
      "doc_id": "doc_memo_2024_001",
      "schedule_id": "sched_memo_destroy",
      "action": "destroy",
      "reason": "Document created 2024-01-15, retention period 730 days expired",
      "doc_title": "Internal Memo - Budget Allocation Q1"
    }
  ],
  "total": 1
}
```

### Create a regional restriction

```http
POST /api/doclib/governance/regional-restrictions
Content-Type: application/json
Authorization: Bearer {{token}}

{
  "name": "EU Data Residency - GDPR",
  "description": "Documents containing EU personal data must not be stored or accessed outside EU",
  "jurisdiction": "EU",
  "allowed_regions": ["eu-west-1", "eu-central-1"],
  "denied_regions": ["us-east-1", "ap-southeast-1"],
  "doc_type_filter": "personal_data"
}
```

### Create a classification enforcement rule

```http
POST /api/doclib/governance/classification-rules
Content-Type: application/json
Authorization: Bearer {{token}}

{
  "name": "Auto-classify financial docs as Confidential",
  "description": "Any document tagged 'financial' or 'transaction' must be at least Confidential",
  "conditions": {
    "tags_contain": ["financial", "transaction"],
    "current_classification_below": "confidential"
  },
  "enforce_classification": "confidential"
}
```

---

## 29. Data Ingestion

### Create an ingestion pipeline

```http
POST /api/doclib/ingestion/pipelines
Content-Type: application/json
Authorization: Bearer {{token}}

{
  "name": "SWIFT Message Ingestion",
  "description": "Ingest SWIFT MT103 wire transfer messages from archive",
  "source_type": "financial",
  "source_config": {
    "endpoint": "sftp://swift-archive.bank.com/mt103",
    "format": "swift_mt103",
    "auth": "certificate"
  },
  "transforms": [
    {
      "operation": "map_field",
      "config": {
        "source_field": "sender_bic",
        "target_field": "entity_source"
      }
    },
    {
      "operation": "set_classification",
      "config": {
        "level": "confidential"
      }
    },
    {
      "operation": "add_tag",
      "config": {
        "tag": "swift_mt103"
      }
    }
  ],
  "schedule": "0 */4 * * *",
  "enabled": true
}
```

### Run a pipeline manually

```http
POST /api/doclib/ingestion/pipelines/pipe_swift/run
Authorization: Bearer {{token}}
```

### List pipeline runs

```http
GET /api/doclib/ingestion/runs?pipeline_id=pipe_swift
Authorization: Bearer {{token}}
```

### Ingest a single record

```http
POST /api/doclib/ingestion/ingest
Content-Type: application/json
Authorization: Bearer {{token}}

{
  "pipeline_id": "pipe_swift",
  "title": "SWIFT MT103 - WT-2026-03-16-001",
  "content": "Sender: HSBCGB2L\nReceiver: BOFAUS3N\nAmount: USD 450,000.00\nRef: WT-2026-03-16-001",
  "doc_type": "transaction_record",
  "classification": "confidential",
  "tags": ["swift_mt103", "wire_transfer", "high_value"],
  "metadata": {
    "sender_bic": "HSBCGB2L",
    "receiver_bic": "BOFAUS3N",
    "amount": "450000",
    "currency": "USD",
    "value_date": "2026-03-16"
  }
}
```

---

## 30. Document Governance

### Sign a document

```http
POST /api/doclib/documents/doc_sar4521/sign
Content-Type: application/json
Authorization: Bearer {{token}}

{
  "purpose": "approval",
  "certificate_ref": "cert_user_agent007_2026"
}
```

### List signatures

```http
GET /api/doclib/documents/doc_sar4521/signatures
Authorization: Bearer {{token}}
```

### Verify a signature

```http
GET /api/doclib/signatures/sig_001/verify
Authorization: Bearer {{token}}
```

### Revoke a signature

```http
POST /api/doclib/signatures/sig_001/revoke
Content-Type: application/json
Authorization: Bearer {{token}}

{
  "reason": "Signer's certificate was compromised"
}
```

### Place legal hold

```http
POST /api/doclib/documents/doc_sar4521/legal-hold
Content-Type: application/json
Authorization: Bearer {{token}}

{
  "reason": "Litigation hold — SEC v. ShellCorp LLC, Case No. 2026-CV-4521",
  "case_ref": "case_shadow_wire",
  "custodian": "user_legal_counsel"
}
```

### Release legal hold

```http
DELETE /api/doclib/legal-holds/hold_001
Content-Type: application/json
Authorization: Bearer {{token}}

{
  "reason": "Litigation resolved — settlement reached"
}
```

### Create retention policy

```http
POST /api/doclib/retention-policies
Content-Type: application/json
Authorization: Bearer {{token}}

{
  "name": "SAR Retention - 5 Years",
  "classification": "confidential",
  "doc_types": ["financial_report"],
  "retention_days": 1825,
  "action_on_expiry": "archive"
}
```

### Apply retention policy to a document

```http
POST /api/doclib/documents/doc_sar4521/retention
Content-Type: application/json
Authorization: Bearer {{token}}

{
  "policy_id": "ret_pol_sar_5yr"
}
```

### Schedule document destruction

```http
POST /api/doclib/documents/doc_old_memo/destruction
Content-Type: application/json
Authorization: Bearer {{token}}

{
  "policy_id": "ret_pol_memo_2yr",
  "scheduled_at": "2026-06-01T00:00:00Z"
}
```

### Approve destruction

```http
POST /api/doclib/destructions/destr_001/approve
Authorization: Bearer {{token}}
```

---

## 31. Policy Documents

### Create a policy document

```http
POST /api/doclib/policy-docs
Content-Type: application/json
Authorization: Bearer {{token}}

{
  "title": "Acceptable Use Policy for Classified Systems",
  "content": "All personnel with access to classified systems must...",
  "category": "security",
  "classification": "internal",
  "target_departments": ["dept_all"]
}
```

### Submit for review

```http
POST /api/doclib/policy-docs/pol_001/submit-review
Authorization: Bearer {{token}}
```

### Review a policy

```http
POST /api/doclib/policy-docs/pol_001/review
Content-Type: application/json
Authorization: Bearer {{token}}

{
  "action": "approve",
  "comment": "Policy is comprehensive and aligns with NIST 800-53 controls"
}
```

### Approve and publish

```http
POST /api/doclib/policy-docs/pol_001/approve
Content-Type: application/json
Authorization: Bearer {{token}}

{
  "action": "approve",
  "comment": "Final approval for publication"
}
```

```http
POST /api/doclib/policy-docs/pol_001/publish
Content-Type: application/json
Authorization: Bearer {{token}}

{
  "target_audience": ["dept_all"],
  "effective_date": "2026-04-01T00:00:00Z"
}
```

### Amend a policy

```http
POST /api/doclib/policy-docs/pol_001/amend
Content-Type: application/json
Authorization: Bearer {{token}}

{
  "reason": "Updated to include mobile device access provisions"
}
```

---

## 32. Org Access Sync

### Add member with automatic clearance sync

```http
POST /api/doclib/org-sync/add-member
Content-Type: application/json
Authorization: Bearer {{token}}

{
  "user_id": "user_new_analyst",
  "unit_id": "unit_fiu",
  "role": "analyst"
}
```

### Remove member with clearance cleanup

```http
POST /api/doclib/org-sync/remove-member
Content-Type: application/json
Authorization: Bearer {{token}}

{
  "user_id": "user_former_analyst",
  "unit_id": "unit_fiu"
}
```

---

## 33. Context-Aware Document Access

### Evaluate document access (full context)

```http
POST /api/doclib/access/evaluate-document
Content-Type: application/json
Authorization: Bearer {{token}}

{
  "user_id": "user_agent007",
  "doc_id": "doc_sar4521",
  "action": "read",
  "ip_address": "10.0.1.45",
  "device_id": "dev_workstation_007",
  "session_id": "sess_abc123"
}
```

---

## 34. Events

### Query platform events

```http
GET /api/doclib/events?type=document.created&from=2026-03-01T00:00:00Z&to=2026-03-31T23:59:59Z&limit=100
Authorization: Bearer {{token}}
```

---

## 35. Dashboard

### Get dashboard statistics

```http
GET /api/doclib/dashboard/stats
Authorization: Bearer {{token}}
```

**Response**:
```json
{
  "total_documents": 847,
  "by_status": {
    "draft": 45,
    "under_review": 23,
    "approved": 312,
    "published": 401,
    "archived": 66
  },
  "by_classification": {
    "public": 120,
    "internal": 340,
    "confidential": 280,
    "secret": 95,
    "top_secret": 12
  },
  "recent_documents": [...]
}
```

---

## Real-World Investigation Scenario

Here's a complete workflow for a money laundering investigation:

### Step 1: Create the organization structure
```http
POST /api/doclib/orgs → Create "Federal Investigation Bureau"
POST /api/doclib/orgs/{{companyID}}/depts → Create "Financial Crimes Division"
POST /api/doclib/depts/{{deptID}}/units → Create "Money Laundering Unit"
POST /api/doclib/units/{{unitID}}/members → Add investigators
```

### Step 2: Set clearances
```http
PUT /api/doclib/clearance/user_lead_inv → Set "secret" clearance
PUT /api/doclib/clearance/user_analyst01 → Set "confidential" clearance
```

### Step 3: Create entities
```http
POST /api/doclib/entities/persons → Create suspect "John Doe"
POST /api/doclib/entities/organizations → Create "ShellCorp LLC"
POST /api/doclib/entities/accounts → Create bank accounts
POST /api/doclib/entities/link → Link John Doe → ShellCorp (beneficial_owner)
POST /api/doclib/entities/link → Link ShellCorp → Account (owns_account)
```

### Step 4: Create the case
```http
POST /api/doclib/cases → Create "Operation Shadow Wire"
POST /api/doclib/cases/{{caseID}}/entities → Link suspect
POST /api/doclib/cases/{{caseID}}/entities → Link shell company
```

### Step 5: Collect evidence
```http
POST /api/doclib/evidence → Bank statements
POST /api/doclib/evidence → Wire transfer records
POST /api/doclib/documents → Create SAR
POST /api/doclib/cases/{{caseID}}/documents → Link SAR to case
```

### Step 6: Investigate using graph intelligence
```http
GET /api/doclib/graph/shortest-path?from=ent_john_doe&to=ent_acct_7890
GET /api/doclib/graph/network/ent_john_doe?depth=3
GET /api/doclib/viz/transaction-flow/ent_acct_4521
```

### Step 7: Search and discover
```http
POST /api/doclib/discovery/search → "wire transfer shell company"
GET /api/doclib/discovery/near-duplicates/{{docID}}
GET /api/doclib/graph/patterns?case_ids={{caseID1}},{{caseID2}}
```

### Step 8: Share with other agencies
```http
POST /api/doclib/documents/{{docID}}/shares → Share with SEC
POST /api/doclib/documents/{{docID}}/dispatch → Dispatch to FinCEN
```

### Step 9: Workflow for evidence transfer
```http
POST /api/doclib/adv-workflows → Start evidence transfer workflow
POST /api/doclib/adv-workflows/{{instanceID}}/approve → Supervisor approves
POST /api/doclib/adv-workflows/{{instanceID}}/approve → Legal approves
POST /api/doclib/adv-workflows/{{instanceID}}/approve → Director approves
```

### Step 10: Audit and compliance
```http
GET /api/doclib/audit/compliance-dashboard
POST /api/doclib/audit/forensic-search → Search all access events
GET /api/doclib/documents/{{docID}}/access-chain → Full audit trail
```
