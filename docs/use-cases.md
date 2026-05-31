# Velocity Use Cases And Business Models

Velocity is an embedded storage, object, search, and knowledge-graph platform for applications that need private, local-first, or self-hosted data infrastructure. It can be used as a single package for key/value data, SQL-like rows, object files, document search, entity extraction, relationship modeling, audit trails, and compliance workflows.

## Core Positioning

Velocity is useful when a product team wants these capabilities without operating separate services for:

- Embedded key/value storage.
- Object storage and file management.
- S3-compatible object APIs.
- Full-text document search.
- Knowledge graph indexing and relationship search.
- Entity extraction and entity resolution.
- Compliance, audit, retention, secrets, and governance metadata.
- Local or self-hosted deployment.

The strongest fit is software that needs searchable data and files inside the product, especially where privacy, compliance, offline operation, or deployment simplicity matters.

## Primary User Segments

### Independent Software Vendors

ISVs can embed Velocity into SaaS, desktop, on-prem, and edge products to provide storage, file upload, search, audit, and KG features without bundling multiple infrastructure dependencies.

Common buyers:

- Vertical SaaS teams.
- Security and compliance product teams.
- Legal tech vendors.
- Healthcare workflow vendors.
- Finance, KYC, and risk vendors.
- Developer-tool vendors.
- AI application builders.

### Internal Platform Teams

Platform teams can use Velocity as a self-contained data layer for internal tools, automation systems, compliance portals, operational consoles, and local-first employee applications.

### Regulated Organizations

Organizations with sensitive data can keep documents, evidence, secrets metadata, and searchable indexes under their own control.

Examples:

- Banks and fintechs.
- Healthcare providers.
- Insurers.
- Government contractors.
- Legal firms.
- Critical infrastructure operators.

### Edge And Offline Applications

Velocity can run close to the data source when network access is unreliable, expensive, or disallowed.

Examples:

- Field service laptops.
- Factory-floor terminals.
- Medical devices or clinic-local tools.
- Disaster recovery kits.
- Air-gapped review systems.

## Use Case Catalog

### 1. Document Search For Applications

Users upload documents, manuals, PDFs, emails, CSV files, JSON files, Office documents, and reports. Velocity extracts text, chunks content, indexes it, and lets users search by document content.

Example workflows:

- Upload a developer manual and search for `merge`, `rebase`, or `stash`.
- Upload policy PDFs and search for `high risk KYC exception`.
- Upload incident reports and search for `database timeout mitigation`.
- Upload contracts and search for `termination notice period`.

Required capabilities:

- File upload and metadata storage.
- Text extraction.
- Full-text search.
- Snippet rendering around matched terms.
- Document details view.
- Source/object preview or download.

Business value:

- Adds search to products without running Elasticsearch/OpenSearch.
- Makes uploaded files immediately useful.
- Reduces manual document browsing.

### 2. Embedded Knowledge Base

Velocity can power a local product knowledge base where every installation has its own searchable corpus.

Examples:

- A desktop app with offline product manuals.
- A CLI assistant with local docs and runbooks.
- A support tool bundled with customer-specific documentation.
- An internal engineering console with architecture docs and incident notes.

Business value:

- Works offline.
- Keeps data local.
- Lowers infrastructure cost.
- Enables product differentiation through built-in search.

### 3. Case And Evidence Management

Velocity can store cases, evidence files, audit notes, envelopes, related entities, and persistent relationships.

Example domains:

- Legal discovery.
- Compliance investigations.
- Fraud investigations.
- Insurance claims.
- Customer due diligence.
- Security incidents.

Example relationships:

- Case references customer.
- Case supported by evidence object.
- Evidence satisfies policy.
- Incident mitigated by runbook.
- Runbook depends on service.
- Service owned by team.

Business value:

- Turns document repositories into explainable case graphs.
- Helps reviewers see why evidence matters.
- Supports traceability and audit review.

### 4. Compliance And Audit Evidence

Velocity can store compliance documents, controls, policies, audit trails, retention metadata, legal holds, and evidence relationships.

Example workflows:

- Search `SOC2 access review evidence`.
- Link a policy to the evidence files that prove compliance.
- Track which customer or system each control applies to.
- Preserve immutable audit chain records.
- Export audit-ready evidence packages.

Business value:

- Reduces audit preparation time.
- Keeps evidence and search under customer control.
- Supports compliance products and internal GRC tools.

### 5. KYC, AML, And Customer Risk Review

Velocity can store customer profiles, KYC documents, risk flags, invoices, investigation notes, policy evidence, and reviewer decisions.

Example workflows:

- Search `high risk customer sanctions evidence`.
- Link customer profile to cases and documents.
- Extract identifiers such as domains, emails, business IDs, dates, and monetary values.
- Review all evidence related to a customer.

Business value:

- Useful for fintech and compliance vendors.
- Provides explainable search over regulated evidence.
- Avoids sending sensitive customer documents to external search services.

### 6. Operational Runbook And Incident Search

Velocity can index incidents, logs, postmortems, service metadata, runbooks, teams, and ownership relationships.

Example workflows:

- Search `payment timeout mitigation owner`.
- Find a postmortem and related runbook.
- Traverse service ownership.
- Link incidents to affected services and responsible teams.

Business value:

- Faster incident response.
- Better operational memory.
- Search plus relationship context in one local component.

### 7. Object Storage With Search

Velocity can be used as an object store where files become searchable and retain object metadata.

Example workflows:

- Upload files through the web UI.
- Search by object content.
- Filter by content type, tag, owner, or object metadata.
- Open the object directly from search results.

Business value:

- Combines object storage and search in one package.
- Useful for embedded admin panels and self-hosted apps.

### 8. Local-First AI And Retrieval Applications

Velocity can serve as a local retrieval substrate for AI apps, agent tools, and assistant experiences.

Example workflows:

- Store documents locally.
- Extract searchable text.
- Build chunks for retrieval.
- Optionally attach embeddings and hybrid search.
- Use KG relations for context expansion.

Business value:

- Enables private RAG-style applications.
- Reduces dependency on hosted vector databases.
- Supports offline or self-hosted AI workflows.

### 9. Developer Documentation Search

Velocity can power documentation search inside developer tools.

Example workflows:

- Index Markdown, HTML, PDF manuals, and code notes.
- Search commands, errors, configuration options, and examples.
- Link results to source files or uploaded documents.

Business value:

- Faster developer onboarding.
- Built-in product documentation search.
- Useful for SDKs, internal portals, and support tools.

### 10. Secure Secrets Metadata Search

Velocity can index secret metadata without exposing raw secret values.

Example workflows:

- Search for secret names, owners, tags, rotation status, and linked systems.
- Link secrets to services, envelopes, and audit records.
- Keep raw secret values out of the KG index.

Business value:

- Improves operational visibility without weakening secret security.
- Supports security administration and compliance evidence.

### 11. SQL-Like Embedded Data Apps

Velocity includes SQL-like row storage and a database/sql driver. Products can store structured records and index them into KG.

Example workflows:

- Store tickets, customers, policies, invoices, and cases as rows.
- Search across rows and documents together.
- Link row entities to uploaded evidence files.

Business value:

- Gives embedded apps a richer data layer.
- Reduces need for separate SQLite plus object store plus search stack.

### 12. Audit-Trail And Immutable Record Systems

Velocity can store append-only audit records, compliance tags, and immutable chains.

Example workflows:

- Track who uploaded a document.
- Track who viewed or deleted records.
- Track evidence revisions.
- Export forensic audit packages.

Business value:

- Supports regulated internal systems.
- Strengthens trust and traceability.

### 13. Entity Resolution And Deduplication

Velocity can extract and resolve entities across documents and records.

Example workflows:

- Detect the same customer mentioned in multiple files.
- Propose merges for duplicate entities.
- Maintain canonical aliases.
- Review entity merge decisions.

Business value:

- Converts unstructured documents into structured knowledge.
- Helps support, compliance, legal, and risk teams avoid duplicate work.

### 14. Relationship And Dependency Search

Velocity can model persistent relations and traverse them.

Example workflows:

- Find all documents supporting a case.
- Find all services owned by a team.
- Find policies connected to a compliance control.
- Find runbooks linked to incidents.

Business value:

- Enables graph-aware workflows without operating a separate graph database.

### 15. Self-Hosted File Intelligence Portal

Velocity can power a single binary or small service that provides upload, search, indexing, KG, and audit capabilities.

Example buyers:

- Small compliance teams.
- Engineering teams.
- Legal offices.
- Research groups.
- Managed service providers.

Business value:

- Simple deployment.
- Private by default.
- Low infrastructure overhead.

## Business Models

### 1. Open-Core Embedded Database

Offer Velocity core storage, object, and search under an open-source license, with paid enterprise modules.

Paid features can include:

- Advanced access control.
- SSO, OIDC, LDAP, and SCIM.
- Compliance packs.
- Audit export.
- High-availability replication.
- Advanced KG analytics.
- Enterprise support.

### 2. Commercial SDK License

Sell Velocity as an embeddable SDK for ISVs that want redistribution rights, support, and long-term maintenance.

Pricing options:

- Per developer seat.
- Per application.
- Per deployed customer.
- Annual OEM license.

### 3. Self-Hosted Enterprise Platform

Package Velocity as a deployable internal search and evidence portal.

Pricing options:

- Annual subscription.
- Per user.
- Per node.
- Per indexed document volume.

### 4. Managed Cloud Service

Offer hosted Velocity workspaces with API access, object search, KG, governance, and admin UI.

Pricing options:

- Free developer tier.
- Usage-based storage and indexing.
- Per-seat collaboration.
- Enterprise compliance tier.

### 5. Compliance Evidence Product

Build a vertical product on top of Velocity for audit evidence and policy search.

Target customers:

- SOC2-focused SaaS companies.
- Fintech compliance teams.
- Healthcare compliance teams.
- Security consultancies.

Revenue:

- Subscription.
- Audit package export add-on.
- Compliance framework packs.
- Professional services onboarding.

### 6. Legal And Investigation Workbench

Use Velocity as the backend for evidence upload, search, entity extraction, review, and case graphing.

Revenue:

- Per matter/case.
- Per reviewer seat.
- Storage add-ons.
- On-prem licensing.

### 7. Private RAG Backend

Sell Velocity as a local-first retrieval backend for AI products that need document search and graph context.

Revenue:

- SDK license.
- Enterprise support.
- Model/provider integration add-ons.
- On-prem deployment packages.

### 8. Developer Tooling Product

Use Velocity to power local docs, codebase notes, CLI command memory, and searchable manuals.

Revenue:

- Pro desktop app.
- Team workspace.
- Enterprise offline package.

### 9. Edge Data Appliance

Bundle Velocity into appliances for factories, clinics, field offices, or disconnected environments.

Revenue:

- Hardware/software bundle.
- Annual support.
- Site license.
- Compliance maintenance contract.

### 10. Integration Marketplace

Build connectors for file systems, S3, SharePoint, Google Drive, Git repositories, Slack exports, ticketing systems, and databases.

Revenue:

- Paid connectors.
- Connector marketplace revenue share.
- Enterprise connector development.

## Product Packaging Ideas

### Velocity Core

- Embedded KV.
- Object storage.
- Basic search.
- Go APIs.
- CLI.

### Velocity Search

- Document extraction.
- Full-text search.
- Object search.
- Admin UI.
- Indexing jobs.

### Velocity KG

- Entity extraction.
- Relations.
- Ontology.
- Context search.
- Graph traversal.
- Entity resolution.

### Velocity Compliance

- Audit trail.
- Retention.
- Legal hold.
- Classification.
- Evidence packages.

### Velocity Enterprise

- SSO.
- RBAC/IAM.
- MFA.
- Multi-tenant controls.
- Advanced audit exports.
- Support and SLA.

## Ideal First Products

The most realistic first commercial products are:

1. Embedded searchable object store for Go applications.
2. Self-hosted document intelligence portal.
3. Compliance evidence search and case graph.
4. Local-first private RAG backend.
5. Incident/runbook operational memory system.

These use cases are concrete, easy to demonstrate, and align well with the current codebase.

