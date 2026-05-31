# Frontend Requirements For Velocity

This document defines the frontend requirements for a professional Velocity UI that can support storage, object search, knowledge graph workflows, compliance evidence, and operational use cases.

The UI should be minimal by default, progressive by disclosure, and centered around user tasks rather than internal API concepts.

## Product Principle

The interface should feel like a document and knowledge console, not a database demo.

Users should be able to:

- Upload files.
- Search content.
- See relevant snippets.
- Open document details.
- Understand indexing status.
- Manage files and metadata.
- Explore relationships only when needed.
- Perform admin tasks without cluttering the primary search experience.

## Primary Personas

### Business Reviewer

Needs to upload, search, review, and export evidence.

Expected UI:

- Simple search.
- Document preview.
- Document details.
- Tags and metadata.
- Case/evidence links.

### Support Or Operations Engineer

Needs to find runbooks, incidents, owners, and related services.

Expected UI:

- Search by error, incident, service, owner, or command.
- See matched runbook snippets.
- See linked incidents and services.
- Traverse ownership relationships.

### Compliance Analyst

Needs to search policies, controls, evidence, KYC documents, audit trails, and decisions.

Expected UI:

- Evidence search.
- Filters by document type, framework, status, owner, date.
- Case/policy relationship view.
- Export or audit package workflow.

### Developer

Needs to use Velocity locally, inspect indexed data, debug search, and test KG behavior.

Expected UI:

- Search diagnostics.
- Indexing status.
- API payload inspection.
- Advanced KG tools hidden behind admin/dev mode.

### Administrator

Needs to configure users, access, indexing, retention, backups, and system health.

Expected UI:

- User and role management.
- Indexing jobs.
- Storage health.
- Audit logs.
- Backup/restore.

## Information Architecture

The UI should have five main sections:

1. Search
2. Files
3. Knowledge Graph
4. Compliance
5. Admin

Search should be the default landing screen after login.

## Global Navigation

Required top-level navigation:

- Search
- Files
- Graph
- Compliance
- Admin

Rules:

- Do not expose multiple search forms on one screen.
- Do not show developer-only graph actions in normal reviewer workflows.
- Do not use API names as labels unless the screen is explicitly a developer/admin screen.
- Use one primary action per view.

## Search Experience

### Search Page

The Search page is the primary user experience.

Required elements:

- One large search input.
- One Search button.
- Compact filter bar.
- Results list.
- Empty state.
- Indexing state.
- Document detail side panel or expandable detail.

Default filters:

- Match mode: Broad match.
- Result type: All.
- Limit: 10.

Optional filters:

- All words.
- Phrase.
- Fuzzy.
- Prefix.
- File type.
- Source type.
- Date range.
- Tags.
- Owner.
- Case/customer/policy ID.

Hidden advanced filters:

- Semantic/vector mode.
- Graph scoring.
- Minimum score.
- Graph depth.
- Entity type.
- Relation type.

### Search Result Card

Each search result must show:

- Document title.
- Source path.
- Content type.
- Relevant snippet centered around matched terms.
- Highlighted query terms.
- Score or confidence, only in advanced mode.
- Matched entity chips when useful.
- Open document action.
- Document details action.

Document details should show:

- Title.
- Source.
- Object path.
- Content type.
- Size, if available.
- Object ID.
- Version ID.
- Document ID.
- Chunk count.
- Entity count.
- Indexed at.
- Metadata.

### Search Empty State

When no results are found, show:

- The query that failed.
- Whether indexing is currently running.
- Suggested next actions.

Suggested messages:

- "No results yet. Indexing is still running."
- "No exact match. Try Broad match or a shorter query."
- "This file may not have extractable text."
- "PDF text extraction may require re-indexing."

### Search Behavior Requirements

The primary search form must call:

- `POST /api/v1/kg/search`

The primary search form must not call:

- `/api/v1/kg/resource-graph`
- `/api/v1/kg/context-search`
- graph traversal endpoints

Those endpoints belong in Graph or Admin views.

### Search Result Relevance Requirements

The UI must not render the beginning of a long chunk if the query appears later.

Required behavior:

- Locate the first matched query term in result text.
- Render a snippet around that position.
- Highlight terms.
- Preserve enough surrounding context.
- Show document metadata next to the snippet.

## Files Experience

### Files Page

Required elements:

- File list.
- Current folder breadcrumb.
- One New menu.
- Upload file action.
- New folder action.
- Refresh action.
- File filter input.

Rules:

- Do not show separate primary buttons for every action.
- Use one New menu for creation actions.
- Keep Upload and New folder inside the New menu.

### File Row

Each row should show:

- Name.
- Type.
- Size.
- Modified date.
- Actions menu or compact actions.

Actions:

- Open.
- Preview.
- Download.
- Rename.
- Delete.
- View metadata.
- Index/re-index.

### Upload Flow

Required behavior:

- Upload file modal or drop zone.
- Show selected file name and size.
- Upload progress.
- Success state.
- Error state.
- After upload, trigger or indicate KG indexing.

Post-upload message:

- "Uploaded. Indexing for search..."
- "Uploaded and searchable."
- "Uploaded, but no text was extracted."

### File Metadata View

Should show:

- Object ID.
- Path.
- Content type.
- Size.
- Hash/checksum.
- Version ID.
- Created by.
- Modified by.
- Tags.
- Custom metadata.
- KG indexing state.

## Knowledge Graph Experience

The Graph view should not be the default search interface.

It should support users who intentionally want to inspect relationships.

Required sections:

- Entity search.
- Relationship explorer.
- Document/entity details.
- Graph visualization or structured relation table.
- Relation creation/editing.
- Entity merge review.

### Graph Search

Graph search should be separate from document search.

It may call:

- `/api/v1/kg/resource-graph`
- `/api/v1/kg/context-search`
- `/api/v1/kg/relations/query`
- graph traversal endpoints

Graph search result should show:

- Nodes.
- Edges.
- Relation type.
- Evidence.
- Confidence.
- Source documents.

### Relation Management

Required workflows:

- Create relation.
- Edit relation.
- Delete relation.
- Review relation evidence.
- Filter by relation type.
- Filter by source/target.

### Entity Merge Review

Required workflows:

- Show duplicate candidates.
- Show canonical entity.
- Show aliases.
- Approve merge.
- Reject merge.
- Undo or review mutation log.

## Compliance Experience

The Compliance view should support evidence-driven workflows.

Required sections:

- Evidence search.
- Policies.
- Controls.
- Cases.
- Audit trail.
- Retention/legal hold.
- Export.

### Evidence Search

Filters:

- Framework.
- Control.
- Policy.
- Case.
- Customer.
- Owner.
- Status.
- Date range.
- Classification.

### Audit View

Show:

- Actor.
- Action.
- Resource.
- Timestamp.
- Before/after metadata, where applicable.
- Export action.

### Retention And Legal Hold

Show:

- Retention policy.
- Legal hold status.
- Expiration.
- Deletion eligibility.
- Warnings before destructive actions.

## Admin Experience

Admin functionality must be separated from everyday search.

Required sections:

- Users and roles.
- Indexing.
- Connectors.
- Ontology.
- NER rules.
- Backups.
- System health.
- API diagnostics.

### Indexing Admin

Required widgets:

- Indexed document count.
- Chunk count.
- Entity count.
- Last sync time.
- Running jobs.
- Failed jobs.
- Re-index selected source.
- Rebuild indexes.

Important:

- Rebuild should not appear as a normal user action.
- Sync should be labeled as "Index files" or "Re-index files".
- Show clear progress and completion.

### Connector Admin

Support connectors for:

- Local file path.
- URL.
- CSV/TSV/JSON structured file.
- Static rows.
- Future external systems such as S3, SharePoint, Google Drive, Slack exports, Git repositories, and ticket systems.

### Ontology Admin

Support:

- Node types.
- Relation types.
- Cardinality rules.
- Taxonomies.
- Validation.
- Versioning.

### NER Rule Admin

Support:

- Add rule.
- Test rule against sample text.
- Enable/disable rule.
- Confidence threshold.
- Entity type selection.

## UI States

Every async operation must have these states:

- Idle.
- Loading.
- Success.
- Empty.
- Error.
- Unauthorized.
- Partial result.

### Unauthorized State

If an API returns `401`:

- Clear invalid token.
- Return to login.
- Do not spam multiple failing requests.

### Indexing State

When indexing is running:

- Show "Indexing..." in the status area.
- Search should still work against already indexed data.
- Empty search should mention that new files may still be indexing.

### Extraction Failure State

If a document cannot be extracted:

- Show file metadata.
- Show extraction error.
- Offer re-index.
- Explain if the file may be scanned/image-only.

## Minimal MVP UI

The MVP should include:

1. Login.
2. Files page with upload and file list.
3. Search page with one search box and filters.
4. Search result cards with matched snippets and document details.
5. Indexing status.
6. Admin-only indexing controls.

Do not include in the MVP default screen:

- Multiple search forms.
- Query graph form.
- Context search form.
- Shortest path form.
- Raw ontology editor.
- Raw NER rule editor.
- Merge queue.

Those belong in advanced/admin sections.

## Recommended Screen Layout

### Search Screen

Top:

- Search input.
- Search button.

Second row:

- Broad match / All words / Phrase.
- File type.
- Result limit.
- Advanced filters toggle.

Main:

- Results list.

Right side or drawer:

- Selected document details.

Bottom:

- Indexing status.

### Files Screen

Top:

- Breadcrumb.
- New menu.
- Refresh.
- Filter files.

Main:

- File table.

Drawer:

- File metadata and indexing state.

### Graph Screen

Top:

- Entity or document selector.

Main:

- Relationship table or graph visualization.

Side:

- Selected node/relation details.

## Acceptance Criteria

Search acceptance:

- A user uploads `Git_Developer_Manual.pdf`.
- The system indexes the document automatically or shows indexing status.
- Searching `merge` returns the PDF.
- The result snippet shows the area around `Merging & Rebasing`.
- The matched term is highlighted.
- The result shows document details.
- The user can open/download the source document.
- No graph endpoint is called during normal search.

Files acceptance:

- Upload and New folder are inside one New menu.
- Upload shows success and indexing state.
- File list updates after upload.
- File details show object metadata.

Admin acceptance:

- Rebuild and raw KG tools are not visible to normal users.
- Advanced graph tools are in Graph/Admin sections.
- Unauthorized tokens are cleared without request spam.

## Future Enhancements

- PDF preview with highlighted search hits.
- Document detail drawer.
- Faceted filters.
- Saved searches.
- Case workspaces.
- Evidence packages.
- Graph visualization.
- Entity resolution review UI.
- OCR for scanned PDFs.
- Connector marketplace UI.
- Audit export wizard.
- Role-aware navigation.

