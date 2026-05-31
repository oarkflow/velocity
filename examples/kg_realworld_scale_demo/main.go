package main

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/oarkflow/velocity"
	"github.com/oarkflow/velocity/pkg/kg"
)

type demoConfig struct {
	Records       int
	Objects       int
	ObjectBytes   int
	MaxIndexBytes int64
	SyncWorkers   int
	Batch         int
	Path          string
	Keep          bool
}

type metric struct {
	label string
	took  time.Duration
}

var services = []string{"payment-api", "identity-api", "case-service", "kyc-worker", "evidence-indexer"}
var teams = []string{"payments", "identity", "support", "compliance", "platform"}
var risks = []string{"low", "medium", "high", "critical"}
var regions = []string{"na", "eu", "apac", "latam"}

func main() {
	ctx := context.Background()
	cfg := loadConfig()
	if !cfg.Keep {
		_ = os.RemoveAll(cfg.Path)
		defer os.RemoveAll(cfg.Path)
	}

	db, err := velocity.NewWithConfig(velocity.Config{
		Path:                    cfg.Path,
		PerformanceMode:         "performance",
		DisableEncryption:       true,
		DisableWAL:              true,
		DisableFsync:            true,
		DisableIndexPersistence: true,
	})
	check(err)
	defer db.Close()

	graph := db.KnowledgeGraph(kg.KGConfig{
		ChunkMaxWords: 48,
		ChunkOverlap:  8,
		IngestWorkers: 8,
		// The scale demo benchmarks KG document/relation search. Mirroring every
		// extracted mention into the root entity graph creates millions of extra
		// entity/relation rows at 100K/1M scale and is a separate workload.
		DisableNER:            true,
		DisableEntityIndexing: true,
		DisableDBTextIndex:    true,
		CustomNERRules: []kg.KGCustomNERRule{
			{Type: "CUSTOMER_ID", Pattern: `CUST-\d{7}`, Confidence: 0.96},
			{Type: "EVIDENCE_ID", Pattern: `EVD-\d{7}`, Confidence: 0.94},
			{Type: "POLICY_ID", Pattern: `POLICY-\d{4}`, Confidence: 0.92},
		},
	})

	fmt.Println("=== Velocity KG Real-World Scale Demo ===")
	fmt.Printf("path=%s records=%d objects=%d object_bytes=%d max_index_bytes=%d sync_workers=%d batch=%d keep=%t\n",
		cfg.Path, cfg.Records, cfg.Objects, cfg.ObjectBytes, cfg.MaxIndexBytes, cfg.SyncWorkers, cfg.Batch, cfg.Keep)
	fmt.Println()

	var metrics []metric
	timed(&metrics, "apply ontology", func() { applyOntology(ctx, graph) })
	timed(&metrics, "store and index object evidence", func() { storeObjects(ctx, db, graph, cfg) })
	timed(&metrics, "bulk write KV and SQL-style rows", func() { bulkWriteRows(db, cfg) })
	timed(&metrics, "create envelopes, entities, and secret metadata", func() { createRichResources(ctx, db) })
	timed(&metrics, "sync existing Velocity resources into KG", func() { syncKG(ctx, db, cfg) })
	timed(&metrics, "ingest canonical context-search seeds", func() { ingestCanonicalSeeds(ctx, graph) })
	timed(&metrics, "import structured CSV and JSON files", func() { importStructuredFiles(ctx, graph, cfg) })
	timed(&metrics, "import static SQL-style rows through connector chunks", func() { importConnectorRows(ctx, graph, cfg) })
	timed(&metrics, "create persistent operational relations", func() { createPersistentRelations(ctx, graph, cfg) })
	timed(&metrics, "run searches and graph queries", func() { runQueries(ctx, graph, cfg) })

	status := db.KnowledgeGraphSyncStatus()
	analytics := graph.GetAnalytics()
	fmt.Println()
	fmt.Println("-- summary --")
	fmt.Printf("kg_documents=%d chunks=%d entities=%d\n", analytics.TotalDocuments, analytics.TotalChunks, analytics.TotalEntities)
	fmt.Printf("sync_indexed=%v sync_skipped=%v\n", status.Indexed, status.Skipped)
	for _, m := range metrics {
		fmt.Printf("%-46s %s\n", m.label, m.took.Round(time.Millisecond))
	}
	if cfg.Keep {
		fmt.Printf("kept demo database at %s\n", cfg.Path)
	}
}

func loadConfig() demoConfig {
	path := os.Getenv("VELOCITY_KG_SCALE_PATH")
	if path == "" {
		path = filepath.Join(os.TempDir(), "velocity_kg_realworld_scale")
	}
	return demoConfig{
		Records:       envInt("VELOCITY_KG_SCALE_RECORDS", 10_000),
		Objects:       envInt("VELOCITY_KG_SCALE_OBJECTS", 1_000),
		ObjectBytes:   envInt("VELOCITY_KG_SCALE_OBJECT_BYTES", 4_096),
		MaxIndexBytes: int64(envInt("VELOCITY_KG_SCALE_MAX_INDEX_BYTES", 1<<20)),
		SyncWorkers:   envInt("VELOCITY_KG_SCALE_SYNC_WORKERS", 16),
		Batch:         envInt("VELOCITY_KG_SCALE_BATCH", 5_000),
		Path:          path,
		Keep:          os.Getenv("VELOCITY_KG_SCALE_KEEP") == "1",
	}
}

func applyOntology(ctx context.Context, graph *kg.KnowledgeGraphEngine) {
	_, err := graph.CreateOntology(ctx, &kg.KGOntology{
		Name:    "default",
		Version: "realworld-scale-v1",
		Taxonomies: map[string]kg.KGOntologyTaxonomy{
			"resource": {
				Name: "resource",
				Terms: map[string]kg.KGOntologyTaxonomyTerm{
					"resource": {ID: "resource", Label: "Resource"},
					"case":     {ID: "case", Label: "Support case", Parent: "resource", Synonyms: []string{"ticket", "incident"}},
					"customer": {ID: "customer", Label: "KYC customer", Parent: "resource"},
					"evidence": {ID: "evidence", Label: "Evidence object", Parent: "resource"},
					"object":   {ID: "object", Label: "Stored object", Parent: "resource"},
					"policy":   {ID: "policy", Label: "Compliance policy", Parent: "resource"},
					"invoice":  {ID: "invoice", Label: "Invoice", Parent: "resource"},
					"runbook":  {ID: "runbook", Label: "Runbook", Parent: "resource"},
					"service":  {ID: "service", Label: "Service", Parent: "resource"},
					"team":     {ID: "team", Label: "Team", Parent: "resource"},
				},
			},
			"relation_category": {
				Name: "relation_category",
				Terms: map[string]kg.KGOntologyTaxonomyTerm{
					"reference":  {ID: "reference", Label: "Reference"},
					"evidence":   {ID: "evidence", Label: "Evidence"},
					"operations": {ID: "operations", Label: "Operations"},
					"ownership":  {ID: "ownership", Label: "Ownership"},
					"dependency": {ID: "dependency", Label: "Dependency"},
				},
			},
		},
		NodeTypes: map[string]kg.KGOntologyNodeType{
			"case":     {Type: "case", ParentTypes: []string{"resource"}},
			"customer": {Type: "customer", ParentTypes: []string{"resource"}},
			"evidence": {Type: "evidence", ParentTypes: []string{"resource"}},
			"object":   {Type: "object", ParentTypes: []string{"resource"}},
			"policy":   {Type: "policy", ParentTypes: []string{"resource"}},
			"invoice":  {Type: "invoice", ParentTypes: []string{"resource"}},
			"runbook":  {Type: "runbook", ParentTypes: []string{"resource"}},
			"service":  {Type: "service", ParentTypes: []string{"resource"}},
			"team":     {Type: "team", ParentTypes: []string{"resource"}},
			"structured": {
				Type:        "structured",
				ParentTypes: []string{"resource"},
			},
			"static-row": {
				Type:        "static-row",
				ParentTypes: []string{"resource"},
			},
			"kv": {
				Type:        "kv",
				ParentTypes: []string{"resource"},
			},
		},
		RelationTypes: map[string]kg.KGOntologyRelationType{
			"references": {
				Type:           "references",
				ParentTypes:    []string{"reference"},
				AllowedSources: []string{"case", "customer", "invoice", "object", "structured", "static-row", "kv"},
				AllowedTargets: []string{"case", "customer", "policy", "invoice"},
				Direction:      kg.KGRelationDirectionOut,
			},
			"supported_by": {
				Type:           "supported_by",
				ParentTypes:    []string{"evidence"},
				AllowedSources: []string{"case"},
				AllowedTargets: []string{"evidence"},
				Direction:      kg.KGRelationDirectionOut,
				RequiredFields: []string{"evidence", "source_kind"},
			},
			"mitigated_by": {
				Type:           "mitigated_by",
				ParentTypes:    []string{"operations"},
				AllowedSources: []string{"case"},
				AllowedTargets: []string{"runbook"},
				Direction:      kg.KGRelationDirectionOut,
			},
			"depends_on": {
				Type:           "depends_on",
				ParentTypes:    []string{"dependency"},
				AllowedSources: []string{"runbook", "service"},
				AllowedTargets: []string{"service"},
				Direction:      kg.KGRelationDirectionOut,
			},
			"owned_by": {
				Type:           "owned_by",
				ParentTypes:    []string{"ownership"},
				AllowedSources: []string{"service"},
				AllowedTargets: []string{"team"},
				Direction:      kg.KGRelationDirectionOut,
			},
		},
	})
	check(err)
}

func bulkWriteRows(db *velocity.DB, cfg demoConfig) {
	bw := db.NewBatchWriter(cfg.Batch)
	defer bw.Flush()
	lastLog := time.Now()
	for i := 1; i <= cfg.Records; i++ {
		caseID := caseID(i)
		customerID := customerID(i)
		evidenceID := evidenceID(i)
		policyID := policyID(i)
		invoiceID := invoiceID(i)
		risk := risks[i%len(risks)]
		region := regions[i%len(regions)]
		service := services[i%len(services)]

		kv := fmt.Sprintf("case:%s customer:%s evidence:%s policy:%s invoice:%s service:%s KYC risk:%s region:%s support incident compliance review mitigation owner",
			caseID, customerID, evidenceID, policyID, invoiceID, service, risk, region)
		check(bw.Put([]byte("case_record:"+caseID), []byte(kv)))

		row := map[string]string{
			"case": caseID, "customer": customerID, "evidence": evidenceID,
			"policy": policyID, "invoice": invoiceID, "service": service,
			"risk": risk, "region": region, "note": "KYC policy high risk customer evidence support ticket",
		}
		raw, _ := json.Marshal(row)
		check(bw.Put([]byte("kyc_rows:"+customerID), raw))

		if i%cfg.Batch == 0 {
			check(bw.Flush())
		}
		if time.Since(lastLog) > 2*time.Second {
			fmt.Printf("  generated rows %d/%d\n", i, cfg.Records)
			lastLog = time.Now()
		}
	}
	check(bw.Flush())
}

func storeObjects(ctx context.Context, db *velocity.DB, graph *kg.KnowledgeGraphEngine, cfg demoConfig) {
	count := cfg.Objects
	if count > cfg.Records {
		count = cfg.Records
	}
	graph.BeginBulkIndexing()
	defer check(graph.EndBulkIndexing(ctx))
	lastLog := time.Now()
	workers := cfg.SyncWorkers
	if workers <= 0 {
		workers = 1
	}
	batchSize := cfg.Batch
	if batchSize <= 0 {
		batchSize = 5000
	}
	if batchSize > count || batchSize <= 0 {
		batchSize = count
	}
	for start := 1; start <= count; start += batchSize {
		end := start + batchSize - 1
		if end > count {
			end = count
		}
		reqs := make([]*kg.KGIngestRequest, end-start+1)
		jobs := make(chan int, workers*2)
		var wg sync.WaitGroup
		var errMu sync.Mutex
		var firstErr error
		setErr := func(err error) {
			if err == nil {
				return
			}
			errMu.Lock()
			if firstErr == nil {
				firstErr = err
			}
			errMu.Unlock()
		}
		for w := 0; w < workers; w++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for i := range jobs {
					path := fmt.Sprintf("evidence/%s/%s.txt", customerID(i), evidenceID(i))
					body := largeEvidenceBody(i, cfg.ObjectBytes)
					if _, err := db.StoreObject(path, "text/plain", "scale-demo", []byte(body), &velocity.ObjectOptions{
						Tags: map[string]string{
							"customer": customerID(i),
							"case":     caseID(i),
							"risk":     risks[i%len(risks)],
						},
					}); err != nil {
						setErr(err)
						continue
					}
					reqs[i-start] = &kg.KGIngestRequest{
						Source:    objectSource(i),
						MediaType: "text/plain",
						Title:     path,
						Content:   []byte(body),
						Metadata: map[string]string{
							"resource_type": string(kg.ResourceObject),
							"path":          path,
							"customer":      customerID(i),
							"case":          caseID(i),
							"risk":          risks[i%len(risks)],
						},
					}
					if i%10 == 0 {
						jsonPath := fmt.Sprintf("evidence/%s/%s.json", customerID(i), evidenceID(i))
						jsonBody := fmt.Sprintf(`{"customer":"%s","case":"%s","evidence":"%s","policy":"%s","source":"json metadata object"}`,
							customerID(i), caseID(i), evidenceID(i), policyID(i))
						if _, err := db.StoreObject(jsonPath, "application/json", "scale-demo", []byte(jsonBody), nil); err != nil {
							setErr(err)
						}
					}
					if i%50 == 0 {
						docxPath := fmt.Sprintf("evidence/%s/%s.docx", customerID(i), evidenceID(i))
						docxBody := buildDocx(fmt.Sprintf("DOCX evidence %s supports %s and customer %s KYC policy review.", evidenceID(i), caseID(i), customerID(i)))
						if _, err := db.StoreObject(docxPath, "application/vnd.openxmlformats-officedocument.wordprocessingml.document", "scale-demo", docxBody, nil); err != nil {
							setErr(err)
						}
					}
				}
			}()
		}
		for i := start; i <= end; i++ {
			jobs <- i
		}
		close(jobs)
		wg.Wait()
		check(firstErr)
		_, errs := graph.IngestBatch(ctx, reqs)
		for _, err := range errs {
			check(err)
		}
		if time.Since(lastLog) > 2*time.Second {
			fmt.Printf("  stored objects %d/%d\n", end, count)
			lastLog = time.Now()
		}
	}
}

func createRichResources(ctx context.Context, db *velocity.DB) {
	_, err := db.CreateSecret(ctx, velocity.SecretRequest{
		Name:  "kyc-screening-api",
		Value: []byte("raw-secret-value-not-indexed-by-this-demo"),
		Owner: "compliance",
		Tags:  map[string]string{"domain": "kyc", "service": "screening"},
	})
	check(err)
	_, err = db.CreateEnvelope(ctx, &velocity.EnvelopeRequest{
		Label:         "CASE-0000420 KYC evidence envelope",
		Type:          velocity.EnvelopeTypeInvestigationRecord,
		CreatedBy:     "compliance",
		CaseReference: "CASE-0000420",
		Payload: velocity.EnvelopePayload{
			Kind:       "evidence",
			InlineData: []byte("Envelope custody record for CASE-0000420 CUST-0000420 EVD-0000420 KYC policy high risk review."),
			Metadata:   map[string]string{"customer": "CUST-0000420", "policy": "POLICY-0420"},
		},
	})
	check(err)
	_, err = db.CreateEntity(ctx, &velocity.EntityRequest{
		Type:        velocity.EntityTypeJSON,
		Name:        "CUST-0000420 enterprise customer profile",
		Description: "High risk KYC customer profile linked to CASE-0000420.",
		Data:        json.RawMessage(`{"customer":"CUST-0000420","case":"CASE-0000420","risk":"high","policy":"POLICY-0420"}`),
		Tags:        map[string]string{"domain": "kyc", "risk": "high"},
		CreatedBy:   "scale-demo",
	})
	check(err)
}

func ingestCanonicalSeeds(ctx context.Context, graph *kg.KnowledgeGraphEngine) {
	for _, doc := range []*kg.KGIngestRequest{
		{
			Source:    "case:CASE-0000420",
			MediaType: "text/plain",
			Title:     "Canonical CASE-0000420",
			Content:   []byte("CASE-0000420 mitigation owner KYC policy high risk customer CUST-0000420 evidence EVD-0000420."),
			Metadata:  map[string]string{"resource_type": "case", "case": "CASE-0000420", "customer": "CUST-0000420"},
		},
		{
			Source:    "customer:CUST-0000420",
			MediaType: "text/plain",
			Title:     "Canonical CUST-0000420",
			Content:   []byte("CUST-0000420 enterprise KYC customer profile high risk review for CASE-0000420."),
			Metadata:  map[string]string{"resource_type": "customer", "customer": "CUST-0000420"},
		},
		{
			Source:    "evidence:EVD-0000420",
			MediaType: "text/plain",
			Title:     "Canonical EVD-0000420",
			Content:   []byte("EVD-0000420 evidence supports CASE-0000420 and KYC policy high risk remediation."),
			Metadata:  map[string]string{"resource_type": "evidence", "evidence": "EVD-0000420"},
		},
		{
			Source:    "runbook:payment-api-mitigation",
			MediaType: "text/plain",
			Title:     "Payment API Mitigation Runbook",
			Content:   []byte("Runbook for CASE-0000420 mitigation owner workflow: inspect payment-api retries and customer KYC evidence."),
			Metadata:  map[string]string{"resource_type": "runbook", "service": "payment-api"},
		},
		{
			Source:    "service:payment-api",
			MediaType: "text/plain",
			Title:     "Payment API Service",
			Content:   []byte("payment-api service handles checkout authorization and mitigation owner escalation."),
			Metadata:  map[string]string{"resource_type": "service", "service": "payment-api"},
		},
		{
			Source:    "team:payments",
			MediaType: "text/plain",
			Title:     "Payments Team",
			Content:   []byte("Payments team is the mitigation owner for payment-api incidents and KYC checkout escalations."),
			Metadata:  map[string]string{"resource_type": "team", "team": "payments"},
		},
	} {
		_, err := graph.Ingest(ctx, doc)
		check(err)
	}
}

func syncKG(ctx context.Context, db *velocity.DB, cfg demoConfig) {
	resources := []kg.ResourceType{kg.ResourceKV, kg.ResourceEnvelope, kg.ResourceEntity, kg.ResourceSecret}
	db.EnableKnowledgeGraphAutoIndex(velocity.KnowledgeGraphAutoIndexConfig{
		Enabled:       true,
		Resources:     resources,
		SecretValues:  false,
		Existing:      false,
		Async:         false,
		SyncWorkers:   cfg.SyncWorkers,
		MaxValueBytes: cfg.MaxIndexBytes,
	})
	check(db.SyncKnowledgeGraph(ctx, velocity.KnowledgeGraphAutoIndexConfig{
		Enabled:       true,
		Resources:     resources,
		SecretValues:  false,
		Existing:      true,
		Async:         false,
		SyncWorkers:   cfg.SyncWorkers,
		MaxValueBytes: cfg.MaxIndexBytes,
	}))
}

func importStructuredFiles(ctx context.Context, graph *kg.KnowledgeGraphEngine, cfg demoConfig) {
	dir := filepath.Join(cfg.Path, "structured_sources")
	check(os.MkdirAll(dir, 0755))
	rows := minInt(cfg.Records, 1000)

	var csv strings.Builder
	csv.WriteString("case,customer,evidence,policy,risk,note\n")
	for i := 1; i <= rows; i++ {
		fmt.Fprintf(&csv, "%s,%s,%s,%s,%s,%s\n", caseID(i), customerID(i), evidenceID(i), policyID(i), risks[i%len(risks)], "structured csv support compliance KYC evidence")
	}
	csvPath := filepath.Join(dir, "support_cases.csv")
	check(os.WriteFile(csvPath, []byte(csv.String()), 0600))
	csvResp, err := graph.ImportConnector(ctx, kg.StructuredFileConnector{Path: csvPath, Table: "support_cases"}, "", rows)
	check(err)

	jsonRecords := make([]map[string]string, 0, rows)
	for i := 1; i <= rows; i++ {
		jsonRecords = append(jsonRecords, map[string]string{
			"case":     caseID(i),
			"customer": customerID(i),
			"invoice":  invoiceID(i),
			"policy":   policyID(i),
			"note":     "structured json invoice KYC policy review",
		})
	}
	rawJSON, err := json.Marshal(jsonRecords)
	check(err)
	jsonPath := filepath.Join(dir, "kyc_invoices.json")
	check(os.WriteFile(jsonPath, rawJSON, 0600))
	jsonResp, err := graph.ImportConnector(ctx, kg.StructuredFileConnector{Path: jsonPath, Table: "kyc_invoices"}, "", rows)
	check(err)

	fmt.Printf("  structured imports csv=%d json=%d\n", csvResp.Imported, jsonResp.Imported)
}

func importConnectorRows(ctx context.Context, graph *kg.KnowledgeGraphEngine, cfg demoConfig) {
	total := cfg.Records / 20
	if total < 100 {
		total = minInt(cfg.Records, 100)
	}
	const connectorBatch = 1000
	for start := 1; start <= total; start += connectorBatch {
		end := start + connectorBatch - 1
		if end > total {
			end = total
		}
		rows := make([]kg.KGConnectorItem, 0, end-start+1)
		for i := start; i <= end; i++ {
			content := fmt.Sprintf(`{"case":"%s","customer":"%s","evidence":"%s","policy":"%s","source":"static sql connector","note":"support escalation compliance KYC evidence"}`,
				caseID(i), customerID(i), evidenceID(i), policyID(i))
			rows = append(rows, kg.KGConnectorItem{
				Source:       "static-row:escalations:" + strconv.Itoa(i),
				ResourceType: kg.ResourceSQLRow,
				ResourceID:   "escalations:" + strconv.Itoa(i),
				MediaType:    "application/json",
				Title:        "Escalation Row " + strconv.Itoa(i),
				Content:      []byte(content),
				Metadata:     map[string]string{"table": "escalations", "row": strconv.Itoa(i)},
			})
		}
		_, err := graph.ImportConnector(ctx, kg.StaticRowsConnector{NameValue: "static_rows", Table: "escalations", Rows: rows}, "", len(rows))
		check(err)
	}
}

func createPersistentRelations(ctx context.Context, graph *kg.KnowledgeGraphEngine, cfg demoConfig) {
	limit := minInt(cfg.Records, maxInt(1000, cfg.Objects))
	for i := 1; i <= limit; i++ {
		service := services[i%len(services)]
		team := teams[i%len(teams)]
		runbook := "runbook:" + service + "-mitigation"
		rels := []*kg.KGRelationRequest{
			{Source: "case:" + caseID(i), Target: "customer:" + customerID(i), RelationType: "references", Direction: kg.KGRelationDirectionOut, Confidence: 0.90, Evidence: "case references customer profile", SourceKind: "synthetic", CreatedBy: "scale-demo"},
			{Source: "case:" + caseID(i), Target: "evidence:" + evidenceID(i), RelationType: "supported_by", Direction: kg.KGRelationDirectionOut, Confidence: 0.92, Evidence: "case has matching evidence object", SourceKind: "synthetic", CreatedBy: "scale-demo"},
			{Source: "case:" + caseID(i), Target: runbook, RelationType: "mitigated_by", Direction: kg.KGRelationDirectionOut, Confidence: 0.86, Evidence: "case category maps to mitigation runbook", SourceKind: "synthetic", CreatedBy: "scale-demo"},
			{Source: runbook, Target: "service:" + service, RelationType: "depends_on", Direction: kg.KGRelationDirectionOut, Confidence: 0.82, Evidence: "runbook operates on service", SourceKind: "synthetic", CreatedBy: "scale-demo"},
			{Source: "service:" + service, Target: "team:" + team, RelationType: "owned_by", Direction: kg.KGRelationDirectionOut, Confidence: 0.88, Evidence: "service catalog ownership", SourceKind: "synthetic", CreatedBy: "scale-demo"},
		}
		for _, rel := range rels {
			_, err := graph.CreateRelation(ctx, rel)
			if err != nil && !strings.Contains(err.Error(), "already exists") {
				check(err)
			}
		}
	}
	highlighted := []*kg.KGRelationRequest{
		{Source: "structured:" + filepath.ToSlash(filepath.Join(cfg.Path, "structured_sources", "support_cases.csv")) + ":420", Target: "case:CASE-0000420", RelationType: "references", Direction: kg.KGRelationDirectionOut, Confidence: 1, Evidence: "structured support row maps to canonical case node", SourceKind: "highlight", CreatedBy: "scale-demo"},
		{Source: "structured:" + filepath.ToSlash(filepath.Join(cfg.Path, "structured_sources", "kyc_invoices.json")) + ":420", Target: "case:CASE-0000420", RelationType: "references", Direction: kg.KGRelationDirectionOut, Confidence: 1, Evidence: "structured invoice row maps to canonical case node", SourceKind: "highlight", CreatedBy: "scale-demo"},
		{Source: objectSource(420), Target: "case:CASE-0000420", RelationType: "references", Direction: kg.KGRelationDirectionOut, Confidence: 1, Evidence: "stored object evidence maps to canonical case node", SourceKind: "highlight", CreatedBy: "scale-demo"},
		{Source: "case:CASE-0000420", Target: "customer:CUST-0000420", RelationType: "references", Direction: kg.KGRelationDirectionOut, Confidence: 1, Evidence: "highlight case references customer profile", SourceKind: "highlight", CreatedBy: "scale-demo"},
		{Source: "case:CASE-0000420", Target: "evidence:EVD-0000420", RelationType: "supported_by", Direction: kg.KGRelationDirectionOut, Confidence: 1, Evidence: "highlight case has matching evidence object", SourceKind: "highlight", CreatedBy: "scale-demo"},
		{Source: "case:CASE-0000420", Target: "runbook:payment-api-mitigation", RelationType: "mitigated_by", Direction: kg.KGRelationDirectionOut, Confidence: 1, Evidence: "highlight case maps to payment API mitigation runbook", SourceKind: "highlight", CreatedBy: "scale-demo"},
		{Source: "runbook:payment-api-mitigation", Target: "service:payment-api", RelationType: "depends_on", Direction: kg.KGRelationDirectionOut, Confidence: 1, Evidence: "highlight runbook operates on payment API", SourceKind: "highlight", CreatedBy: "scale-demo"},
		{Source: "service:payment-api", Target: "team:payments", RelationType: "owned_by", Direction: kg.KGRelationDirectionOut, Confidence: 1, Evidence: "highlight service catalog ownership", SourceKind: "highlight", CreatedBy: "scale-demo"},
	}
	for _, rel := range highlighted {
		_, err := graph.CreateRelation(ctx, rel)
		if err != nil && !strings.Contains(err.Error(), "already exists") {
			check(err)
		}
	}
}

func runQueries(ctx context.Context, graph *kg.KnowledgeGraphEngine, cfg demoConfig) {
	searches := []kg.KGSearchRequest{
		{Query: "CASE-0000420", Limit: 5},
		{Query: "CASE-0000420 mitigation owner", MatchMode: "any", Limit: 5, EnableGraph: true, GraphDepth: 2},
		{Query: "custmer evidnce", Fuzzy: true, FuzzyMaxEdits: 1, Limit: 5},
		{Query: "KYC policy high risk", MatchMode: "any", Limit: 5},
		{Query: "large object payload segment compliance evidence", MatchMode: "any", Limit: 5},
	}
	if cfg.Records > 420 {
		tail := cfg.Records
		if tail > 421 {
			tail--
		}
		searches = append(searches, kg.KGSearchRequest{Query: caseID(tail), Limit: 5})
	}
	for _, req := range searches {
		start := time.Now()
		resp, err := graph.Search(ctx, &req)
		check(err)
		graphSuffix := ""
		if req.EnableGraph {
			graphSuffix = fmt.Sprintf(" graph_nodes=%d", resp.GraphNodes)
		}
		fmt.Printf("search query=%q hits=%d%s took=%s\n", req.Query, resp.TotalHits, graphSuffix, time.Since(start).Round(time.Millisecond))
		for _, hit := range resp.Hits {
			fmt.Printf("  hit source=%s title=%s score=%.4f\n", hit.Source, hit.Title, hit.Score)
		}
	}

	start := time.Now()
	rg, err := graph.SearchResourceGraph(ctx, &kg.KGResourceGraphRequest{Query: "CUST-0000420 CASE-0000420", Limit: 20, MinShared: 1})
	check(err)
	fmt.Printf("resource_graph nodes=%d edges=%d took=%s\n", len(rg.Nodes), len(rg.Edges), time.Since(start).Round(time.Millisecond))

	start = time.Now()
	materialized, err := graph.MaterializeResourceGraph(ctx, &kg.KGMaterializeRelationsRequest{
		ResourceGraph: kg.KGResourceGraphRequest{Query: "CUST-0000420 CASE-0000420", Limit: 20, MinShared: 1},
		CreatedBy:     "scale-demo",
	})
	check(err)
	fmt.Printf("materialized_relations created=%d updated=%d skipped=%d took=%s\n", materialized.Created, materialized.Updated, materialized.Skipped, time.Since(start).Round(time.Millisecond))

	start = time.Now()
	persistent, err := graph.QueryGraph(ctx, &kg.KGGraphQuery{SeedIDs: []string{"case:CASE-0000420"}, Depth: 3, Limit: 50})
	check(err)
	fmt.Printf("persistent_graph nodes=%d relations=%d took=%s\n", len(persistent.Nodes), len(persistent.Relations), time.Since(start).Round(time.Millisecond))

	start = time.Now()
	contextual, err := graph.ContextSearch(ctx, &kg.KGContextSearchRequest{
		Query:          "CASE-0000420",
		Limit:          10,
		GraphDepth:     3,
		RelationTypes:  []string{"references", "supported_by", "mitigated_by", "depends_on", "owned_by"},
		MinConfidence:  0.99,
		IncludeRelated: true,
		ContextWeight:  0.45,
	})
	check(err)
	fmt.Printf("context_search hits=%d relations=%d took=%s\n", contextual.TotalHits, len(contextual.Relations), time.Since(start).Round(time.Millisecond))
	for i, hit := range contextual.Hits {
		if i >= 10 {
			fmt.Printf("  ... %d more context hits omitted\n", len(contextual.Hits)-i)
			break
		}
		fmt.Printf("  context hit kind=%-14s source=%-36s final=%.4f base=%.4f context=%.4f rels=%d\n",
			hit.MatchKind, hit.Source, hit.FinalScore, hit.BaseScore, hit.ContextScore, len(hit.RelatedRelations))
	}
}

func timed(metrics *[]metric, label string, fn func()) {
	start := time.Now()
	fn()
	took := time.Since(start)
	*metrics = append(*metrics, metric{label: label, took: took})
	fmt.Printf("%s took %s\n", label, took.Round(time.Millisecond))
}

func caseID(i int) string {
	return fmt.Sprintf("CASE-%07d", i)
}

func customerID(i int) string {
	return fmt.Sprintf("CUST-%07d", ((i-1)%1_000_000)+1)
}

func evidenceID(i int) string {
	return fmt.Sprintf("EVD-%07d", i)
}

func objectSource(i int) string {
	return fmt.Sprintf("object:evidence/%s/%s.txt", customerID(i), evidenceID(i))
}

func policyID(i int) string {
	return fmt.Sprintf("POLICY-%04d", ((i-1)%1000)+1)
}

func invoiceID(i int) string {
	return fmt.Sprintf("INV-%07d", i)
}

func envInt(name string, fallback int) int {
	raw := os.Getenv(name)
	if raw == "" {
		return fallback
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value <= 0 {
		return fallback
	}
	return value
}

func largeEvidenceBody(i, targetBytes int) string {
	header := fmt.Sprintf("Evidence object %s for %s and %s. KYC policy high risk review references invoice %s and mitigation owner %s. Large object payload segment compliance evidence searchable archive shard %07d.\n",
		evidenceID(i), customerID(i), caseID(i), invoiceID(i), teams[i%len(teams)], i)
	if targetBytes <= len(header) {
		return header
	}
	var b strings.Builder
	b.Grow(targetBytes)
	b.WriteString(header)
	paragraph := fmt.Sprintf("payload segment %07d customer %s case %s evidence %s policy %s support compliance KYC audit remediation owner %s retained object bytes for large file search.\n",
		i, "redacted", "redacted", "redacted", policyID(i), teams[i%len(teams)])
	for b.Len() < targetBytes {
		b.WriteString(paragraph)
	}
	return b.String()[:targetBytes]
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func buildDocx(text string) []byte {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create("word/document.xml")
	check(err)
	_, err = w.Write([]byte(`<?xml version="1.0"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>` + text + `</w:t></w:r></w:p></w:body></w:document>`))
	check(err)
	check(zw.Close())
	return buf.Bytes()
}

func check(err error) {
	if err != nil {
		panic(err)
	}
}
