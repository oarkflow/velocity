package main

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/oarkflow/velocity/pkg/compliance"
	"github.com/oarkflow/velocity/pkg/kg"
	"log"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/oarkflow/velocity"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	cmd := os.Args[1]
	args := os.Args[2:]

	cfg := &velocity.Config{
		Path: getDBPath(),
		MasterKeyConfig: velocity.MasterKeyConfig{
			Source: velocity.SystemFile,
		},
	}

	db, err := velocity.NewWithConfig(*cfg)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	defer db.Close()

	ctx := context.Background()

	switch cmd {
	case "data":
		return handleData(db, ctx, args)
	case "secret":
		return handleSecret(db, args)
	case "object":
		return handleObject(db, args)
	case "envelope":
		return handleEnvelope(db, ctx, args)
	case "compliance":
		return handleCompliance(db, ctx, args)
	case "kg":
		return handleKG(db, ctx, args)
	case "help":
		printUsage()
	default:
		fmt.Printf("Unknown command: %s\n", cmd)
		printUsage()
		os.Exit(1)
	}
	return nil
}

func printUsage() {
	fmt.Print(`Usage:
  velocity <command> [arguments]

Commands:
  data put <key> <value>      Store a key-value pair
  data get <key>            Retrieve a value
  secret set <name> <value>  Store a secret
  secret get <name>        Retrieve a secret
  object put <key>          Store an object
  object get <key>          Retrieve an object
  object preview <file> [object-path]  Store a file and open browser preview
  envelope create --label L   Create an envelope
  envelope get --id ID       Get envelope details
  envelope export --id ID --path PATH  Export envelope
  envelope import --path PATH        Import envelope
  envelope bundle create --label L --resource JSON  Create bundle
  envelope bundle list --id ID          List resources
  envelope bundle resolve --id ID        Resolve resources
  compliance tag --type TYPE [resource flags] --framework GDPR --class restricted
  compliance get --type TYPE [resource flags]
  compliance check --type TYPE [resource flags] --operation read --actor alice
  kg ingest --source SRC --file PATH [--media-type TYPE] [--title TITLE]
  kg import --connector local_file --path PATH [--limit N] [--format text]
  kg import --connector structured_file --file rows.csv [--table TABLE]
  kg search QUERY [--limit N] [--format text]
  kg graph QUERY [--limit N] [--depth N] [--format text]
  kg materialize QUERY [--limit N] [--depth N] [--overwrite]
  kg relation create --source A --target B --type REL [--evidence TEXT]
  kg relation list [--source A] [--target B] [--type REL] [--format text]
  kg relation get --id REL_ID
  kg relation delete --id REL_ID
  kg query --seed NODE [--depth N] [--type REL] [--format text]
  kg path --source A --target B [--depth N] [--format text]
  kg ontology apply --file ontology.json
  kg ontology validate --file ontology.json
  kg ontology get [--name default]
  kg entity merge --target ID --sources A,B [--reason TEXT]
  kg entity propose-merge --target ID --sources A,B [--reason TEXT]
  kg entity approve-merge --id PROPOSAL_ID
  kg entity split --aliases A,B
  kg entity resolve ID
  kg job start --connector local_file --path PATH [--limit N] [--async]
  kg job list [--status succeeded]
  kg job get --id JOB_ID
  kg mutations [--limit N]
  kg rebuild
  kg sync [--async] [--secret-values]
  kg status
  kg analytics
  kg ner list
  kg ner add --type TYPE --pattern REGEX [--confidence N]

Examples:
  velocity data put mykey myvalue
  velocity data get mykey
  velocity secret set api_key sk_12345
  velocity object preview ./notes.md docs/notes.md
  velocity envelope create --label "Case 001" --type court_evidence
  velocity envelope bundle create --label "Evidence" --resource '[{"type":"file","name":"doc.pdf","path":"evidence/doc.pdf"}]'
  velocity compliance tag --type sql_table --table patients --framework HIPAA --class restricted --encrypt
  velocity compliance tag --type secret --name api-key --framework GDPR --class confidential
  velocity kg ingest --source notes.md --file ./notes.md --media-type text/markdown
  velocity kg import --connector local_file --path ./docs --format text
  velocity kg import --connector structured_file --file ./customers.csv --table customers
  velocity kg search "retention policy" --format text

Environment:
  VELOCITY_PATH   Database path (default: ./velocity_data)
`)
}

func handleCompliance(db *velocity.DB, ctx context.Context, args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: velocity compliance <tag|get|check> --type TYPE [resource flags]")
	}
	subcmd := args[0]
	flags, _ := parseFlags(args[1:])
	ref, err := complianceRefFromFlags(flags)
	if err != nil {
		return err
	}
	ctm := db.ComplianceTagManager()
	if ctm == nil {
		ctm = velocity.NewComplianceTagManager(db)
		db.SetComplianceTagManager(ctm)
	}
	switch subcmd {
	case "tag":
		frameworks, err := parseComplianceFrameworks(flags["framework"])
		if err != nil {
			return err
		}
		dataClass := compliance.DataClassification(flags["class"])
		if dataClass == "" {
			dataClass = compliance.DataClassInternal
		}
		tag := &velocity.ComplianceTag{
			Frameworks:    frameworks,
			DataClass:     dataClass,
			Owner:         flags["owner"],
			Custodian:     flags["custodian"],
			EncryptionReq: flags["encrypt"] == "true",
			AuditLevel:    flags["audit"],
			AccessPolicy:  flags["access-policy"],
			CreatedBy:     flagDefault(flags, "created-by", "cli"),
		}
		if err := ctm.TagResource(ctx, ref, tag); err != nil {
			return err
		}
		fmt.Printf("Tagged %s\n", tag.ResourceID)
	case "get":
		tags := ctm.GetResourceTags(ref)
		return printJSON(tags)
	case "check":
		req := &velocity.ComplianceOperationRequest{
			Operation:       flagDefault(flags, "operation", "read"),
			Actor:           flags["actor"],
			Region:          flags["region"],
			SubjectID:       flags["subject-id"],
			Purpose:         flags["purpose"],
			Encrypted:       flags["encrypted"] == "true" || flags["encrypt"] == "true",
			MFAVerified:     flags["mfa"] == "true" || flags["mfa-verified"] == "true",
			CryptoAlgorithm: flags["crypto-algorithm"],
			Reason:          flags["reason"],
		}
		result, err := ctm.ValidateResourceOperation(ctx, ref, req)
		if err != nil {
			return err
		}
		return printJSON(result)
	default:
		return fmt.Errorf("unknown compliance command: %s", subcmd)
	}
	return nil
}

func complianceRefFromFlags(flags map[string]string) (velocity.ComplianceResourceRef, error) {
	typ := velocity.ComplianceResourceType(flags["type"])
	ref := velocity.ComplianceResourceRef{Type: typ}
	switch typ {
	case velocity.ComplianceResourceKV:
		ref.Path = requiredFlag(flags, "path")
	case velocity.ComplianceResourceObject:
		ref.Path = requiredFlag(flags, "path")
	case velocity.ComplianceResourceBucket:
		ref.Bucket = requiredFlag(flags, "bucket")
	case velocity.ComplianceResourceFolder:
		ref.Path = requiredFlag(flags, "path")
	case velocity.ComplianceResourceSecret:
		ref.SecretName = requiredFlag(flags, "name")
	case velocity.ComplianceResourceSecretVersion:
		ref.SecretName = requiredFlag(flags, "name")
		ref.SecretVersion = requiredFlag(flags, "version")
	case velocity.ComplianceResourceSQLSchema:
		ref.SQLSchema = flagDefault(flags, "schema", "main")
	case velocity.ComplianceResourceSQLTable:
		ref.SQLSchema = flagDefault(flags, "schema", "main")
		ref.SQLTable = requiredFlag(flags, "table")
	case velocity.ComplianceResourceSQLColumn:
		ref.SQLSchema = flagDefault(flags, "schema", "main")
		ref.SQLTable = requiredFlag(flags, "table")
		ref.SQLColumn = requiredFlag(flags, "column")
	case velocity.ComplianceResourceSQLRow:
		ref.SQLSchema = flagDefault(flags, "schema", "main")
		ref.SQLTable = requiredFlag(flags, "table")
		ref.SQLRowKey = requiredFlag(flags, "row")
	default:
		return ref, fmt.Errorf("--type is required and must be one of kv, object, bucket, folder, secret, secret_version, sql_schema, sql_table, sql_column, sql_row")
	}
	if ref.CanonicalID() == "" {
		return ref, fmt.Errorf("missing resource flags for type %s", typ)
	}
	return ref, nil
}

func parseComplianceFrameworks(raw string) ([]compliance.Framework, error) {
	if raw == "" {
		return nil, fmt.Errorf("--framework is required")
	}
	parts := strings.Split(raw, ",")
	frameworks := make([]compliance.Framework, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		switch strings.ToUpper(part) {
		case "HIPAA":
			frameworks = append(frameworks, compliance.FrameworkHIPAA)
		case "GDPR":
			frameworks = append(frameworks, compliance.FrameworkGDPR)
		case "NIST", "NIST_800_53":
			frameworks = append(frameworks, compliance.FrameworkNIST)
		case "FIPS", "FIPS_140_2":
			frameworks = append(frameworks, compliance.FrameworkFIPS)
		case "PCI", "PCI_DSS":
			frameworks = append(frameworks, compliance.FrameworkPCIDSS)
		case "SOC2", "SOC2_TYPE2":
			frameworks = append(frameworks, compliance.FrameworkSOC2)
		case "ISO27001", "ISO_27001":
			frameworks = append(frameworks, compliance.FrameworkISO27001)
		default:
			return nil, fmt.Errorf("unknown framework: %s", part)
		}
	}
	return frameworks, nil
}

func requiredFlag(flags map[string]string, name string) string {
	return strings.TrimSpace(flags[name])
}

func flagDefault(flags map[string]string, name, fallback string) string {
	if value := strings.TrimSpace(flags[name]); value != "" {
		return value
	}
	return fallback
}

func printJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func getDBPath() string {
	if path := os.Getenv("VELOCITY_PATH"); path != "" {
		return path
	}
	return "./velocity_data"
}

func handleKG(db *velocity.DB, ctx context.Context, args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: velocity kg <ingest|import|search|graph|materialize|relation|query|path|ontology|entity|job|mutations|rebuild|sync|status|analytics|ner>")
	}
	graph := db.KnowledgeGraph()
	if graph == nil {
		return fmt.Errorf("knowledge graph unavailable")
	}
	subcmd := args[0]
	flags, positional := parseFlags(args[1:])
	format := flagDefault(flags, "format", "json")

	switch subcmd {
	case "ingest":
		source := flags["source"]
		filePath := flags["file"]
		if filePath == "" && len(positional) > 0 {
			filePath = positional[0]
		}
		if filePath == "" {
			return fmt.Errorf("usage: velocity kg ingest --source SRC --file PATH [--media-type TYPE] [--title TITLE]")
		}
		if source == "" {
			source = filePath
		}
		data, err := os.ReadFile(filePath)
		if err != nil {
			return fmt.Errorf("failed to read file: %w", err)
		}
		mediaType := flags["media-type"]
		if mediaType == "" {
			mediaType, _ = detectFileContentType(filePath)
		}
		resp, err := graph.Ingest(ctx, &kg.KGIngestRequest{
			Source:    source,
			Content:   data,
			MediaType: mediaType,
			Title:     flagDefault(flags, "title", filepath.Base(filePath)),
			Metadata:  map[string]string{"connector": "cli", "path": filePath},
		})
		if err != nil {
			return err
		}
		if format == "text" {
			fmt.Printf("ingested doc=%s chunks=%d entities=%d duration_ms=%d\n", resp.DocID, resp.ChunkCount, resp.EntityCount, resp.DurationMs)
			return nil
		}
		return printJSON(resp)
	case "import":
		connectorName := flagDefault(flags, "connector", "local_file")
		connector, err := kgConnectorFromFlags(connectorName, flags, positional)
		if err != nil {
			return err
		}
		resp, err := graph.ImportConnector(ctx, connector, flags["cursor"], parseIntDefault(flags["limit"], 0))
		if err != nil {
			return err
		}
		if format == "text" {
			fmt.Printf("connector=%s imported=%d skipped=%d next_cursor=%s\n", resp.Connector, resp.Imported, resp.Skipped, resp.NextCursor)
			for _, msg := range resp.Errors {
				fmt.Printf("error: %s\n", msg)
			}
			return nil
		}
		return printJSON(resp)
	case "search":
		query := strings.Join(positional, " ")
		if query == "" {
			query = flags["query"]
		}
		if query == "" {
			return fmt.Errorf("usage: velocity kg search QUERY [--limit N] [--format text]")
		}
		limit := parseIntDefault(flags["limit"], 10)
		resp, err := graph.Search(ctx, &kg.KGSearchRequest{Query: query, Limit: limit})
		if err != nil {
			return err
		}
		if format == "text" {
			for _, hit := range resp.Hits {
				fmt.Printf("%s\t%.4f\t%s\n", firstNonEmptyCLI(hit.Source, hit.DocID), hit.Score, strings.TrimSpace(hit.Title))
			}
			return nil
		}
		return printJSON(resp)
	case "graph":
		query := strings.Join(positional, " ")
		if query == "" {
			query = flags["query"]
		}
		if query == "" {
			return fmt.Errorf("usage: velocity kg graph QUERY [--limit N] [--depth N] [--format text]")
		}
		resp, err := graph.SearchResourceGraph(ctx, &kg.KGResourceGraphRequest{
			Query: query,
			Limit: parseIntDefault(flags["limit"], 10),
			Depth: parseIntDefault(flags["depth"], 1),
		})
		if err != nil {
			return err
		}
		if format == "text" {
			fmt.Printf("nodes=%d edges=%d hits=%d\n", len(resp.Nodes), len(resp.Edges), resp.SearchHits)
			for _, edge := range resp.Edges {
				fmt.Printf("%s -> %s [%s %.2f] %s\n", edge.Source, edge.Target, edge.RelationType, edge.Confidence, edge.Evidence)
			}
			return nil
		}
		return printJSON(resp)
	case "materialize":
		query := strings.Join(positional, " ")
		if query == "" {
			query = flags["query"]
		}
		if query == "" {
			return fmt.Errorf("usage: velocity kg materialize QUERY [--limit N] [--depth N] [--overwrite] [--format text]")
		}
		resp, err := graph.MaterializeResourceGraph(ctx, &kg.KGMaterializeRelationsRequest{
			ResourceGraph: kg.KGResourceGraphRequest{
				Query: query,
				Limit: parseIntDefault(flags["limit"], 10),
				Depth: parseIntDefault(flags["depth"], 1),
			},
			CreatedBy: flagDefault(flags, "created-by", "cli"),
			Overwrite: flags["overwrite"] == "true",
			DryRun:    flags["dry-run"] == "true",
		})
		if err != nil {
			return err
		}
		if format == "text" {
			fmt.Printf("created=%d updated=%d skipped=%d relations=%d\n", resp.Created, resp.Updated, resp.Skipped, len(resp.Relations))
			for _, rel := range resp.Relations {
				fmt.Printf("%s\t%s -- %s -- %s\n", rel.RelationID, rel.Source, rel.RelationType, rel.Target)
			}
			return nil
		}
		return printJSON(resp)
	case "relation":
		if len(positional) < 1 {
			return fmt.Errorf("usage: velocity kg relation <create|list|get|delete>")
		}
		switch positional[0] {
		case "create":
			req := &kg.KGRelationRequest{
				Source:       flagDefault(flags, "source", ""),
				Target:       flagDefault(flags, "target", ""),
				RelationType: flagDefault(flags, "type", flagDefault(flags, "relation-type", "")),
				Confidence:   parseFloatDefault(flags["confidence"], 1),
				Evidence:     flags["evidence"],
				SourceKind:   flags["source-kind"],
				CreatedBy:    flagDefault(flags, "created-by", "cli"),
			}
			rel, err := graph.CreateRelation(ctx, req)
			if err != nil {
				return err
			}
			if format == "text" {
				fmt.Printf("%s\t%s -> %s [%s %.2f]\n", rel.RelationID, rel.Source, rel.Target, rel.RelationType, rel.Confidence)
				return nil
			}
			return printJSON(rel)
		case "list":
			query := &kg.KGRelationQuery{
				Source:         flags["source"],
				Target:         flags["target"],
				RelationTypes:  splitCSVTrim(firstNonEmptyCLI(flags["type"], flags["relation-type"])),
				Status:         kg.KGRelationStatus(flags["status"]),
				MinConfidence:  parseFloatDefault(flags["min-confidence"], 0),
				Limit:          parseIntDefault(flags["limit"], 0),
				IncludeDeleted: flags["include-deleted"] == "true",
			}
			relations, err := graph.QueryRelations(ctx, query)
			if err != nil {
				return err
			}
			if format == "text" {
				for _, rel := range relations {
					fmt.Printf("%s\t%s -> %s [%s %.2f %s]\n", rel.RelationID, rel.Source, rel.Target, rel.RelationType, rel.Confidence, rel.Status)
				}
				return nil
			}
			return printJSON(map[string]any{"relations": relations})
		case "get":
			id := flagDefault(flags, "id", "")
			if id == "" && len(positional) > 1 {
				id = positional[1]
			}
			rel, err := graph.GetRelation(ctx, id)
			if err != nil {
				return err
			}
			return printJSON(rel)
		case "delete":
			id := flagDefault(flags, "id", "")
			if id == "" && len(positional) > 1 {
				id = positional[1]
			}
			if err := graph.DeleteRelation(ctx, id, flagDefault(flags, "actor", "cli")); err != nil {
				return err
			}
			if format == "text" {
				fmt.Printf("deleted relation=%s\n", id)
				return nil
			}
			return printJSON(map[string]string{"status": "deleted", "relation_id": id})
		default:
			return fmt.Errorf("unknown kg relation command: %s", positional[0])
		}
	case "query":
		seeds := splitCSVTrim(flags["seed"])
		if len(seeds) == 0 {
			seeds = positional
		}
		resp, err := graph.QueryGraph(ctx, &kg.KGGraphQuery{
			SeedIDs:         seeds,
			SeedSearch:      flags["seed-search"],
			SeedSearchLimit: parseIntDefault(flags["seed-search-limit"], 10),
			Depth:           parseIntDefault(flags["depth"], 1),
			RelationTypes:   splitCSVTrim(firstNonEmptyCLI(flags["type"], flags["relation-type"])),
			MinConfidence:   parseFloatDefault(flags["min-confidence"], 0),
			Limit:           parseIntDefault(flags["limit"], 0),
		})
		if err != nil {
			return err
		}
		if format == "text" {
			fmt.Printf("nodes=%d relations=%d\n", len(resp.Nodes), len(resp.Relations))
			for _, rel := range resp.Relations {
				fmt.Printf("%s -> %s [%s %.2f]\n", rel.Source, rel.Target, rel.RelationType, rel.Confidence)
			}
			return nil
		}
		return printJSON(resp)
	case "path":
		source := flags["source"]
		target := flags["target"]
		if source == "" && len(positional) > 0 {
			source = positional[0]
		}
		if target == "" && len(positional) > 1 {
			target = positional[1]
		}
		path, err := graph.ShortestPath(ctx, source, target, &kg.KGGraphQuery{
			Depth:         parseIntDefault(flags["depth"], 8),
			RelationTypes: splitCSVTrim(firstNonEmptyCLI(flags["type"], flags["relation-type"])),
		})
		if err != nil {
			return err
		}
		if format == "text" {
			fmt.Println(strings.Join(path.Nodes, " -> "))
			return nil
		}
		return printJSON(path)
	case "ontology":
		if len(positional) < 1 {
			return fmt.Errorf("usage: velocity kg ontology <apply|validate|get>")
		}
		switch positional[0] {
		case "apply":
			ontology, err := readOntologyFile(flags["file"])
			if err != nil {
				return err
			}
			applied, err := graph.CreateOntology(ctx, ontology)
			if err != nil {
				return err
			}
			return printJSON(applied)
		case "validate":
			ontology, err := readOntologyFile(flags["file"])
			if err != nil {
				return err
			}
			return printJSON(graph.ValidateOntology(ontology))
		case "get":
			ontology, err := graph.GetOntology(ctx, flagDefault(flags, "name", "default"))
			if err != nil {
				return err
			}
			return printJSON(ontology)
		default:
			return fmt.Errorf("unknown kg ontology command: %s", positional[0])
		}
	case "entity":
		if len(positional) < 1 {
			return fmt.Errorf("usage: velocity kg entity <merge|propose-merge|approve-merge|reject-merge|split|resolve|merge-list>")
		}
		switch positional[0] {
		case "merge":
			aliases, err := graph.MergeEntities(ctx, &kg.KGEntityMergeRequest{
				SourceIDs: splitCSVTrim(flags["sources"]),
				TargetID:  flags["target"],
				Reason:    flags["reason"],
				CreatedBy: flagDefault(flags, "created-by", "cli"),
			})
			if err != nil {
				return err
			}
			return printJSON(map[string]any{"aliases": aliases})
		case "propose-merge":
			proposal, err := graph.ProposeMerge(ctx, &kg.KGEntityMergeRequest{
				SourceIDs: splitCSVTrim(flags["sources"]),
				TargetID:  flags["target"],
				Reason:    flags["reason"],
				CreatedBy: flagDefault(flags, "created-by", "cli"),
			})
			if err != nil {
				return err
			}
			return printJSON(proposal)
		case "approve-merge":
			proposal, err := graph.ApproveMerge(ctx, flagDefault(flags, "id", ""), flagDefault(flags, "reviewed-by", "cli"))
			if err != nil {
				return err
			}
			return printJSON(proposal)
		case "reject-merge":
			proposal, err := graph.RejectMerge(ctx, flagDefault(flags, "id", ""), flagDefault(flags, "reviewed-by", "cli"))
			if err != nil {
				return err
			}
			return printJSON(proposal)
		case "merge-list":
			proposals, err := graph.ListMergeProposals(ctx, kg.KGMergeStatus(flags["status"]))
			if err != nil {
				return err
			}
			return printJSON(map[string]any{"proposals": proposals})
		case "split":
			if err := graph.SplitEntity(ctx, splitCSVTrim(flags["aliases"]), flagDefault(flags, "actor", "cli")); err != nil {
				return err
			}
			return printJSON(map[string]any{"status": "split", "aliases": splitCSVTrim(flags["aliases"])})
		case "resolve":
			id := flagDefault(flags, "id", "")
			if id == "" && len(positional) > 1 {
				id = positional[1]
			}
			canonical, chain, err := graph.ResolveEntity(ctx, id)
			if err != nil {
				return err
			}
			return printJSON(map[string]any{"entity_id": id, "canonical_id": canonical, "chain": chain})
		default:
			return fmt.Errorf("unknown kg entity command: %s", positional[0])
		}
	case "job":
		if len(positional) < 1 {
			return fmt.Errorf("usage: velocity kg job <start|list|get|retry>")
		}
		switch positional[0] {
		case "start":
			connectorName := flagDefault(flags, "connector", "local_file")
			connector, err := kgConnectorFromFlags(connectorName, flags, nil)
			if err != nil {
				return err
			}
			var job *kg.KGImportJob
			if flags["async"] == "true" {
				job, err = graph.StartImportJobAsync(ctx, connector, flags["cursor"], parseIntDefault(flags["limit"], 0))
			} else {
				job, err = graph.StartImportJob(ctx, connector, flags["cursor"], parseIntDefault(flags["limit"], 0))
			}
			if err != nil {
				return err
			}
			return printJSON(job)
		case "cancel":
			job, err := graph.CancelImportJob(ctx, flagDefault(flags, "id", ""))
			if err != nil {
				return err
			}
			return printJSON(job)
		case "list":
			jobs, err := graph.ListImportJobs(ctx, kg.KGImportJobStatus(flags["status"]))
			if err != nil {
				return err
			}
			return printJSON(map[string]any{"jobs": jobs})
		case "get":
			job, err := graph.GetImportJob(ctx, flagDefault(flags, "id", ""))
			if err != nil {
				return err
			}
			return printJSON(job)
		case "retry":
			connectorName := flagDefault(flags, "connector", "local_file")
			connector, err := kgConnectorFromFlags(connectorName, flags, nil)
			if err != nil {
				return err
			}
			job, err := graph.RetryImportJob(ctx, flagDefault(flags, "id", ""), connector)
			if err != nil {
				return err
			}
			return printJSON(job)
		default:
			return fmt.Errorf("unknown kg job command: %s", positional[0])
		}
	case "mutations":
		records, err := graph.ListMutationLog(ctx, parseIntDefault(flags["limit"], 100))
		if err != nil {
			return err
		}
		return printJSON(map[string]any{"mutations": records})
	case "rebuild":
		if err := graph.RebuildIndexes(ctx); err != nil {
			return err
		}
		return printJSON(map[string]string{"status": "rebuilt"})
	case "sync":
		cfg := velocity.KnowledgeGraphAutoIndexConfig{
			Enabled:      true,
			Existing:     true,
			Async:        flags["async"] == "true",
			SecretValues: flags["secret-values"] == "true",
		}
		if err := db.SyncKnowledgeGraph(ctx, cfg); err != nil {
			return err
		}
		return printJSON(db.KnowledgeGraphSyncStatus())
	case "status":
		return printJSON(db.KnowledgeGraphSyncStatus())
	case "analytics":
		analytics := graph.GetAnalytics()
		if format == "text" {
			fmt.Printf("documents=%d chunks=%d entities=%d\n", analytics.TotalDocuments, analytics.TotalChunks, analytics.TotalEntities)
			return nil
		}
		return printJSON(analytics)
	case "ner":
		if len(positional) < 1 {
			return fmt.Errorf("usage: velocity kg ner <list|add>")
		}
		switch positional[0] {
		case "list":
			return printJSON(map[string]any{"rules": graph.ListNERRules()})
		case "add":
			rule := kg.KGCustomNERRule{
				Type:       flagDefault(flags, "type", ""),
				Pattern:    flagDefault(flags, "pattern", ""),
				Confidence: parseFloatDefault(flags["confidence"], 0.75),
			}
			if err := graph.AddNERRule(rule); err != nil {
				return err
			}
			if format == "text" {
				fmt.Printf("added rule type=%s confidence=%.2f\n", rule.Type, rule.Confidence)
				return nil
			}
			return printJSON(rule)
		default:
			return fmt.Errorf("unknown kg ner command: %s", positional[0])
		}
	default:
		return fmt.Errorf("unknown kg command: %s", subcmd)
	}
}

func kgConnectorFromFlags(name string, flags map[string]string, positional []string) (kg.KGConnector, error) {
	switch name {
	case "local_file", "local-file", "file", "directory", "dir":
		root := flags["path"]
		if root == "" {
			root = flags["root"]
		}
		if root == "" && len(positional) > 0 {
			root = positional[0]
		}
		if root == "" {
			return nil, fmt.Errorf("usage: velocity kg import --connector local_file --path PATH")
		}
		return kg.LocalFileConnector{Root: root}, nil
	case "url", "http":
		url := flags["url"]
		if url == "" && len(positional) > 0 {
			url = positional[0]
		}
		if url == "" {
			return nil, fmt.Errorf("usage: velocity kg import --connector url --url URL")
		}
		return kg.URLConnector{URL: url}, nil
	case "structured_file", "structured-file", "csv", "json":
		path := flags["file"]
		if path == "" {
			path = flags["path"]
		}
		if path == "" && len(positional) > 0 {
			path = positional[0]
		}
		if path == "" {
			return nil, fmt.Errorf("usage: velocity kg import --connector structured_file --file PATH [--table TABLE]")
		}
		return kg.StructuredFileConnector{Path: path, Table: flags["table"]}, nil
	case "static_rows", "static-rows", "rows", "sql_rows", "sql-rows":
		path := flags["file"]
		if path == "" {
			path = flags["path"]
		}
		if path == "" && len(positional) > 0 {
			path = positional[0]
		}
		if path == "" {
			return nil, fmt.Errorf("usage: velocity kg import --connector static_rows --file rows.json [--table TABLE]")
		}
		rows, err := loadStaticRows(path, flags["table"])
		if err != nil {
			return nil, err
		}
		return kg.StaticRowsConnector{NameValue: "static_rows", Table: flags["table"], Rows: rows}, nil
	default:
		return nil, fmt.Errorf("unknown kg connector: %s", name)
	}
}

func loadStaticRows(path, table string) ([]kg.KGConnectorItem, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read rows file: %w", err)
	}
	var decoded []map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		return nil, fmt.Errorf("rows file must be a JSON array of objects: %w", err)
	}
	items := make([]kg.KGConnectorItem, 0, len(decoded))
	for i, row := range decoded {
		content, _ := json.Marshal(row)
		rowID := fmt.Sprintf("%s:%d", filepath.Base(path), i+1)
		items = append(items, kg.KGConnectorItem{
			Source:       "static_rows:" + rowID,
			ResourceType: kg.ResourceSQLRow,
			ResourceID:   rowID,
			MediaType:    "application/json",
			Title:        rowID,
			Content:      content,
			Metadata: map[string]string{
				"connector": "static_rows",
				"table":     table,
				"row":       strconv.Itoa(i + 1),
			},
		})
	}
	return items, nil
}

func parseIntDefault(raw string, fallback int) int {
	if raw == "" {
		return fallback
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n <= 0 {
		return fallback
	}
	return n
}

func parseFloatDefault(raw string, fallback float64) float64 {
	if raw == "" {
		return fallback
	}
	n, err := strconv.ParseFloat(raw, 64)
	if err != nil || n <= 0 {
		return fallback
	}
	return n
}

func firstNonEmptyCLI(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func splitCSVTrim(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func readOntologyFile(path string) (*kg.KGOntology, error) {
	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("--file is required")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read ontology file: %w", err)
	}
	var ontology kg.KGOntology
	if err := json.Unmarshal(data, &ontology); err != nil {
		return nil, fmt.Errorf("invalid ontology JSON: %w", err)
	}
	return &ontology, nil
}

func handleData(db *velocity.DB, ctx context.Context, args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: velocity data put <key> <value> or velocity data get <key>")
	}
	subcmd := args[0]
	key := args[1]
	value := ""
	if len(args) >= 3 {
		value = args[2]
	}

	switch subcmd {
	case "put":
		if value == "" {
			return fmt.Errorf("usage: velocity data put <key> <value>")
		}
		if err := db.Put([]byte(key), []byte(value)); err != nil {
			return fmt.Errorf("failed to put: %w", err)
		}
		fmt.Printf("Stored: %s\n", key)
	case "get":
		val, err := db.Get([]byte(key))
		if err != nil {
			return fmt.Errorf("failed to get: %w", err)
		}
		fmt.Println(string(val))
	default:
		return fmt.Errorf("unknown data command: %s", subcmd)
	}
	return nil
}

func handleSecret(db *velocity.DB, args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: velocity secret set <name> <value> or velocity secret get <name>")
	}
	subcmd := args[0]
	name := args[1]
	value := ""
	if len(args) >= 3 {
		value = args[2]
	}
	key := fmt.Sprintf("secret:general:%s", name)

	switch subcmd {
	case "set":
		if value == "" {
			return fmt.Errorf("usage: velocity secret set <name> <value>")
		}
		if err := db.Put([]byte(key), []byte(value)); err != nil {
			return fmt.Errorf("failed to set secret: %w", err)
		}
		fmt.Printf("Stored secret: %s\n", name)
	case "get":
		val, err := db.Get([]byte(key))
		if err != nil {
			return fmt.Errorf("secret not found: %s", name)
		}
		fmt.Println(string(val))
	default:
		return fmt.Errorf("unknown secret command: %s", subcmd)
	}
	return nil
}

func handleObject(db *velocity.DB, args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: velocity object put <key>, velocity object get <key>, or velocity object preview <file> [object-path]")
	}
	subcmd := args[0]

	switch subcmd {
	case "put":
		key := args[1]
		content := []byte(key)
		_, err := db.StoreObject(key, "application/octet-stream", "system", content, nil)
		if err != nil {
			return fmt.Errorf("failed to store: %w", err)
		}
		fmt.Printf("Stored: %s\n", key)
	case "get":
		key := args[1]
		data, _, err := db.GetObject(key, "system")
		if err != nil {
			return fmt.Errorf("failed to get: %w", err)
		}
		fmt.Println(string(data))
	case "preview", "render":
		return storeAndPreviewObject(db, args[1:])
	default:
		return fmt.Errorf("unknown object command: %s", subcmd)
	}
	return nil
}

func storeAndPreviewObject(db *velocity.DB, args []string) error {
	flags, positional := parseFlags(args)
	if len(positional) < 1 {
		return fmt.Errorf("usage: velocity object preview <file> [object-path] [--content-type TYPE] [--user USER] [--public]")
	}
	filePath := positional[0]
	objectPath := ""
	if len(positional) >= 2 {
		objectPath = positional[1]
	} else if flagPath := flags["path"]; flagPath != "" {
		objectPath = flagPath
	} else {
		objectPath = filepath.ToSlash(filepath.Base(filePath))
	}
	user := flags["user"]
	if user == "" {
		user = "system"
	}
	contentType := flags["content-type"]
	if contentType == "" {
		var err error
		contentType, err = detectFileContentType(filePath)
		if err != nil {
			return err
		}
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}
	opts := &velocity.ObjectOptions{}
	if flags["public"] == "true" || flags["public"] == "1" || flags["public"] == "yes" {
		opts.ACL = &velocity.ObjectACL{Owner: user, Public: true}
	}
	meta, err := db.StoreObject(objectPath, contentType, user, data, opts)
	if err != nil {
		return fmt.Errorf("failed to store object: %w", err)
	}
	fmt.Printf("Stored object: %s (%d bytes, %s)\n", meta.Path, meta.Size, meta.ContentType)
	fmt.Printf("Opening Preview in browser: %s\n", meta.Path)
	if err := db.ViewObject(meta.Path, user); err != nil {
		return fmt.Errorf("failed to preview object: %w", err)
	}
	return nil
}

func detectFileContentType(path string) (string, error) {
	if ext := filepath.Ext(path); ext != "" {
		if contentType := mime.TypeByExtension(ext); contentType != "" {
			return contentType, nil
		}
	}
	file, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("failed to open file for content detection: %w", err)
	}
	defer file.Close()
	buf := make([]byte, 512)
	n, err := file.Read(buf)
	if err != nil && n == 0 {
		return "", fmt.Errorf("failed to read file for content detection: %w", err)
	}
	return http.DetectContentType(buf[:n]), nil
}

func parseFlags(args []string) (map[string]string, []string) {
	flags := make(map[string]string)
	var positional []string

	for i := 0; i < len(args); i++ {
		arg := args[i]
		if strings.HasPrefix(arg, "--") {
			parts := strings.SplitN(arg, "=", 2)
			if len(parts) == 2 {
				flags[strings.TrimPrefix(parts[0], "--")] = parts[1]
			} else if i+1 < len(args) && !strings.HasPrefix(args[i+1], "--") {
				flags[strings.TrimPrefix(parts[0], "--")] = args[i+1]
				i++
			} else {
				flags[strings.TrimPrefix(parts[0], "--")] = "true"
			}
		} else if strings.HasPrefix(arg, "-") {
			if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				flags[strings.TrimPrefix(arg, "-")] = args[i+1]
				i++
			} else {
				flags[strings.TrimPrefix(arg, "-")] = "true"
			}
		} else {
			positional = append(positional, arg)
		}
	}
	return flags, positional
}

func handleEnvelope(db *velocity.DB, ctx context.Context, args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: velocity envelope <create|get|export|import|bundle>")
	}
	subcmd := args[0]
	flags, _ := parseFlags(args[1:])

	switch subcmd {
	case "create":
		label := flags["label"]
		if label == "" {
			return fmt.Errorf("--label is required")
		}
		envType := flags["type"]
		if envType == "" {
			envType = "court_evidence"
		}
		kind := flags["kind"]
		if kind == "" {
			kind = "kv"
		}
		data := flags["data"]
		if data == "" {
			data = "{}"
		}

		payload := velocity.EnvelopePayload{Kind: kind}
		if kind == "kv" {
			payload.Value = json.RawMessage(data)
		}

		req := &velocity.EnvelopeRequest{
			Label:     label,
			Type:      velocity.EnvelopeType(envType),
			CreatedBy: "system",
			Payload:   payload,
		}

		env, err := db.CreateEnvelope(ctx, req)
		if err != nil {
			return fmt.Errorf("failed to create: %w", err)
		}

		fmt.Printf("Created envelope: %s\n", env.EnvelopeID)
		fmt.Printf("  Label: %s\n", env.Label)
		fmt.Printf("  Type: %s\n", env.Type)

	case "get":
		id := flags["id"]
		if id == "" {
			return fmt.Errorf("--id is required")
		}

		env, err := db.LoadEnvelope(ctx, id)
		if err != nil {
			return fmt.Errorf("envelope not found: %s", id)
		}

		fmt.Printf("Envelope: %s\n", env.EnvelopeID)
		fmt.Printf("  Label: %s\n", env.Label)
		fmt.Printf("  Type: %s\n", env.Type)
		fmt.Printf("  Kind: %s\n", env.Payload.Kind)
		fmt.Printf("  Status: %s\n", env.Status)
		fmt.Printf("  Created: %s\n", env.CreatedAt)

		if env.Payload.Kind == "bundle" && len(env.Payload.Resources) > 0 {
			fmt.Printf("\nResources (%d):\n", len(env.Payload.Resources))
			for _, res := range env.Payload.Resources {
				fmt.Printf("  - %s (%s)\n", res.Name, res.Type)
			}
		}

	case "export":
		id := flags["id"]
		path := flags["path"]
		if id == "" || path == "" {
			return fmt.Errorf("--id and --path are required")
		}

		if err := db.ExportEnvelope(ctx, id, path); err != nil {
			return fmt.Errorf("failed to export: %w", err)
		}

		fmt.Printf("Exported to: %s\n", path)

	case "import":
		path := flags["path"]
		if path == "" {
			return fmt.Errorf("--path is required")
		}

		env, err := db.ImportEnvelope(ctx, path)
		if err != nil {
			return fmt.Errorf("failed to import: %w", err)
		}

		fmt.Printf("Imported envelope: %s\n", env.EnvelopeID)
		fmt.Printf("  Label: %s\n", env.Label)

	case "bundle":
		bundleArgs := args[1:]
		return handleEnvelopeBundle(db, ctx, bundleArgs)

	default:
		return fmt.Errorf("unknown envelope command: %s", subcmd)
	}
	return nil
}

func handleEnvelopeBundle(db *velocity.DB, ctx context.Context, args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: velocity envelope bundle <create|list|resolve>")
	}
	bundleCmd := args[0]
	flags, _ := parseFlags(args[1:])

	switch bundleCmd {
	case "create":
		label := flags["label"]
		if label == "" {
			return fmt.Errorf("--label is required")
		}
		resourceJSON := flags["resource"]

		var resources []velocity.EnvelopeResource
		if resourceJSON != "" {
			if err := json.Unmarshal([]byte(resourceJSON), &resources); err != nil {
				return fmt.Errorf("failed to parse resources: %w", err)
			}
		}

		payload := velocity.EnvelopePayload{
			Kind:      "bundle",
			Resources: resources,
		}

		req := &velocity.EnvelopeRequest{
			Label:     label,
			Type:      velocity.EnvelopeTypeInvestigationRecord,
			CreatedBy: "system",
			Payload:   payload,
		}

		env, err := db.CreateEnvelope(ctx, req)
		if err != nil {
			return fmt.Errorf("failed to create: %w", err)
		}

		fmt.Printf("Created bundle: %s\n", env.EnvelopeID)
		fmt.Printf("  Resources: %d\n", len(env.Payload.Resources))

	case "list":
		id := flags["id"]
		if id == "" {
			return fmt.Errorf("--id is required")
		}

		env, err := db.LoadEnvelope(ctx, id)
		if err != nil {
			return fmt.Errorf("envelope not found: %s", id)
		}

		if len(env.Payload.Resources) == 0 {
			fmt.Println("No resources in bundle")
			return nil
		}

		fmt.Printf("Resources (%d):\n", len(env.Payload.Resources))
		for _, res := range env.Payload.Resources {
			fmt.Printf("  - %s (%s)\n", res.Name, res.Type)
		}

	case "resolve":
		id := flags["id"]
		if id == "" {
			return fmt.Errorf("--id is required")
		}

		env, err := db.LoadEnvelope(ctx, id)
		if err != nil {
			return fmt.Errorf("envelope not found: %s", id)
		}

		resolved, err := db.ResolveResources(env.Payload)
		if err != nil {
			return fmt.Errorf("resolution failed: %w", err)
		}

		fmt.Printf("Resolved resources (%d):\n", len(resolved))
		for rid, data := range resolved {
			fmt.Printf("  %s: %d bytes\n", rid, len(data))
		}

	default:
		return fmt.Errorf("unknown bundle command: %s", bundleCmd)
	}
	return nil
}
