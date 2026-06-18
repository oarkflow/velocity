package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/oarkflow/velocity"
	"github.com/oarkflow/velocity/pkg/kg"
	"github.com/urfave/cli/v3"
)

func kgCmd(db *velocity.DB) *cli.Command {
	return &cli.Command{
		Name:  "kg",
		Usage: "Knowledge graph operations",
		Commands: []*cli.Command{
			kgIngestCmd(db),
			kgImportCmd(db),
			kgSearchCmd(db),
			kgGraphCmd(db),
			kgMaterializeCmd(db),
			kgRelationCmd(db),
			kgQueryCmd(db),
			kgPathCmd(db),
			kgOntologyCmd(db),
			kgEntityCmd(db),
			kgJobCmd(db),
			kgMutationsCmd(db),
			kgRebuildCmd(db),
			kgSyncCmd(db),
			kgStatusCmd(db),
			kgAnalyticsCmd(db),
			kgNERCmd(db),
		},
	}
}

func kgIngestCmd(db *velocity.DB) *cli.Command {
	return &cli.Command{
		Name:  "ingest",
		Usage: "Ingest a document into the knowledge graph",
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "source", Usage: "Document source identifier"},
			&cli.StringFlag{Name: "file", Usage: "Path to file to ingest", Required: true},
			&cli.StringFlag{Name: "media-type", Usage: "MIME type of the document"},
			&cli.StringFlag{Name: "title", Usage: "Document title"},
			&cli.StringFlag{Name: "format", Usage: "Output format (json, text)", Value: "json"},
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			graph := db.KnowledgeGraph()
			if graph == nil {
				return fmt.Errorf("knowledge graph unavailable")
			}
			filePath := cmd.String("file")
			source := cmd.String("source")
			data, err := os.ReadFile(filePath)
			if err != nil {
				return fmt.Errorf("failed to read file: %w", err)
			}
			mediaType := cmd.String("media-type")
			if mediaType == "" {
				mediaType, _ = detectFileContentType(filePath)
			}
			resp, err := graph.Ingest(ctx, &kg.KGIngestRequest{
				Source:    firstNonEmpty(source, filePath),
				Content:   data,
				MediaType: mediaType,
				Title:     firstNonEmpty(cmd.String("title"), filepath.Base(filePath)),
				Metadata:  map[string]string{"connector": "cli", "path": filePath},
			})
			if err != nil {
				return err
			}
			if cmd.String("format") == "text" {
				fmt.Printf("ingested doc=%s chunks=%d entities=%d duration_ms=%d\n", resp.DocID, resp.ChunkCount, resp.EntityCount, resp.DurationMs)
				return nil
			}
			return printJSON(resp)
		},
	}
}

func kgImportCmd(db *velocity.DB) *cli.Command {
	return &cli.Command{
		Name:  "import",
		Usage: "Import documents using a connector",
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "connector", Usage: "Connector type (local_file, url, structured_file)", Value: "local_file"},
			&cli.StringFlag{Name: "path", Usage: "Path for local_file connector"},
			&cli.StringFlag{Name: "root", Usage: "Root path (alias for --path)"},
			&cli.StringFlag{Name: "file", Usage: "File path for structured_file connector"},
			&cli.StringFlag{Name: "table", Usage: "Table name for structured_file"},
			&cli.StringFlag{Name: "url", Usage: "URL for url connector"},
			&cli.StringFlag{Name: "cursor", Usage: "Cursor for incremental import"},
			&cli.StringFlag{Name: "limit", Usage: "Maximum items to import"},
			&cli.StringFlag{Name: "format", Usage: "Output format (json, text)", Value: "json"},
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			graph := db.KnowledgeGraph()
			if graph == nil {
				return fmt.Errorf("knowledge graph unavailable")
			}
			connector, err := kgConnectorFromCmd(cmd)
			if err != nil {
				return err
			}
			resp, err := graph.ImportConnector(ctx, connector, cmd.String("cursor"), parseIntDefault(cmd.String("limit"), 0))
			if err != nil {
				return err
			}
			if cmd.String("format") == "text" {
				fmt.Printf("connector=%s imported=%d skipped=%d next_cursor=%s\n", resp.Connector, resp.Imported, resp.Skipped, resp.NextCursor)
				for _, msg := range resp.Errors {
					fmt.Printf("error: %s\n", msg)
				}
				return nil
			}
			return printJSON(resp)
		},
	}
}

func kgSearchCmd(db *velocity.DB) *cli.Command {
	return &cli.Command{
		Name:      "search",
		Usage:     "Search the knowledge graph",
		ArgsUsage: "<query>",
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "query", Usage: "Search query string"},
			&cli.IntFlag{Name: "limit", Usage: "Maximum results", Value: 10},
			&cli.StringFlag{Name: "format", Usage: "Output format (json, text)", Value: "json"},
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			graph := db.KnowledgeGraph()
			if graph == nil {
				return fmt.Errorf("knowledge graph unavailable")
			}
			query := strings.Join(cmd.Args().Slice(), " ")
			if query == "" {
				query = cmd.String("query")
			}
			if query == "" {
				return fmt.Errorf("usage: velocity kg search <query> [--limit N] [--format text]")
			}
			resp, err := graph.Search(ctx, &kg.KGSearchRequest{Query: query, Limit: int(cmd.Int("limit"))})
			if err != nil {
				return err
			}
			if cmd.String("format") == "text" {
				for _, hit := range resp.Hits {
					fmt.Printf("%s\t%.4f\t%s\n", firstNonEmpty(hit.Source, hit.DocID), hit.Score, strings.TrimSpace(hit.Title))
				}
				return nil
			}
			return printJSON(resp)
		},
	}
}

func kgGraphCmd(db *velocity.DB) *cli.Command {
	return &cli.Command{
		Name:      "graph",
		Usage:     "Search resource graph",
		ArgsUsage: "<query>",
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "query", Usage: "Graph query string"},
			&cli.IntFlag{Name: "limit", Usage: "Maximum results", Value: 10},
			&cli.IntFlag{Name: "depth", Usage: "Graph depth", Value: 1},
			&cli.StringFlag{Name: "format", Usage: "Output format (json, text)", Value: "json"},
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			graph := db.KnowledgeGraph()
			if graph == nil {
				return fmt.Errorf("knowledge graph unavailable")
			}
			query := strings.Join(cmd.Args().Slice(), " ")
			if query == "" {
				query = cmd.String("query")
			}
			if query == "" {
				return fmt.Errorf("usage: velocity kg graph <query> [--limit N] [--depth N] [--format text]")
			}
			resp, err := graph.SearchResourceGraph(ctx, &kg.KGResourceGraphRequest{
				Query: query,
				Limit: int(cmd.Int("limit")),
				Depth: int(cmd.Int("depth")),
			})
			if err != nil {
				return err
			}
			if cmd.String("format") == "text" {
				fmt.Printf("nodes=%d edges=%d hits=%d\n", len(resp.Nodes), len(resp.Edges), resp.SearchHits)
				for _, edge := range resp.Edges {
					fmt.Printf("%s -> %s [%s %.2f] %s\n", edge.Source, edge.Target, edge.RelationType, edge.Confidence, edge.Evidence)
				}
				return nil
			}
			return printJSON(resp)
		},
	}
}

func kgMaterializeCmd(db *velocity.DB) *cli.Command {
	return &cli.Command{
		Name:      "materialize",
		Usage:     "Materialize resource graph as relations",
		ArgsUsage: "<query>",
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "query", Usage: "Materialize query"},
			&cli.IntFlag{Name: "limit", Usage: "Maximum results", Value: 10},
			&cli.IntFlag{Name: "depth", Usage: "Graph depth", Value: 1},
			&cli.BoolFlag{Name: "overwrite", Usage: "Overwrite existing relations"},
			&cli.BoolFlag{Name: "dry-run", Usage: "Dry run without creating relations"},
			&cli.StringFlag{Name: "created-by", Usage: "Creator identity", Value: "cli"},
			&cli.StringFlag{Name: "format", Usage: "Output format (json, text)", Value: "json"},
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			graph := db.KnowledgeGraph()
			if graph == nil {
				return fmt.Errorf("knowledge graph unavailable")
			}
			query := strings.Join(cmd.Args().Slice(), " ")
			if query == "" {
				query = cmd.String("query")
			}
			if query == "" {
				return fmt.Errorf("usage: velocity kg materialize <query> [--limit N] [--depth N] [--overwrite] [--format text]")
			}
			resp, err := graph.MaterializeResourceGraph(ctx, &kg.KGMaterializeRelationsRequest{
				ResourceGraph: kg.KGResourceGraphRequest{
					Query: query,
					Limit: int(cmd.Int("limit")),
					Depth: int(cmd.Int("depth")),
				},
				CreatedBy: cmd.String("created-by"),
				Overwrite: cmd.Bool("overwrite"),
				DryRun:    cmd.Bool("dry-run"),
			})
			if err != nil {
				return err
			}
			if cmd.String("format") == "text" {
				fmt.Printf("created=%d updated=%d skipped=%d relations=%d\n", resp.Created, resp.Updated, resp.Skipped, len(resp.Relations))
				for _, rel := range resp.Relations {
					fmt.Printf("%s\t%s -- %s -- %s\n", rel.RelationID, rel.Source, rel.RelationType, rel.Target)
				}
				return nil
			}
			return printJSON(resp)
		},
	}
}

func kgRelationCmd(db *velocity.DB) *cli.Command {
	return &cli.Command{
		Name:  "relation",
		Usage: "Manage knowledge graph relations",
		Commands: []*cli.Command{
			{
				Name:  "create",
				Usage: "Create a relation",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "source", Usage: "Source entity", Required: true},
					&cli.StringFlag{Name: "target", Usage: "Target entity", Required: true},
					&cli.StringFlag{Name: "type", Usage: "Relation type", Required: true},
					&cli.StringFlag{Name: "confidence", Usage: "Confidence score (0-1)", Value: "1"},
					&cli.StringFlag{Name: "evidence", Usage: "Evidence text"},
					&cli.StringFlag{Name: "source-kind", Usage: "Source entity kind"},
					&cli.StringFlag{Name: "created-by", Usage: "Creator identity", Value: "cli"},
					&cli.StringFlag{Name: "format", Usage: "Output format (json, text)", Value: "json"},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					graph := db.KnowledgeGraph()
					if graph == nil {
						return fmt.Errorf("knowledge graph unavailable")
					}
					rel, err := graph.CreateRelation(ctx, &kg.KGRelationRequest{
						Source:       cmd.String("source"),
						Target:       cmd.String("target"),
						RelationType: cmd.String("type"),
						Confidence:   parseFloatDefault(cmd.String("confidence"), 1),
						Evidence:     cmd.String("evidence"),
						SourceKind:   cmd.String("source-kind"),
						CreatedBy:    cmd.String("created-by"),
					})
					if err != nil {
						return err
					}
					if cmd.String("format") == "text" {
						fmt.Printf("%s\t%s -> %s [%s %.2f]\n", rel.RelationID, rel.Source, rel.Target, rel.RelationType, rel.Confidence)
						return nil
					}
					return printJSON(rel)
				},
			},
			{
				Name:  "list",
				Usage: "List relations",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "source", Usage: "Filter by source"},
					&cli.StringFlag{Name: "target", Usage: "Filter by target"},
					&cli.StringFlag{Name: "type", Usage: "Filter by relation type"},
					&cli.StringFlag{Name: "status", Usage: "Filter by status"},
					&cli.StringFlag{Name: "min-confidence", Usage: "Minimum confidence"},
					&cli.IntFlag{Name: "limit", Usage: "Maximum results"},
					&cli.BoolFlag{Name: "include-deleted", Usage: "Include deleted relations"},
					&cli.StringFlag{Name: "format", Usage: "Output format (json, text)", Value: "json"},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					graph := db.KnowledgeGraph()
					if graph == nil {
						return fmt.Errorf("knowledge graph unavailable")
					}
					relations, err := graph.QueryRelations(ctx, &kg.KGRelationQuery{
						Source:         cmd.String("source"),
						Target:         cmd.String("target"),
						RelationTypes:  splitCSVTrim(firstNonEmpty(cmd.String("type"), cmd.String("relation-type"))),
						Status:         kg.KGRelationStatus(cmd.String("status")),
						MinConfidence:  parseFloatDefault(cmd.String("min-confidence"), 0),
						Limit:          int(cmd.Int("limit")),
						IncludeDeleted: cmd.Bool("include-deleted"),
					})
					if err != nil {
						return err
					}
					if cmd.String("format") == "text" {
						for _, rel := range relations {
							fmt.Printf("%s\t%s -> %s [%s %.2f %s]\n", rel.RelationID, rel.Source, rel.Target, rel.RelationType, rel.Confidence, rel.Status)
						}
						return nil
					}
					return printJSON(map[string]any{"relations": relations})
				},
			},
			{
				Name:  "get",
				Usage: "Get a relation by ID",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "id", Usage: "Relation ID", Required: true},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					graph := db.KnowledgeGraph()
					if graph == nil {
						return fmt.Errorf("knowledge graph unavailable")
					}
					rel, err := graph.GetRelation(ctx, cmd.String("id"))
					if err != nil {
						return err
					}
					return printJSON(rel)
				},
			},
			{
				Name:  "delete",
				Usage: "Delete a relation",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "id", Usage: "Relation ID", Required: true},
					&cli.StringFlag{Name: "actor", Usage: "Actor performing deletion", Value: "cli"},
					&cli.StringFlag{Name: "format", Usage: "Output format (json, text)", Value: "json"},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					graph := db.KnowledgeGraph()
					if graph == nil {
						return fmt.Errorf("knowledge graph unavailable")
					}
					if err := graph.DeleteRelation(ctx, cmd.String("id"), cmd.String("actor")); err != nil {
						return err
					}
					if cmd.String("format") == "text" {
						fmt.Printf("deleted relation=%s\n", cmd.String("id"))
						return nil
					}
					return printJSON(map[string]string{"status": "deleted", "relation_id": cmd.String("id")})
				},
			},
		},
	}
}

func kgQueryCmd(db *velocity.DB) *cli.Command {
	return &cli.Command{
		Name:  "query",
		Usage: "Query the knowledge graph",
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "seed", Usage: "Seed entity IDs (comma-separated)"},
			&cli.StringFlag{Name: "seed-search", Usage: "Search for seed entities by text"},
			&cli.IntFlag{Name: "seed-search-limit", Usage: "Max seed search results", Value: 10},
			&cli.IntFlag{Name: "depth", Usage: "Graph traversal depth", Value: 1},
			&cli.StringFlag{Name: "type", Usage: "Relation types to follow (comma-separated)"},
			&cli.StringFlag{Name: "min-confidence", Usage: "Minimum confidence"},
			&cli.IntFlag{Name: "limit", Usage: "Maximum results"},
			&cli.StringFlag{Name: "format", Usage: "Output format (json, text)", Value: "json"},
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			graph := db.KnowledgeGraph()
			if graph == nil {
				return fmt.Errorf("knowledge graph unavailable")
			}
			seeds := splitCSVTrim(cmd.String("seed"))
			if len(seeds) == 0 {
				seeds = cmd.Args().Slice()
			}
			resp, err := graph.QueryGraph(ctx, &kg.KGGraphQuery{
				SeedIDs:         seeds,
				SeedSearch:      cmd.String("seed-search"),
				SeedSearchLimit: int(cmd.Int("seed-search-limit")),
				Depth:           int(cmd.Int("depth")),
				RelationTypes:   splitCSVTrim(firstNonEmpty(cmd.String("type"), cmd.String("relation-type"))),
				MinConfidence:   parseFloatDefault(cmd.String("min-confidence"), 0),
				Limit:           int(cmd.Int("limit")),
			})
			if err != nil {
				return err
			}
			if cmd.String("format") == "text" {
				fmt.Printf("nodes=%d relations=%d\n", len(resp.Nodes), len(resp.Relations))
				for _, rel := range resp.Relations {
					fmt.Printf("%s -> %s [%s %.2f]\n", rel.Source, rel.Target, rel.RelationType, rel.Confidence)
				}
				return nil
			}
			return printJSON(resp)
		},
	}
}

func kgPathCmd(db *velocity.DB) *cli.Command {
	return &cli.Command{
		Name:  "path",
		Usage: "Find shortest path between two entities",
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "source", Usage: "Source entity", Required: true},
			&cli.StringFlag{Name: "target", Usage: "Target entity", Required: true},
			&cli.IntFlag{Name: "depth", Usage: "Maximum path depth", Value: 8},
			&cli.StringFlag{Name: "type", Usage: "Relation types to traverse (comma-separated)"},
			&cli.StringFlag{Name: "format", Usage: "Output format (json, text)", Value: "json"},
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			graph := db.KnowledgeGraph()
			if graph == nil {
				return fmt.Errorf("knowledge graph unavailable")
			}
			path, err := graph.ShortestPath(ctx, cmd.String("source"), cmd.String("target"), &kg.KGGraphQuery{
				Depth:         int(cmd.Int("depth")),
				RelationTypes: splitCSVTrim(firstNonEmpty(cmd.String("type"), cmd.String("relation-type"))),
			})
			if err != nil {
				return err
			}
			if cmd.String("format") == "text" {
				fmt.Println(strings.Join(path.Nodes, " -> "))
				return nil
			}
			return printJSON(path)
		},
	}
}

func kgOntologyCmd(db *velocity.DB) *cli.Command {
	return &cli.Command{
		Name:  "ontology",
		Usage: "Manage knowledge graph ontologies",
		Commands: []*cli.Command{
			{
				Name:  "apply",
				Usage: "Apply an ontology from a file",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "file", Usage: "Path to ontology JSON file", Required: true},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					graph := db.KnowledgeGraph()
					if graph == nil {
						return fmt.Errorf("knowledge graph unavailable")
					}
					ontology, err := readOntologyFile(cmd.String("file"))
					if err != nil {
						return err
					}
					applied, err := graph.CreateOntology(ctx, ontology)
					if err != nil {
						return err
					}
					return printJSON(applied)
				},
			},
			{
				Name:  "validate",
				Usage: "Validate an ontology file",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "file", Usage: "Path to ontology JSON file", Required: true},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					graph := db.KnowledgeGraph()
					if graph == nil {
						return fmt.Errorf("knowledge graph unavailable")
					}
					ontology, err := readOntologyFile(cmd.String("file"))
					if err != nil {
						return err
					}
					return printJSON(graph.ValidateOntology(ontology))
				},
			},
			{
				Name:  "get",
				Usage: "Get an ontology",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "name", Usage: "Ontology name", Value: "default"},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					graph := db.KnowledgeGraph()
					if graph == nil {
						return fmt.Errorf("knowledge graph unavailable")
					}
					ontology, err := graph.GetOntology(ctx, cmd.String("name"))
					if err != nil {
						return err
					}
					return printJSON(ontology)
				},
			},
		},
	}
}

func kgEntityCmd(db *velocity.DB) *cli.Command {
	return &cli.Command{
		Name:  "entity",
		Usage: "Manage knowledge graph entities",
		Commands: []*cli.Command{
			{
				Name:  "merge",
				Usage: "Merge entities",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "target", Usage: "Target entity ID", Required: true},
					&cli.StringFlag{Name: "sources", Usage: "Source entity IDs (comma-separated)", Required: true},
					&cli.StringFlag{Name: "reason", Usage: "Merge reason"},
					&cli.StringFlag{Name: "created-by", Usage: "Creator identity", Value: "cli"},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					graph := db.KnowledgeGraph()
					if graph == nil {
						return fmt.Errorf("knowledge graph unavailable")
					}
					aliases, err := graph.MergeEntities(ctx, &kg.KGEntityMergeRequest{
						SourceIDs: splitCSVTrim(cmd.String("sources")),
						TargetID:  cmd.String("target"),
						Reason:    cmd.String("reason"),
						CreatedBy: cmd.String("created-by"),
					})
					if err != nil {
						return err
					}
					return printJSON(map[string]any{"aliases": aliases})
				},
			},
			{
				Name:  "propose-merge",
				Usage: "Propose an entity merge",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "target", Usage: "Target entity ID", Required: true},
					&cli.StringFlag{Name: "sources", Usage: "Source entity IDs (comma-separated)", Required: true},
					&cli.StringFlag{Name: "reason", Usage: "Merge reason"},
					&cli.StringFlag{Name: "created-by", Usage: "Creator identity", Value: "cli"},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					graph := db.KnowledgeGraph()
					if graph == nil {
						return fmt.Errorf("knowledge graph unavailable")
					}
					proposal, err := graph.ProposeMerge(ctx, &kg.KGEntityMergeRequest{
						SourceIDs: splitCSVTrim(cmd.String("sources")),
						TargetID:  cmd.String("target"),
						Reason:    cmd.String("reason"),
						CreatedBy: cmd.String("created-by"),
					})
					if err != nil {
						return err
					}
					return printJSON(proposal)
				},
			},
			{
				Name:  "approve-merge",
				Usage: "Approve a merge proposal",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "id", Usage: "Proposal ID", Required: true},
					&cli.StringFlag{Name: "reviewed-by", Usage: "Reviewer identity", Value: "cli"},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					graph := db.KnowledgeGraph()
					if graph == nil {
						return fmt.Errorf("knowledge graph unavailable")
					}
					proposal, err := graph.ApproveMerge(ctx, cmd.String("id"), cmd.String("reviewed-by"))
					if err != nil {
						return err
					}
					return printJSON(proposal)
				},
			},
			{
				Name:  "reject-merge",
				Usage: "Reject a merge proposal",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "id", Usage: "Proposal ID", Required: true},
					&cli.StringFlag{Name: "reviewed-by", Usage: "Reviewer identity", Value: "cli"},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					graph := db.KnowledgeGraph()
					if graph == nil {
						return fmt.Errorf("knowledge graph unavailable")
					}
					proposal, err := graph.RejectMerge(ctx, cmd.String("id"), cmd.String("reviewed-by"))
					if err != nil {
						return err
					}
					return printJSON(proposal)
				},
			},
			{
				Name:  "merge-list",
				Usage: "List merge proposals",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "status", Usage: "Filter by status"},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					graph := db.KnowledgeGraph()
					if graph == nil {
						return fmt.Errorf("knowledge graph unavailable")
					}
					proposals, err := graph.ListMergeProposals(ctx, kg.KGMergeStatus(cmd.String("status")))
					if err != nil {
						return err
					}
					return printJSON(map[string]any{"proposals": proposals})
				},
			},
			{
				Name:  "split",
				Usage: "Split an entity into aliases",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "aliases", Usage: "Alias IDs to split (comma-separated)", Required: true},
					&cli.StringFlag{Name: "actor", Usage: "Actor identity", Value: "cli"},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					graph := db.KnowledgeGraph()
					if graph == nil {
						return fmt.Errorf("knowledge graph unavailable")
					}
					aliases := splitCSVTrim(cmd.String("aliases"))
					if err := graph.SplitEntity(ctx, aliases, cmd.String("actor")); err != nil {
						return err
					}
					return printJSON(map[string]any{"status": "split", "aliases": aliases})
				},
			},
			{
				Name:      "resolve",
				Usage:     "Resolve an entity to its canonical ID",
				ArgsUsage: "<id>",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "id", Usage: "Entity ID to resolve"},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					graph := db.KnowledgeGraph()
					if graph == nil {
						return fmt.Errorf("knowledge graph unavailable")
					}
					id := cmd.String("id")
					if id == "" && cmd.Args().Len() > 0 {
						id = cmd.Args().Get(0)
					}
					if id == "" {
						return fmt.Errorf("entity ID is required")
					}
					canonical, chain, err := graph.ResolveEntity(ctx, id)
					if err != nil {
						return err
					}
					return printJSON(map[string]any{"entity_id": id, "canonical_id": canonical, "chain": chain})
				},
			},
		},
	}
}

func kgJobCmd(db *velocity.DB) *cli.Command {
	return &cli.Command{
		Name:  "job",
		Usage: "Manage import jobs",
		Commands: []*cli.Command{
			{
				Name:  "start",
				Usage: "Start an import job",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "connector", Usage: "Connector type", Value: "local_file"},
					&cli.StringFlag{Name: "path", Usage: "Path for local_file connector"},
					&cli.StringFlag{Name: "root", Usage: "Root path alias"},
					&cli.StringFlag{Name: "file", Usage: "File path for structured_file"},
					&cli.StringFlag{Name: "table", Usage: "Table name"},
					&cli.StringFlag{Name: "url", Usage: "URL for url connector"},
					&cli.StringFlag{Name: "cursor", Usage: "Import cursor"},
					&cli.StringFlag{Name: "limit", Usage: "Maximum items"},
					&cli.BoolFlag{Name: "async", Usage: "Run asynchronously"},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					graph := db.KnowledgeGraph()
					if graph == nil {
						return fmt.Errorf("knowledge graph unavailable")
					}
					connector, err := kgConnectorFromCmd(cmd)
					if err != nil {
						return err
					}
					var job *kg.KGImportJob
					if cmd.Bool("async") {
						job, err = graph.StartImportJobAsync(ctx, connector, cmd.String("cursor"), parseIntDefault(cmd.String("limit"), 0))
					} else {
						job, err = graph.StartImportJob(ctx, connector, cmd.String("cursor"), parseIntDefault(cmd.String("limit"), 0))
					}
					if err != nil {
						return err
					}
					return printJSON(job)
				},
			},
			{
				Name:  "cancel",
				Usage: "Cancel an import job",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "id", Usage: "Job ID", Required: true},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					graph := db.KnowledgeGraph()
					if graph == nil {
						return fmt.Errorf("knowledge graph unavailable")
					}
					job, err := graph.CancelImportJob(ctx, cmd.String("id"))
					if err != nil {
						return err
					}
					return printJSON(job)
				},
			},
			{
				Name:  "list",
				Usage: "List import jobs",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "status", Usage: "Filter by status"},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					graph := db.KnowledgeGraph()
					if graph == nil {
						return fmt.Errorf("knowledge graph unavailable")
					}
					jobs, err := graph.ListImportJobs(ctx, kg.KGImportJobStatus(cmd.String("status")))
					if err != nil {
						return err
					}
					return printJSON(map[string]any{"jobs": jobs})
				},
			},
			{
				Name:  "get",
				Usage: "Get an import job",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "id", Usage: "Job ID", Required: true},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					graph := db.KnowledgeGraph()
					if graph == nil {
						return fmt.Errorf("knowledge graph unavailable")
					}
					job, err := graph.GetImportJob(ctx, cmd.String("id"))
					if err != nil {
						return err
					}
					return printJSON(job)
				},
			},
			{
				Name:  "retry",
				Usage: "Retry a failed import job",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "id", Usage: "Job ID", Required: true},
					&cli.StringFlag{Name: "connector", Usage: "Connector type", Value: "local_file"},
					&cli.StringFlag{Name: "path", Usage: "Path for local_file"},
					&cli.StringFlag{Name: "file", Usage: "File path for structured_file"},
					&cli.StringFlag{Name: "table", Usage: "Table name"},
					&cli.StringFlag{Name: "url", Usage: "URL for url connector"},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					graph := db.KnowledgeGraph()
					if graph == nil {
						return fmt.Errorf("knowledge graph unavailable")
					}
					connector, err := kgConnectorFromCmd(cmd)
					if err != nil {
						return err
					}
					job, err := graph.RetryImportJob(ctx, cmd.String("id"), connector)
					if err != nil {
						return err
					}
					return printJSON(job)
				},
			},
		},
	}
}

func kgMutationsCmd(db *velocity.DB) *cli.Command {
	return &cli.Command{
		Name:  "mutations",
		Usage: "List mutation log",
		Flags: []cli.Flag{
			&cli.IntFlag{Name: "limit", Usage: "Maximum entries", Value: 100},
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			graph := db.KnowledgeGraph()
			if graph == nil {
				return fmt.Errorf("knowledge graph unavailable")
			}
			records, err := graph.ListMutationLog(ctx, int(cmd.Int("limit")))
			if err != nil {
				return err
			}
			return printJSON(map[string]any{"mutations": records})
		},
	}
}

func kgRebuildCmd(db *velocity.DB) *cli.Command {
	return &cli.Command{
		Name:  "rebuild",
		Usage: "Rebuild knowledge graph indexes",
		Action: func(ctx context.Context, cmd *cli.Command) error {
			graph := db.KnowledgeGraph()
			if graph == nil {
				return fmt.Errorf("knowledge graph unavailable")
			}
			if err := graph.RebuildIndexes(ctx); err != nil {
				return err
			}
			return printJSON(map[string]string{"status": "rebuilt"})
		},
	}
}

func kgSyncCmd(db *velocity.DB) *cli.Command {
	return &cli.Command{
		Name:  "sync",
		Usage: "Sync database to knowledge graph",
		Flags: []cli.Flag{
			&cli.BoolFlag{Name: "async", Usage: "Run asynchronously"},
			&cli.BoolFlag{Name: "secret-values", Usage: "Include secret values"},
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			cfg := velocity.KnowledgeGraphAutoIndexConfig{
				Enabled:      true,
				Existing:     true,
				Async:        cmd.Bool("async"),
				SecretValues: cmd.Bool("secret-values"),
			}
			if err := db.SyncKnowledgeGraph(ctx, cfg); err != nil {
				return err
			}
			return printJSON(db.KnowledgeGraphSyncStatus())
		},
	}
}

func kgStatusCmd(db *velocity.DB) *cli.Command {
	return &cli.Command{
		Name: "status",
		Usage: "Show knowledge graph sync status",
		Action: func(ctx context.Context, cmd *cli.Command) error {
			return printJSON(db.KnowledgeGraphSyncStatus())
		},
	}
}

func kgAnalyticsCmd(db *velocity.DB) *cli.Command {
	return &cli.Command{
		Name:  "analytics",
		Usage: "Show knowledge graph analytics",
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "format", Usage: "Output format (json, text)", Value: "json"},
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			graph := db.KnowledgeGraph()
			if graph == nil {
				return fmt.Errorf("knowledge graph unavailable")
			}
			analytics := graph.GetAnalytics()
			if cmd.String("format") == "text" {
				fmt.Printf("documents=%d chunks=%d entities=%d\n", analytics.TotalDocuments, analytics.TotalChunks, analytics.TotalEntities)
				return nil
			}
			return printJSON(analytics)
		},
	}
}

func kgNERCmd(db *velocity.DB) *cli.Command {
	return &cli.Command{
		Name:  "ner",
		Usage: "Manage named entity recognition rules",
		Commands: []*cli.Command{
			{
				Name: "list",
				Usage: "List NER rules",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					graph := db.KnowledgeGraph()
					if graph == nil {
						return fmt.Errorf("knowledge graph unavailable")
					}
					return printJSON(map[string]any{"rules": graph.ListNERRules()})
				},
			},
			{
				Name:  "add",
				Usage: "Add a custom NER rule",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "type", Usage: "Entity type", Required: true},
					&cli.StringFlag{Name: "pattern", Usage: "Regex pattern", Required: true},
					&cli.StringFlag{Name: "confidence", Usage: "Confidence score", Value: "0.75"},
					&cli.StringFlag{Name: "format", Usage: "Output format (json, text)", Value: "json"},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					graph := db.KnowledgeGraph()
					if graph == nil {
						return fmt.Errorf("knowledge graph unavailable")
					}
					rule := kg.KGCustomNERRule{
						Type:       cmd.String("type"),
						Pattern:    cmd.String("pattern"),
						Confidence: parseFloatDefault(cmd.String("confidence"), 0.75),
					}
					if err := graph.AddNERRule(rule); err != nil {
						return err
					}
					if cmd.String("format") == "text" {
						fmt.Printf("added rule type=%s confidence=%.2f\n", rule.Type, rule.Confidence)
						return nil
					}
					return printJSON(rule)
				},
			},
		},
	}
}

func kgConnectorFromCmd(cmd *cli.Command) (kg.KGConnector, error) {
	switch cmd.String("connector") {
	case "local_file", "local-file", "file", "directory", "dir":
		root := cmd.String("path")
		if root == "" {
			root = cmd.String("root")
		}
		if root == "" && cmd.Args().Len() > 0 {
			root = cmd.Args().Get(0)
		}
		if root == "" {
			return nil, fmt.Errorf("--path is required for local_file connector")
		}
		return kg.LocalFileConnector{Root: root}, nil
	case "url", "http":
		url := cmd.String("url")
		if url == "" && cmd.Args().Len() > 0 {
			url = cmd.Args().Get(0)
		}
		if url == "" {
			return nil, fmt.Errorf("--url is required for url connector")
		}
		return kg.URLConnector{URL: url}, nil
	case "structured_file", "structured-file", "csv", "json":
		path := cmd.String("file")
		if path == "" {
			path = cmd.String("path")
		}
		if path == "" && cmd.Args().Len() > 0 {
			path = cmd.Args().Get(0)
		}
		if path == "" {
			return nil, fmt.Errorf("--file is required for structured_file connector")
		}
		return kg.StructuredFileConnector{Path: path, Table: cmd.String("table")}, nil
	case "static_rows", "static-rows", "rows", "sql_rows", "sql-rows":
		path := cmd.String("file")
		if path == "" {
			path = cmd.String("path")
		}
		if path == "" && cmd.Args().Len() > 0 {
			path = cmd.Args().Get(0)
		}
		if path == "" {
			return nil, fmt.Errorf("--file is required for static_rows connector")
		}
		rows, err := loadStaticRows(path, cmd.String("table"))
		if err != nil {
			return nil, err
		}
		return kg.StaticRowsConnector{NameValue: "static_rows", Table: cmd.String("table"), Rows: rows}, nil
	default:
		return nil, fmt.Errorf("unknown connector: %s", cmd.String("connector"))
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
