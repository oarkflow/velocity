package web

import (
	"encoding/json"
	"io"
	"strconv"

	"github.com/gofiber/fiber/v3"
	"github.com/oarkflow/velocity"
	"github.com/oarkflow/velocity/pkg/kg"
)

// KGAPI provides HTTP endpoints for the Knowledge Graph subsystem.
type KGAPI struct {
	db *velocity.DB
	kg *kg.KnowledgeGraphEngine
}

// NewKGAPI creates a new KG API handler.
func NewKGAPI(db *velocity.DB, engine *kg.KnowledgeGraphEngine) *KGAPI {
	return &KGAPI{db: db, kg: engine}
}

// RegisterRoutes registers all KG API routes.
func (a *KGAPI) RegisterRoutes(app *fiber.App) {
	kg := app.Group("/api/v1/kg")

	kg.Post("/ingest", a.handleIngest)
	kg.Post("/ingest/batch", a.handleIngestBatch)
	kg.Get("/connectors", a.handleListConnectors)
	kg.Post("/connectors/import", a.handleConnectorImport)
	kg.Post("/search", a.handleSearch)
	kg.Post("/resource-graph", a.handleResourceGraph)
	kg.Get("/documents/:id", a.handleGetDocument)
	kg.Delete("/documents/:id", a.handleDeleteDocument)
	kg.Get("/graph/:entity_id", a.handleGraphNeighbors)
	kg.Get("/analytics", a.handleAnalytics)
	kg.Post("/sync", a.handleSync)
	kg.Get("/sync/status", a.handleSyncStatus)
	kg.Get("/ner/rules", a.handleListNERRules)
	kg.Post("/ner/rules", a.handleAddNERRule)
}

func (a *KGAPI) handleListConnectors(c fiber.Ctx) error {
	return c.JSON(fiber.Map{"connectors": []fiber.Map{
		{"name": "local_file", "resource_type": string(kg.ResourceObject), "inputs": []string{"path", "root", "limit"}},
		{"name": "url", "resource_type": string(kg.ResourceObject), "inputs": []string{"url"}},
		{"name": "structured_file", "resource_type": string(kg.ResourceSQLRow), "inputs": []string{"path", "table", "limit"}},
		{"name": "static_rows", "resource_type": string(kg.ResourceSQLRow), "inputs": []string{"table", "rows"}},
	}})
}

type kgConnectorImportRequest struct {
	Connector string               `json:"connector"`
	Path      string               `json:"path,omitempty"`
	Root      string               `json:"root,omitempty"`
	URL       string               `json:"url,omitempty"`
	Table     string               `json:"table,omitempty"`
	Rows      []kg.KGConnectorItem `json:"rows,omitempty"`
	Cursor    string               `json:"cursor,omitempty"`
	Limit     int                  `json:"limit,omitempty"`
}

func (a *KGAPI) handleIngest(c fiber.Ctx) error {
	contentType := c.Get("Content-Type")

	var req kg.KGIngestRequest

	if contentType == "application/json" || contentType == "" {
		if err := json.Unmarshal(c.Body(), &req); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid JSON: " + err.Error()})
		}
	} else {
		// Multipart: file + metadata
		file, err := c.FormFile("file")
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "file required"})
		}
		f, err := file.Open()
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "open file: " + err.Error()})
		}
		defer f.Close()

		content, err := io.ReadAll(f)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "read file: " + err.Error()})
		}

		req.Content = content
		req.Source = c.FormValue("source", file.Filename)
		req.MediaType = c.FormValue("media_type", file.Header.Get("Content-Type"))
		req.Title = c.FormValue("title", file.Filename)

		if metaStr := c.FormValue("metadata"); metaStr != "" {
			var meta map[string]string
			if json.Unmarshal([]byte(metaStr), &meta) == nil {
				req.Metadata = meta
			}
		}
	}

	resp, err := a.kg.Ingest(c.Context(), &req)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	return c.Status(fiber.StatusCreated).JSON(resp)
}

func (a *KGAPI) handleIngestBatch(c fiber.Ctx) error {
	var reqs []*kg.KGIngestRequest
	if err := json.Unmarshal(c.Body(), &reqs); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid JSON: " + err.Error()})
	}

	results, errs := a.kg.IngestBatch(c.Context(), reqs)

	type batchResult struct {
		Result *kg.KGIngestResponse `json:"result,omitempty"`
		Error  string               `json:"error,omitempty"`
	}

	out := make([]batchResult, len(reqs))
	for i := range reqs {
		if errs[i] != nil {
			out[i] = batchResult{Error: errs[i].Error()}
		} else {
			out[i] = batchResult{Result: results[i]}
		}
	}

	return c.JSON(fiber.Map{"results": out})
}

func (a *KGAPI) handleConnectorImport(c fiber.Ctx) error {
	var req kgConnectorImportRequest
	if err := json.Unmarshal(c.Body(), &req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid JSON: " + err.Error()})
	}
	connector, err := connectorFromImportRequest(req)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}
	resp, err := a.kg.ImportConnector(c.Context(), connector, req.Cursor, req.Limit)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}
	return c.Status(fiber.StatusCreated).JSON(resp)
}

func connectorFromImportRequest(req kgConnectorImportRequest) (kg.KGConnector, error) {
	switch req.Connector {
	case "local_file", "local-file", "file", "directory", "dir":
		root := req.Root
		if root == "" {
			root = req.Path
		}
		if root == "" {
			return nil, fiber.NewError(fiber.StatusBadRequest, "path or root is required")
		}
		return kg.LocalFileConnector{Root: root}, nil
	case "url", "http":
		if req.URL == "" {
			return nil, fiber.NewError(fiber.StatusBadRequest, "url is required")
		}
		return kg.URLConnector{URL: req.URL}, nil
	case "structured_file", "structured-file", "csv", "json":
		if req.Path == "" {
			return nil, fiber.NewError(fiber.StatusBadRequest, "path is required")
		}
		return kg.StructuredFileConnector{Path: req.Path, Table: req.Table}, nil
	case "static_rows", "static-rows", "rows", "sql_rows", "sql-rows":
		if len(req.Rows) == 0 {
			return nil, fiber.NewError(fiber.StatusBadRequest, "rows are required")
		}
		return kg.StaticRowsConnector{NameValue: "static_rows", Table: req.Table, Rows: req.Rows}, nil
	default:
		return nil, fiber.NewError(fiber.StatusBadRequest, "connector must be one of local_file, url, structured_file, or static_rows")
	}
}

func (a *KGAPI) handleSearch(c fiber.Ctx) error {
	var req kg.KGSearchRequest
	if err := json.Unmarshal(c.Body(), &req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid JSON: " + err.Error()})
	}

	resp, err := a.kg.Search(c.Context(), &req)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	return c.JSON(resp)
}

func (a *KGAPI) handleResourceGraph(c fiber.Ctx) error {
	var req kg.KGResourceGraphRequest
	if err := json.Unmarshal(c.Body(), &req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid JSON: " + err.Error()})
	}

	resp, err := a.kg.SearchResourceGraph(c.Context(), &req)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	return c.JSON(resp)
}

func (a *KGAPI) handleGetDocument(c fiber.Ctx) error {
	docID := c.Params("id")
	if docID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "document ID required"})
	}

	doc, err := a.kg.GetDocument(docID)
	if err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": err.Error()})
	}

	return c.JSON(doc)
}

func (a *KGAPI) handleDeleteDocument(c fiber.Ctx) error {
	docID := c.Params("id")
	if docID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "document ID required"})
	}

	if err := a.kg.DeleteDocument(docID); err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": err.Error()})
	}

	return c.JSON(fiber.Map{"status": "deleted", "doc_id": docID})
}

func (a *KGAPI) handleGraphNeighbors(c fiber.Ctx) error {
	entityID := c.Params("entity_id")
	if entityID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "entity_id required"})
	}

	depth := 1
	if d, err := strconv.Atoi(c.Query("depth", "1")); err == nil && d > 0 {
		depth = d
	}
	relationType := c.Query("relation_type", "")

	result, err := a.kg.GraphNeighbors(c.Context(), entityID, depth, relationType)
	if err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": err.Error()})
	}

	return c.JSON(result)
}

func (a *KGAPI) handleAnalytics(c fiber.Ctx) error {
	analytics := a.kg.GetAnalytics()
	return c.JSON(analytics)
}

func (a *KGAPI) handleSync(c fiber.Ctx) error {
	if a.db == nil {
		return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{"error": "sync unavailable"})
	}
	var cfg velocity.KnowledgeGraphAutoIndexConfig
	if len(c.Body()) > 0 {
		if err := json.Unmarshal(c.Body(), &cfg); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid JSON: " + err.Error()})
		}
	}
	cfg.Enabled = true
	cfg.Existing = true
	if err := a.db.SyncKnowledgeGraph(c.Context(), cfg); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(a.db.KnowledgeGraphSyncStatus())
}

func (a *KGAPI) handleSyncStatus(c fiber.Ctx) error {
	if a.db == nil {
		return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{"error": "sync unavailable"})
	}
	return c.JSON(a.db.KnowledgeGraphSyncStatus())
}

func (a *KGAPI) handleListNERRules(c fiber.Ctx) error {
	return c.JSON(fiber.Map{"rules": a.kg.ListNERRules()})
}

func (a *KGAPI) handleAddNERRule(c fiber.Ctx) error {
	var rule kg.KGCustomNERRule
	if err := json.Unmarshal(c.Body(), &rule); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid JSON: " + err.Error()})
	}
	if err := a.kg.AddNERRule(rule); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}
	return c.Status(fiber.StatusCreated).JSON(rule)
}
