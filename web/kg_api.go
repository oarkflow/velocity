package web

import (
	"encoding/json"
	"io"
	"strconv"

	"github.com/gofiber/fiber/v3"
	"github.com/oarkflow/velocity"
)

// KGAPI provides HTTP endpoints for the Knowledge Graph subsystem.
type KGAPI struct {
	kg *velocity.KnowledgeGraphEngine
}

// NewKGAPI creates a new KG API handler.
func NewKGAPI(kg *velocity.KnowledgeGraphEngine) *KGAPI {
	return &KGAPI{kg: kg}
}

// RegisterRoutes registers all KG API routes.
func (a *KGAPI) RegisterRoutes(app *fiber.App) {
	kg := app.Group("/api/v1/kg")

	kg.Post("/ingest", a.handleIngest)
	kg.Post("/ingest/batch", a.handleIngestBatch)
	kg.Post("/search", a.handleSearch)
	kg.Get("/documents/:id", a.handleGetDocument)
	kg.Delete("/documents/:id", a.handleDeleteDocument)
	kg.Get("/graph/:entity_id", a.handleGraphNeighbors)
	kg.Get("/analytics", a.handleAnalytics)
}

func (a *KGAPI) handleIngest(c fiber.Ctx) error {
	contentType := c.Get("Content-Type")

	var req velocity.KGIngestRequest

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
	var reqs []*velocity.KGIngestRequest
	if err := json.Unmarshal(c.Body(), &reqs); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid JSON: " + err.Error()})
	}

	results, errs := a.kg.IngestBatch(c.Context(), reqs)

	type batchResult struct {
		Result *velocity.KGIngestResponse `json:"result,omitempty"`
		Error  string                     `json:"error,omitempty"`
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

func (a *KGAPI) handleSearch(c fiber.Ctx) error {
	var req velocity.KGSearchRequest
	if err := json.Unmarshal(c.Body(), &req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid JSON: " + err.Error()})
	}

	resp, err := a.kg.Search(c.Context(), &req)
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

	result, err := a.kg.GraphNeighbors(c.Context(), entityID, depth)
	if err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": err.Error()})
	}

	return c.JSON(result)
}

func (a *KGAPI) handleAnalytics(c fiber.Ctx) error {
	analytics := a.kg.GetAnalytics()
	return c.JSON(analytics)
}
