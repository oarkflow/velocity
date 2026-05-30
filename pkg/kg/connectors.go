package kg

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// LocalFileConnector imports a single file or all regular files under a directory.
type LocalFileConnector struct {
	Root string
}

func (c LocalFileConnector) Name() string { return "local_file" }

func (c LocalFileConnector) ResourceType() ResourceType { return ResourceObject }

func (c LocalFileConnector) List(ctx context.Context, cursor string) ([]KGConnectorItem, string, error) {
	root := strings.TrimSpace(c.Root)
	if root == "" {
		return nil, "", fmt.Errorf("root is required")
	}
	var items []KGConnectorItem
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if d.IsDir() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		mediaType := mime.TypeByExtension(filepath.Ext(path))
		if mediaType == "" {
			mediaType = "text/plain"
		}
		items = append(items, KGConnectorItem{
			Source:       "file:" + filepath.ToSlash(path),
			ResourceType: ResourceObject,
			ResourceID:   filepath.ToSlash(path),
			MediaType:    mediaType,
			Title:        filepath.Base(path),
			Metadata: map[string]string{
				"connector": "local_file",
				"path":      filepath.ToSlash(path),
				"size":      intString(int(info.Size())),
				"mod_time":  info.ModTime().UTC().Format(time.RFC3339),
			},
		})
		return nil
	})
	return items, "", err
}

func (c LocalFileConnector) Fetch(ctx context.Context, item KGConnectorItem) (*KGIngestRequest, error) {
	path := strings.TrimPrefix(item.ResourceID, "file:")
	if path == "" {
		path = strings.TrimPrefix(item.Source, "file:")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return &KGIngestRequest{
		Source:    item.Source,
		Content:   data,
		MediaType: item.MediaType,
		Title:     item.Title,
		Metadata:  item.Metadata,
	}, nil
}

// URLConnector imports one HTTP(S) response as a KG document.
type URLConnector struct {
	URL    string
	Client *http.Client
}

func (c URLConnector) Name() string { return "url" }

func (c URLConnector) ResourceType() ResourceType { return ResourceObject }

func (c URLConnector) List(ctx context.Context, cursor string) ([]KGConnectorItem, string, error) {
	if strings.TrimSpace(c.URL) == "" {
		return nil, "", fmt.Errorf("url is required")
	}
	return []KGConnectorItem{{
		Source:       "url:" + c.URL,
		ResourceType: ResourceObject,
		ResourceID:   c.URL,
		Title:        c.URL,
		Metadata:     map[string]string{"connector": "url", "url": c.URL},
	}}, "", ctx.Err()
}

func (c URLConnector) Fetch(ctx context.Context, item KGConnectorItem) (*KGIngestRequest, error) {
	client := c.Client
	if client == nil {
		client = http.DefaultClient
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, item.ResourceID, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("fetch %s: status %d", item.ResourceID, resp.StatusCode)
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	mediaType := item.MediaType
	if mediaType == "" {
		mediaType = resp.Header.Get("Content-Type")
	}
	return &KGIngestRequest{
		Source:    item.Source,
		Content:   data,
		MediaType: mediaType,
		Title:     item.Title,
		Metadata:  item.Metadata,
	}, nil
}

// StaticRowsConnector adapts already-materialized table rows to KG ingest
// requests. SQL drivers can use this without pkg/kg importing database/sql.
type StaticRowsConnector struct {
	NameValue string
	Table     string
	Rows      []KGConnectorItem
}

func (c StaticRowsConnector) Name() string {
	if c.NameValue != "" {
		return c.NameValue
	}
	return "static_rows"
}

func (c StaticRowsConnector) ResourceType() ResourceType { return ResourceSQLRow }

func (c StaticRowsConnector) List(ctx context.Context, cursor string) ([]KGConnectorItem, string, error) {
	out := make([]KGConnectorItem, len(c.Rows))
	copy(out, c.Rows)
	for i := range out {
		if out[i].ResourceType == "" {
			out[i].ResourceType = ResourceSQLRow
		}
		if out[i].MediaType == "" {
			out[i].MediaType = "application/json"
		}
		if out[i].Metadata == nil {
			out[i].Metadata = make(map[string]string)
		}
		out[i].Metadata["connector"] = c.Name()
		if c.Table != "" {
			out[i].Metadata["table"] = c.Table
		}
	}
	return out, "", ctx.Err()
}

func (c StaticRowsConnector) Fetch(ctx context.Context, item KGConnectorItem) (*KGIngestRequest, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	content := item.Content
	if len(content) == 0 && item.Metadata != nil {
		content = []byte(item.Metadata["content"])
	}
	return &KGIngestRequest{
		Source:    item.Source,
		Content:   content,
		MediaType: item.MediaType,
		Title:     item.Title,
		Metadata:  item.Metadata,
	}, nil
}

// StructuredFileConnector imports CSV or JSON records as individual KG rows.
type StructuredFileConnector struct {
	Path  string
	Table string
}

func (c StructuredFileConnector) Name() string { return "structured_file" }

func (c StructuredFileConnector) ResourceType() ResourceType { return ResourceSQLRow }

func (c StructuredFileConnector) List(ctx context.Context, cursor string) ([]KGConnectorItem, string, error) {
	path := strings.TrimSpace(c.Path)
	if path == "" {
		return nil, "", fmt.Errorf("path is required")
	}
	switch strings.ToLower(filepath.Ext(path)) {
	case ".csv", ".tsv":
		return c.listDelimited(ctx, path)
	case ".json":
		return c.listJSON(ctx, path)
	default:
		return nil, "", fmt.Errorf("unsupported structured file extension: %s", filepath.Ext(path))
	}
}

func (c StructuredFileConnector) Fetch(ctx context.Context, item KGConnectorItem) (*KGIngestRequest, error) {
	return StaticRowsConnector{}.Fetch(ctx, item)
}

func (c StructuredFileConnector) listDelimited(ctx context.Context, path string) ([]KGConnectorItem, string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, "", err
	}
	defer file.Close()
	reader := csv.NewReader(file)
	if strings.EqualFold(filepath.Ext(path), ".tsv") {
		reader.Comma = '\t'
	}
	rows, err := reader.ReadAll()
	if err != nil {
		return nil, "", err
	}
	if len(rows) == 0 {
		return nil, "", nil
	}
	headers := rows[0]
	items := make([]KGConnectorItem, 0, len(rows)-1)
	for i, row := range rows[1:] {
		if ctx.Err() != nil {
			return items, "", ctx.Err()
		}
		record := make(map[string]string, len(headers))
		for col, header := range headers {
			if col < len(row) {
				record[header] = row[col]
			}
		}
		content, _ := json.Marshal(record)
		rowKey := fmt.Sprintf("%s:%d", filepath.Base(path), i+1)
		items = append(items, KGConnectorItem{
			Source:       "structured:" + filepath.ToSlash(path) + ":" + intString(i+1),
			ResourceType: ResourceSQLRow,
			ResourceID:   rowKey,
			MediaType:    "application/json",
			Title:        rowKey,
			Content:      content,
			Metadata: map[string]string{
				"connector": "structured_file",
				"path":      filepath.ToSlash(path),
				"table":     c.tableName(path),
				"row":       intString(i + 1),
			},
		})
	}
	return items, "", nil
}

func (c StructuredFileConnector) listJSON(ctx context.Context, path string) ([]KGConnectorItem, string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, "", err
	}
	var decoded any
	if err := json.Unmarshal(data, &decoded); err != nil {
		return nil, "", err
	}
	var rows []any
	switch v := decoded.(type) {
	case []any:
		rows = v
	default:
		rows = []any{v}
	}
	items := make([]KGConnectorItem, 0, len(rows))
	for i, row := range rows {
		if ctx.Err() != nil {
			return items, "", ctx.Err()
		}
		content, _ := json.Marshal(row)
		rowKey := fmt.Sprintf("%s:%d", filepath.Base(path), i+1)
		items = append(items, KGConnectorItem{
			Source:       "structured:" + filepath.ToSlash(path) + ":" + intString(i+1),
			ResourceType: ResourceSQLRow,
			ResourceID:   rowKey,
			MediaType:    "application/json",
			Title:        rowKey,
			Content:      content,
			Metadata: map[string]string{
				"connector": "structured_file",
				"path":      filepath.ToSlash(path),
				"table":     c.tableName(path),
				"row":       intString(i + 1),
			},
		})
	}
	return items, "", nil
}

func (c StructuredFileConnector) tableName(path string) string {
	if strings.TrimSpace(c.Table) != "" {
		return c.Table
	}
	base := filepath.Base(path)
	return strings.TrimSuffix(base, filepath.Ext(base))
}
