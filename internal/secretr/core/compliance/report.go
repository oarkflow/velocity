package compliance

import (
	"bytes"
	"fmt"
	"html/template"
	"time"
)

// ReportFormat defines the report output format
type ReportFormat string

const (
	ReportFormatHTML     ReportFormat = "html"
	ReportFormatJSON     ReportFormat = "json"
	ReportFormatMarkdown ReportFormat = "markdown"

	// htmlTemplate is a simple embedded template for compliance reports
	htmlTemplate = `
<!DOCTYPE html>
<html>
<head>
	<title>Compliance Assessment Report: {{.Name}}</title>
	<style>
		body { font-family: sans-serif; margin: 40px; }
		h1 { color: #333; }
		.meta { color: #666; margin-bottom: 30px; }
		.status { font-weight: bold; }
		.status-pass { color: green; }
		.status-fail { color: red; }
		.control { border: 1px solid #ccc; padding: 15px; margin-bottom: 20px; border-radius: 5px; }
		.question { font-weight: bold; margin-bottom: 10px; }
		.answer { margin-bottom: 10px; }
		.evidence { font-size: 0.9em; color: #555; }
	</style>
</head>
<body>
	<h1>Compliance Assessment Report</h1>
	<div class="meta">
		<p><strong>Assessment:</strong> {{.Name}}</p>
		<p><strong>Framework:</strong> {{.Framework}}</p>
		<p><strong>Generated At:</strong> {{.GeneratedAt}}</p>
		<p><strong>Status:</strong> <span class="status">{{.Status}}</span></p>
	</div>

	<h2>Controls & Answers</h2>
	{{range .Items}}
	<div class="control">
		<div class="question">{{.QuestionText}}</div>
		<div class="answer">Answer: {{.AnswerValue}}</div>
		{{if .Notes}}
		<div class="notes">Notes: {{.Notes}}</div>
		{{end}}
	</div>
	{{end}}
</body>
</html>
`
)

// GenerateReport generates a compliance report
func GenerateReport(assessment *Assessment, format ReportFormat) ([]byte, error) {
	switch format {
	case ReportFormatHTML:
		return generateHTMLReport(assessment)
	default:
		return nil, fmt.Errorf("compliance: unsupported report format %s", format)
	}
}

type reportData struct {
	Name        string
	Framework   string
	GeneratedAt string
	Status      string
	Items       []reportItem
}

type reportItem struct {
	QuestionText string
	AnswerValue  string
	Notes        string
}

func generateHTMLReport(a *Assessment) ([]byte, error) {
	tmpl, err := template.New("report").Parse(htmlTemplate)
	if err != nil {
		return nil, err
	}

	data := reportData{
		Name:        a.Name,
		Framework:   string(a.Framework),
		GeneratedAt: time.Now().Format(time.RFC1123),
		Status:      string(a.Status),
	}

	for _, q := range a.Questions {
		ans := ""
		notes := ""
		if q.Answer != nil {
			ans = q.Answer.Value
			notes = q.Answer.Notes
		}
		data.Items = append(data.Items, reportItem{
			QuestionText: q.Text,
			AnswerValue:  ans,
			Notes:        notes,
		})
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}
