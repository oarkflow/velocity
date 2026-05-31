package kg

import (
	"context"
	"testing"
	"time"
)

func TestImportJobLifecycleAndRetry(t *testing.T) {
	ctx := context.Background()
	engine, err := NewKnowledgeGraphEngine(newTestStore(), KGConfig{})
	if err != nil {
		t.Fatalf("new kg engine: %v", err)
	}
	connector := StaticRowsConnector{
		NameValue: "jobs",
		Table:     "cases",
		Rows: []KGConnectorItem{{
			Source:    "job-row-1",
			MediaType: "text/plain",
			Title:     "Job Row",
			Content:   []byte("CASE-90909 import job"),
		}},
	}

	job, err := engine.StartImportJob(ctx, connector, "", 10)
	if err != nil {
		t.Fatalf("start job: %v", err)
	}
	if job.Status != KGImportJobSucceeded || job.Imported != 1 || job.Metrics["duration_ms"] < 0 {
		t.Fatalf("unexpected completed job: %+v", job)
	}

	got, err := engine.GetImportJob(ctx, job.JobID)
	if err != nil {
		t.Fatalf("get job: %v", err)
	}
	if got.JobID != job.JobID || got.Connector != "jobs" {
		t.Fatalf("unexpected stored job: %+v", got)
	}

	jobs, err := engine.ListImportJobs(ctx, KGImportJobSucceeded)
	if err != nil {
		t.Fatalf("list jobs: %v", err)
	}
	if len(jobs) != 1 {
		t.Fatalf("expected one succeeded job, got %+v", jobs)
	}

	retried, err := engine.RetryImportJob(ctx, job.JobID, connector)
	if err != nil {
		t.Fatalf("retry job: %v", err)
	}
	if retried.RetryCount != 1 || retried.Status != KGImportJobSucceeded {
		t.Fatalf("unexpected retried job: %+v", retried)
	}
}

func TestCancelImportJob(t *testing.T) {
	ctx := context.Background()
	engine, err := NewKnowledgeGraphEngine(newTestStore(), KGConfig{})
	if err != nil {
		t.Fatalf("new kg engine: %v", err)
	}
	job := &KGImportJob{JobID: "job-pending", Connector: "manual", Status: KGImportJobPending}
	if err := engine.putImportJob(job); err != nil {
		t.Fatalf("seed job: %v", err)
	}
	cancelled, err := engine.CancelImportJob(ctx, "job-pending")
	if err != nil {
		t.Fatalf("cancel job: %v", err)
	}
	if cancelled.Status != KGImportJobCancelled {
		t.Fatalf("expected cancelled job: %+v", cancelled)
	}
}

func TestAsyncImportJobCanBeCancelled(t *testing.T) {
	ctx := context.Background()
	engine, err := NewKnowledgeGraphEngine(newTestStore(), KGConfig{})
	if err != nil {
		t.Fatalf("new kg engine: %v", err)
	}
	connector := slowConnector{}
	job, err := engine.StartImportJobAsync(ctx, connector, "", 0)
	if err != nil {
		t.Fatalf("start async job: %v", err)
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		got, err := engine.GetImportJob(ctx, job.JobID)
		if err == nil && got.Status == KGImportJobRunning {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancelled, err := engine.CancelImportJob(ctx, job.JobID)
	if err != nil {
		t.Fatalf("cancel running job: %v", err)
	}
	if cancelled.Status != KGImportJobCancelled {
		t.Fatalf("expected cancelled status: %+v", cancelled)
	}
	deadline = time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		got, err := engine.GetImportJob(ctx, job.JobID)
		if err == nil && got.Status == KGImportJobCancelled {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("async job did not settle as cancelled")
}

type slowConnector struct{}

func (slowConnector) Name() string { return "slow" }

func (slowConnector) ResourceType() ResourceType { return ResourceObject }

func (slowConnector) List(context.Context, string) ([]KGConnectorItem, string, error) {
	return []KGConnectorItem{
		{Source: "slow-1", MediaType: "text/plain"},
		{Source: "slow-2", MediaType: "text/plain"},
	}, "", nil
}

func (slowConnector) Fetch(ctx context.Context, item KGConnectorItem) (*KGIngestRequest, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(250 * time.Millisecond):
		return &KGIngestRequest{Source: item.Source, MediaType: "text/plain", Content: []byte("slow import CASE-55555")}, nil
	}
}
