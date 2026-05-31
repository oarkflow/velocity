package kg

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

func (e *KnowledgeGraphEngine) StartImportJob(ctx context.Context, connector KGConnector, cursor string, limit int) (*KGImportJob, error) {
	job, err := e.createImportJob(ctx, connector, cursor, limit)
	if err != nil {
		return nil, err
	}
	return e.runImportJob(ctx, job, connector)
}

func (e *KnowledgeGraphEngine) StartImportJobAsync(ctx context.Context, connector KGConnector, cursor string, limit int) (*KGImportJob, error) {
	job, err := e.createImportJob(ctx, connector, cursor, limit)
	if err != nil {
		return nil, err
	}
	go func() {
		_, _ = e.runImportJob(context.Background(), job, connector)
	}()
	return job, nil
}

func (e *KnowledgeGraphEngine) createImportJob(ctx context.Context, connector KGConnector, cursor string, limit int) (*KGImportJob, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if e == nil {
		return nil, fmt.Errorf("knowledge graph engine is nil")
	}
	if connector == nil {
		return nil, fmt.Errorf("connector is required")
	}
	now := time.Now().UTC()
	job := &KGImportJob{
		JobID:        stableImportJobID(connector.Name(), cursor, now),
		Connector:    connector.Name(),
		ResourceType: connector.ResourceType(),
		Cursor:       cursor,
		Limit:        limit,
		Status:       KGImportJobPending,
		Metrics:      map[string]int64{},
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	if err := e.putImportJob(job); err != nil {
		return nil, err
	}
	return job, nil
}

func (e *KnowledgeGraphEngine) GetImportJob(ctx context.Context, jobID string) (*KGImportJob, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	jobID = strings.TrimSpace(jobID)
	if jobID == "" {
		return nil, fmt.Errorf("job_id is required")
	}
	data, err := e.db.Get([]byte(kgJobPrefix + jobID))
	if err != nil {
		return nil, fmt.Errorf("import job not found: %s", jobID)
	}
	var job KGImportJob
	if err := json.Unmarshal(data, &job); err != nil {
		return nil, fmt.Errorf("decode import job %s: %w", jobID, err)
	}
	return &job, nil
}

func (e *KnowledgeGraphEngine) ListImportJobs(ctx context.Context, status KGImportJobStatus) ([]KGImportJob, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	keys, err := e.db.Keys(kgJobPrefix + "*")
	if err != nil {
		return nil, err
	}
	jobs := make([]KGImportJob, 0, len(keys))
	for _, key := range keys {
		data, err := e.db.Get([]byte(key))
		if err != nil {
			continue
		}
		var job KGImportJob
		if json.Unmarshal(data, &job) != nil {
			continue
		}
		if status == "" || job.Status == status {
			jobs = append(jobs, job)
		}
	}
	sort.Slice(jobs, func(i, j int) bool { return jobs[i].CreatedAt.Before(jobs[j].CreatedAt) })
	return jobs, nil
}

func (e *KnowledgeGraphEngine) CancelImportJob(ctx context.Context, jobID string) (*KGImportJob, error) {
	job, err := e.GetImportJob(ctx, jobID)
	if err != nil {
		return nil, err
	}
	if job.Status == KGImportJobSucceeded || job.Status == KGImportJobFailed {
		return nil, fmt.Errorf("cannot cancel completed job %s", job.JobID)
	}
	e.jobMu.Lock()
	if stop := e.jobStops[job.JobID]; stop != nil {
		stop()
	}
	e.jobMu.Unlock()
	job.Status = KGImportJobCancelled
	job.UpdatedAt = time.Now().UTC()
	job.FinishedAt = job.UpdatedAt
	return job, e.putImportJob(job)
}

func (e *KnowledgeGraphEngine) RetryImportJob(ctx context.Context, jobID string, connector KGConnector) (*KGImportJob, error) {
	job, err := e.GetImportJob(ctx, jobID)
	if err != nil {
		return nil, err
	}
	if connector == nil {
		return nil, fmt.Errorf("connector is required to retry import job")
	}
	if connector.Name() != job.Connector {
		return nil, fmt.Errorf("connector mismatch: job=%s retry=%s", job.Connector, connector.Name())
	}
	job.RetryCount++
	job.Status = KGImportJobPending
	job.Errors = nil
	job.Imported = 0
	job.Skipped = 0
	job.UpdatedAt = time.Now().UTC()
	if err := e.putImportJob(job); err != nil {
		return nil, err
	}
	return e.runImportJob(ctx, job, connector)
}

func (e *KnowledgeGraphEngine) runImportJob(ctx context.Context, job *KGImportJob, connector KGConnector) (*KGImportJob, error) {
	current, err := e.GetImportJob(ctx, job.JobID)
	if err == nil && current.Status == KGImportJobCancelled {
		return current, nil
	}
	ctx, cancel := context.WithCancel(ctx)
	e.jobMu.Lock()
	e.jobStops[job.JobID] = cancel
	e.jobMu.Unlock()
	defer func() {
		cancel()
		e.jobMu.Lock()
		delete(e.jobStops, job.JobID)
		e.jobMu.Unlock()
	}()
	start := time.Now().UTC()
	job.Status = KGImportJobRunning
	job.StartedAt = start
	job.UpdatedAt = start
	if err := e.putImportJob(job); err != nil {
		return nil, err
	}
	resp, err := e.ImportConnector(ctx, connector, job.Cursor, job.Limit)
	finish := time.Now().UTC()
	job.FinishedAt = finish
	job.UpdatedAt = finish
	job.Metrics["duration_ms"] = finish.Sub(start).Milliseconds()
	if resp != nil {
		job.Imported = resp.Imported
		job.Skipped = resp.Skipped
		job.NextCursor = resp.NextCursor
		job.Errors = append(job.Errors, resp.Errors...)
	}
	if err != nil {
		job.Status = KGImportJobFailed
		job.Errors = append(job.Errors, err.Error())
	} else if ctx.Err() != nil {
		job.Status = KGImportJobCancelled
		job.Errors = append(job.Errors, ctx.Err().Error())
	} else {
		job.Status = KGImportJobSucceeded
	}
	if putErr := e.putImportJob(job); putErr != nil {
		return nil, putErr
	}
	return job, err
}

func (e *KnowledgeGraphEngine) putImportJob(job *KGImportJob) error {
	data, err := json.Marshal(job)
	if err != nil {
		return err
	}
	return e.db.Put([]byte(kgJobPrefix+job.JobID), data)
}

func stableImportJobID(connector, cursor string, t time.Time) string {
	h := sha256.Sum256([]byte(fmt.Sprintf("%s\x00%s\x00%d", connector, cursor, t.UnixNano())))
	return "job-" + hex.EncodeToString(h[:12])
}
