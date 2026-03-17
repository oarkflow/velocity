// Package scheduler provides job scheduling functionality for automation.
package scheduler

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/oarkflow/velocity/internal/secretr/core/crypto"
	"github.com/oarkflow/velocity/internal/secretr/storage"
	"github.com/oarkflow/velocity/internal/secretr/types"
)

var (
	ErrJobNotFound      = errors.New("scheduler: job not found")
	ErrJobExists        = errors.New("scheduler: job already exists")
	ErrSchedulerStopped = errors.New("scheduler: scheduler is stopped")
)

// JobType represents the type of scheduled job
type JobType string

const (
	JobTypeKeyRotation    JobType = "key_rotation"
	JobTypeSecretRotation JobType = "secret_rotation"
	JobTypeBackup         JobType = "backup"
	JobTypeCleanup        JobType = "cleanup"
	JobTypePolicyEval     JobType = "policy_evaluation"
	JobTypeAuditExport    JobType = "audit_export"
	JobTypeSessionPrune   JobType = "session_prune"
)

// Job represents a scheduled job
type Job struct {
	ID          types.ID        `json:"id"`
	Type        JobType         `json:"type"`
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Schedule    string          `json:"schedule"` // Cron expression or interval
	Interval    time.Duration   `json:"interval"`
	Enabled     bool            `json:"enabled"`
	LastRun     *types.Timestamp `json:"last_run,omitempty"`
	NextRun     *types.Timestamp `json:"next_run,omitempty"`
	LastStatus  string          `json:"last_status,omitempty"`
	LastError   string          `json:"last_error,omitempty"`
	RunCount    int             `json:"run_count"`
	Config      types.Metadata  `json:"config,omitempty"`
	CreatedAt   types.Timestamp `json:"created_at"`
	CreatedBy   types.ID        `json:"created_by"`
	Status      types.EntityStatus `json:"status"`
}

// JobExecution represents a job execution record
type JobExecution struct {
	ID        types.ID        `json:"id"`
	JobID     types.ID        `json:"job_id"`
	StartedAt types.Timestamp `json:"started_at"`
	EndedAt   *types.Timestamp `json:"ended_at,omitempty"`
	Status    string          `json:"status"` // running, success, failed
	Error     string          `json:"error,omitempty"`
	Output    types.Metadata  `json:"output,omitempty"`
}

// JobHandler is a function that executes a job
type JobHandler func(ctx context.Context, job *Job) error

// Scheduler manages scheduled jobs
type Scheduler struct {
	store         *storage.Store
	crypto        *crypto.Engine
	jobStore      *storage.TypedStore[Job]
	execStore     *storage.TypedStore[JobExecution]
	handlers      map[JobType]JobHandler
	running       bool
	mu            sync.RWMutex
	stopCh        chan struct{}
	wg            sync.WaitGroup
	checkInterval time.Duration
}

// Config configures the scheduler
type Config struct {
	Store         *storage.Store
	CheckInterval time.Duration // How often to check for jobs to run
}

// NewScheduler creates a new scheduler
func NewScheduler(cfg Config) *Scheduler {
	if cfg.CheckInterval == 0 {
		cfg.CheckInterval = 1 * time.Minute
	}

	return &Scheduler{
		store:         cfg.Store,
		crypto:        crypto.NewEngine(""),
		jobStore:      storage.NewTypedStore[Job](cfg.Store, "scheduled_jobs"),
		execStore:     storage.NewTypedStore[JobExecution](cfg.Store, "job_executions"),
		handlers:      make(map[JobType]JobHandler),
		checkInterval: cfg.CheckInterval,
	}
}

// RegisterHandler registers a handler for a job type
func (s *Scheduler) RegisterHandler(jobType JobType, handler JobHandler) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.handlers[jobType] = handler
}

// Start starts the scheduler
func (s *Scheduler) Start(ctx context.Context) error {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return nil
	}
	s.running = true
	s.stopCh = make(chan struct{})
	s.mu.Unlock()

	s.wg.Add(1)
	go s.run(ctx)

	return nil
}

// Stop stops the scheduler
func (s *Scheduler) Stop() error {
	s.mu.Lock()
	if !s.running {
		s.mu.Unlock()
		return nil
	}
	s.running = false
	close(s.stopCh)
	s.mu.Unlock()

	s.wg.Wait()
	return nil
}

// run is the main scheduler loop
func (s *Scheduler) run(ctx context.Context) {
	defer s.wg.Done()

	ticker := time.NewTicker(s.checkInterval)
	defer ticker.Stop()

	for {
		select {
		case <-s.stopCh:
			return
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.checkAndRunJobs(ctx)
		}
	}
}

// checkAndRunJobs checks for jobs that need to run
func (s *Scheduler) checkAndRunJobs(ctx context.Context) {
	jobs, err := s.ListJobs(ctx, true)
	if err != nil {
		return
	}

	now := types.Now()
	for _, job := range jobs {
		if !job.Enabled || job.Status != types.StatusActive {
			continue
		}

		// Check if job should run
		shouldRun := false
		if job.NextRun != nil && now >= *job.NextRun {
			shouldRun = true
		} else if job.NextRun == nil && job.LastRun == nil {
			// Never run before
			shouldRun = true
		}

		if shouldRun {
			s.wg.Add(1)
			go func(j *Job) {
				defer s.wg.Done()
				s.executeJob(ctx, j)
			}(job)
		}
	}
}

// executeJob executes a single job
func (s *Scheduler) executeJob(ctx context.Context, job *Job) {
	s.mu.RLock()
	handler, exists := s.handlers[job.Type]
	s.mu.RUnlock()

	if !exists {
		job.LastStatus = "failed"
		job.LastError = "no handler registered"
		s.jobStore.Set(ctx, string(job.ID), job)
		return
	}

	// Create execution record
	execID, _ := s.crypto.GenerateRandomID()
	exec := &JobExecution{
		ID:        execID,
		JobID:     job.ID,
		StartedAt: types.Now(),
		Status:    "running",
	}
	s.execStore.Set(ctx, string(exec.ID), exec)

	// Execute the job
	err := handler(ctx, job)

	// Update execution record
	endedAt := types.Now()
	exec.EndedAt = &endedAt
	if err != nil {
		exec.Status = "failed"
		exec.Error = err.Error()
	} else {
		exec.Status = "success"
	}
	s.execStore.Set(ctx, string(exec.ID), exec)

	// Update job
	now := types.Now()
	job.LastRun = &now
	job.RunCount++
	if err != nil {
		job.LastStatus = "failed"
		job.LastError = err.Error()
	} else {
		job.LastStatus = "success"
		job.LastError = ""
	}

	// Calculate next run
	if job.Interval > 0 {
		nextRun := types.Timestamp(time.Now().Add(job.Interval).UnixNano())
		job.NextRun = &nextRun
	}

	s.jobStore.Set(ctx, string(job.ID), job)
}

// CreateJob creates a new scheduled job
func (s *Scheduler) CreateJob(ctx context.Context, opts CreateJobOptions) (*Job, error) {
	id, err := s.crypto.GenerateRandomID()
	if err != nil {
		return nil, err
	}

	job := &Job{
		ID:          id,
		Type:        opts.Type,
		Name:        opts.Name,
		Description: opts.Description,
		Schedule:    opts.Schedule,
		Interval:    opts.Interval,
		Enabled:     true,
		Config:      opts.Config,
		CreatedAt:   types.Now(),
		CreatedBy:   opts.CreatorID,
		Status:      types.StatusActive,
	}

	// Set initial next run
	if opts.Interval > 0 {
		nextRun := types.Timestamp(time.Now().Add(opts.Interval).UnixNano())
		job.NextRun = &nextRun
	} else if opts.RunImmediately {
		nextRun := types.Now()
		job.NextRun = &nextRun
	}

	if err := s.jobStore.Set(ctx, string(job.ID), job); err != nil {
		return nil, err
	}

	return job, nil
}

// CreateJobOptions holds job creation options
type CreateJobOptions struct {
	Type           JobType
	Name           string
	Description    string
	Schedule       string
	Interval       time.Duration
	RunImmediately bool
	Config         types.Metadata
	CreatorID      types.ID
}

// GetJob retrieves a job by ID
func (s *Scheduler) GetJob(ctx context.Context, id types.ID) (*Job, error) {
	job, err := s.jobStore.Get(ctx, string(id))
	if err != nil {
		return nil, ErrJobNotFound
	}
	return job, nil
}

// ListJobs lists all jobs
func (s *Scheduler) ListJobs(ctx context.Context, enabledOnly bool) ([]*Job, error) {
	jobs, err := s.jobStore.List(ctx, "")
	if err != nil {
		return nil, err
	}

	if !enabledOnly {
		return jobs, nil
	}

	var result []*Job
	for _, j := range jobs {
		if j.Enabled && j.Status == types.StatusActive {
			result = append(result, j)
		}
	}
	return result, nil
}

// EnableJob enables a job
func (s *Scheduler) EnableJob(ctx context.Context, id types.ID) error {
	job, err := s.GetJob(ctx, id)
	if err != nil {
		return err
	}
	job.Enabled = true
	return s.jobStore.Set(ctx, string(job.ID), job)
}

// DisableJob disables a job
func (s *Scheduler) DisableJob(ctx context.Context, id types.ID) error {
	job, err := s.GetJob(ctx, id)
	if err != nil {
		return err
	}
	job.Enabled = false
	return s.jobStore.Set(ctx, string(job.ID), job)
}

// DeleteJob deletes a job
func (s *Scheduler) DeleteJob(ctx context.Context, id types.ID) error {
	job, err := s.GetJob(ctx, id)
	if err != nil {
		return err
	}
	job.Status = types.StatusRevoked
	return s.jobStore.Set(ctx, string(job.ID), job)
}

// RunJobNow runs a job immediately
func (s *Scheduler) RunJobNow(ctx context.Context, id types.ID) error {
	job, err := s.GetJob(ctx, id)
	if err != nil {
		return err
	}

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.executeJob(ctx, job)
	}()

	return nil
}

// GetJobExecutions retrieves execution history for a job
func (s *Scheduler) GetJobExecutions(ctx context.Context, jobID types.ID, limit int) ([]*JobExecution, error) {
	executions, err := s.execStore.List(ctx, "")
	if err != nil {
		return nil, err
	}

	var result []*JobExecution
	for _, e := range executions {
		if e.JobID == jobID {
			result = append(result, e)
			if limit > 0 && len(result) >= limit {
				break
			}
		}
	}
	return result, nil
}

// UpdateJobInterval updates a job's interval
func (s *Scheduler) UpdateJobInterval(ctx context.Context, id types.ID, interval time.Duration) error {
	job, err := s.GetJob(ctx, id)
	if err != nil {
		return err
	}
	job.Interval = interval

	// Update next run
	nextRun := types.Timestamp(time.Now().Add(interval).UnixNano())
	job.NextRun = &nextRun

	return s.jobStore.Set(ctx, string(job.ID), job)
}

// Built-in job handlers

// CreateKeyRotationHandler creates a key rotation job handler
func CreateKeyRotationHandler(rotateFunc func(ctx context.Context, keyID types.ID) error) JobHandler {
	return func(ctx context.Context, job *Job) error {
		keyID, ok := job.Config["key_id"].(string)
		if !ok {
			return fmt.Errorf("key_id not configured")
		}
		return rotateFunc(ctx, types.ID(keyID))
	}
}

// CreateSecretRotationHandler creates a secret rotation job handler
func CreateSecretRotationHandler(rotateFunc func(ctx context.Context, secretName string) error) JobHandler {
	return func(ctx context.Context, job *Job) error {
		secretName, ok := job.Config["secret_name"].(string)
		if !ok {
			return fmt.Errorf("secret_name not configured")
		}
		return rotateFunc(ctx, secretName)
	}
}

// CreateBackupHandler creates a backup job handler
func CreateBackupHandler(backupFunc func(ctx context.Context, backupType string) error) JobHandler {
	return func(ctx context.Context, job *Job) error {
		backupType, _ := job.Config["backup_type"].(string)
		if backupType == "" {
			backupType = "full"
		}
		return backupFunc(ctx, backupType)
	}
}

// CreateSessionPruneHandler creates a session prune job handler
func CreateSessionPruneHandler(pruneFunc func(ctx context.Context, maxAge time.Duration) (int, error)) JobHandler {
	return func(ctx context.Context, job *Job) error {
		maxAgeHours, _ := job.Config["max_age_hours"].(float64)
		if maxAgeHours == 0 {
			maxAgeHours = 24 // Default to 24 hours
		}
		maxAge := time.Duration(maxAgeHours) * time.Hour
		_, err := pruneFunc(ctx, maxAge)
		return err
	}
}

// Close cleans up resources
func (s *Scheduler) Close() error {
	s.Stop()
	return s.crypto.Close()
}
