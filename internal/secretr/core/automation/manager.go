package automation

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"sync"

	"github.com/oarkflow/velocity/internal/secretr/core/crypto"
	"github.com/oarkflow/velocity/internal/secretr/storage"
	"github.com/oarkflow/velocity/internal/secretr/types"
)

// StepHandler is a function that executes an automation step
type StepHandler func(ctx context.Context, params map[string]string) error

// FunctionHandler is a function that returns a value for interpolation
type FunctionHandler func(args ...string) (string, error)

// Manager handles the execution and management of automation pipelines
type Manager struct {
	store         *storage.Store
	pipelineStore *storage.TypedStore[types.AutomationPipeline]
	crypto        *crypto.Engine
	handlers      map[string]StepHandler
	functions     map[string]FunctionHandler
	mu            sync.RWMutex
}

// ManagerConfig holds configuration for the automation manager
type ManagerConfig struct {
	Store  *storage.Store
	Crypto *crypto.Engine
}

// NewManager creates a new automation manager
func NewManager(cfg ManagerConfig) *Manager {
	return &Manager{
		store:         cfg.Store,
		pipelineStore: storage.NewTypedStore[types.AutomationPipeline](cfg.Store, storage.CollectionPipelines),
		crypto:        cfg.Crypto,
		handlers:      make(map[string]StepHandler),
		functions:     make(map[string]FunctionHandler),
	}
}

// RegisterHandler registers a new step handler
func (m *Manager) RegisterHandler(stepType string, handler StepHandler) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.handlers[stepType] = handler
}

// RegisterFunction registers a new function handler
func (m *Manager) RegisterFunction(name string, handler FunctionHandler) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.functions[name] = handler
}

// CreatePipeline creates a new automation pipeline
func (m *Manager) CreatePipeline(ctx context.Context, pipeline *types.AutomationPipeline) error {
	if pipeline.ID == "" {
		id, err := m.crypto.GenerateRandomID()
		if err != nil {
			return err
		}
		pipeline.ID = id
	}

	now := types.Now()
	pipeline.CreatedAt = now
	pipeline.UpdatedAt = now
	pipeline.Status = types.StatusActive

	return m.pipelineStore.Set(ctx, string(pipeline.ID), pipeline)
}

// GetPipeline retrieves a pipeline by ID
func (m *Manager) GetPipeline(ctx context.Context, id types.ID) (*types.AutomationPipeline, error) {
	return m.pipelineStore.Get(ctx, string(id))
}

// ListPipelines lists pipelines for an organization
func (m *Manager) ListPipelines(ctx context.Context, orgID types.ID) ([]*types.AutomationPipeline, error) {
	pipelines, err := m.pipelineStore.List(ctx, "")
	if err != nil {
		return nil, err
	}

	var orgPipelines []*types.AutomationPipeline
	for _, p := range pipelines {
		if p.OrgID == orgID {
			orgPipelines = append(orgPipelines, p)
		}
	}
	return orgPipelines, nil
}

// TriggerPipeline triggers a pipeline by name or trigger event
func (m *Manager) TriggerPipeline(ctx context.Context, trigger string, params map[string]string) error {
	pipelines, err := m.pipelineStore.List(ctx, "")
	if err != nil {
		return err
	}

	for _, p := range pipelines {
		if p.Trigger == trigger && p.Status == types.StatusActive {
			if err := m.ExecutePipeline(ctx, p, params); err != nil {
				return fmt.Errorf("pipeline %s failed: %w", p.ID, err)
			}
		}
	}
	return nil
}

// ExecutePipeline executes all steps in a pipeline
func (m *Manager) ExecutePipeline(ctx context.Context, p *types.AutomationPipeline, globalParams map[string]string) error {
	for _, step := range p.Steps {
		// Prepare parameters with interpolation
		interpolatedParams := make(map[string]string)
		for k, v := range step.Parameters {
			val := v
			// First replace parameters {{key}}
			for pk, pv := range globalParams {
				val = strings.ReplaceAll(val, "{{"+pk+"}}", pv)
			}

			// Then handle functions {{func(arg1, arg2)}}
			val = m.interpolateFunctions(val, globalParams)

			interpolatedParams[k] = val
		}

		handler, ok := m.getHandler(step.Type)
		if !ok {
			return fmt.Errorf("unsupported step type: %s", step.Type)
		}

		if err := handler(ctx, interpolatedParams); err != nil {
			return fmt.Errorf("step %s failed: %w", step.Name, err)
		}
	}
	return nil
}

var funcRegex = regexp.MustCompile(`\{\{(\w+)\((.*?)\)\}\}`)

func (m *Manager) interpolateFunctions(input string, params map[string]string) string {
	return funcRegex.ReplaceAllStringFunc(input, func(match string) string {
		sub := funcRegex.FindStringSubmatch(match)
		if len(sub) < 3 {
			return match
		}
		funcName := sub[1]
		argsStr := sub[2]

		var args []string
		if argsStr != "" {
			parts := strings.Split(argsStr, ",")
			for _, p := range parts {
				argName := strings.TrimSpace(p)
				// Resolve argName if it exists in params, otherwise use as literal
				if val, ok := params[argName]; ok {
					args = append(args, val)
				} else {
					args = append(args, argName)
				}
			}
		}

		m.mu.RLock()
		handler, ok := m.functions[funcName]
		m.mu.RUnlock()

		if !ok {
			return match
		}

		val, err := handler(args...)
		if err != nil {
			return match
		}
		return val
	})
}

func (m *Manager) getHandler(stepType string) (StepHandler, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	handler, ok := m.handlers[stepType]
	return handler, ok
}
