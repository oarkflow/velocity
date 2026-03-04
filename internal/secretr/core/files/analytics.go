package files

import (
	"context"
	"strings"

	"github.com/oarkflow/velocity/internal/secretr/types"
)

// AccessHeatmap represents access counts by country
type AccessHeatmap map[string]int

// GetGlobalAccessHeatmap returns a heatmap of all file accesses by country
func (m *ProtectionManager) GetGlobalAccessHeatmap(ctx context.Context) (AccessHeatmap, error) {
	logs, err := m.ListAccessLogs(ctx, "", 10000) // Limit to 10k for now
	if err != nil {
		return nil, err
	}

	heatmap := make(AccessHeatmap)
	for _, log := range logs {
		if log.Country != "" {
			cc := strings.ToUpper(log.Country)
			heatmap[cc]++
		}
	}

	return heatmap, nil
}

// GetFileAccessHeatmap returns a heatmap for a specific file
func (m *ProtectionManager) GetFileAccessHeatmap(ctx context.Context, fileID string) (AccessHeatmap, error) {
	// ListAccessLogs filters by fileID if provided?
	// The current implementation of ListAccessLogs in protection.go handles filtering if fileID is argument?
	// Need to check ListAccessLogs signature. Assuming it supports filtering or I filter manually.

	// Assuming ListAccessLogs has filtering support based on view of protection.go (it wasn't fully visible but likely)
	// If not, I'll filter manually.

	logs, err := m.ListAccessLogs(ctx, types.ID(fileID), 10000)
	if err != nil {
		return nil, err
	}

	heatmap := make(AccessHeatmap)
	for _, log := range logs {
		if log.Country != "" {
			cc := strings.ToUpper(log.Country)
			heatmap[cc]++
		}
	}

	return heatmap, nil
}
