package velocity

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// DecommissionState represents the current phase of node decommissioning.
type DecommissionState int

const (
	DecommissionPending    DecommissionState = iota // Plan created, not yet started
	DecommissionPlanning                            // Building migration plan
	DecommissionMigrating                           // Actively transferring objects
	DecommissionDraining                            // Final pass: verifying nothing remains
	DecommissionCompleted                           // All data migrated, node safe to remove
	DecommissionFailed                              // Unrecoverable error
	DecommissionCancelled                           // Cancelled by operator
)

func (s DecommissionState) String() string {
	switch s {
	case DecommissionPending:
		return "pending"
	case DecommissionPlanning:
		return "planning"
	case DecommissionMigrating:
		return "migrating"
	case DecommissionDraining:
		return "draining"
	case DecommissionCompleted:
		return "completed"
	case DecommissionFailed:
		return "failed"
	case DecommissionCancelled:
		return "cancelled"
	default:
		return "unknown"
	}
}

// DecommissionStatus provides a snapshot of the decommissioning progress.
type DecommissionStatus struct {
	NodeID           string            `json:"node_id"`
	State            DecommissionState `json:"state"`
	StateName        string            `json:"state_name"`
	TotalObjects     int64             `json:"total_objects"`
	MigratedObjects  int64             `json:"migrated_objects"`
	FailedObjects    int64             `json:"failed_objects"`
	TotalBytes       int64             `json:"total_bytes"`
	TransferredBytes int64             `json:"transferred_bytes"`
	StartedAt        time.Time         `json:"started_at"`
	UpdatedAt        time.Time         `json:"updated_at"`
	CompletedAt      *time.Time        `json:"completed_at,omitempty"`
	Errors           []string          `json:"errors,omitempty"`
	CurrentObject    string            `json:"current_object,omitempty"`
}

// DecommissionPlanEntry describes a single object migration: what to move and where.
type DecommissionPlanEntry struct {
	ObjectPath string `json:"object_path"`
	ObjectSize int64  `json:"object_size"`
	TargetNode string `json:"target_node"`
}

// DecommissionPlan is the full migration manifest for a node being removed.
type DecommissionPlan struct {
	NodeID    string                  `json:"node_id"`
	Entries   []DecommissionPlanEntry `json:"entries"`
	CreatedAt time.Time               `json:"created_at"`
}

// decommissionTransferPayload is serialized into WireMessage.Payload when
// pushing an object to its new owner.
type decommissionTransferPayload struct {
	ObjectPath  string `json:"object_path"`
	ContentType string `json:"content_type"`
	Data        []byte `json:"data"`
	MetaJSON    []byte `json:"meta_json"`
}

// decommissionTransferAck is the response from the receiving node.
type decommissionTransferAck struct {
	Success    bool   `json:"success"`
	ObjectPath string `json:"object_path"`
	Error      string `json:"error,omitempty"`
}

// DecommissionManager coordinates the safe removal of a node from the cluster
// by migrating all its data to the remaining nodes according to the consistent
// hash ring.
type DecommissionManager struct {
	cluster *ClusterManager

	mu     sync.Mutex
	status *DecommissionStatus // nil when idle
	cancel context.CancelFunc // cancel the active decommission

	maxRetries    int
	batchPause    time.Duration // small pause between objects to avoid saturation
	maxConcurrent int           // parallel transfers
}

// NewDecommissionManager creates a DecommissionManager tied to the given cluster.
func NewDecommissionManager(cluster *ClusterManager) *DecommissionManager {
	dm := &DecommissionManager{
		cluster:       cluster,
		maxRetries:    3,
		batchPause:    10 * time.Millisecond,
		maxConcurrent: 4,
	}

	// Register a handler so other nodes can receive migrated objects.
	if cluster.transport != nil {
		cluster.transport.RegisterHandler(MsgDataTransfer, dm.handleIncomingTransfer)
	}

	return dm
}

// Status returns the current decommission status, or nil if idle.
func (dm *DecommissionManager) Status() *DecommissionStatus {
	dm.mu.Lock()
	defer dm.mu.Unlock()
	if dm.status == nil {
		return nil
	}
	cp := *dm.status
	cp.StateName = cp.State.String()
	return &cp
}

// Cancel cancels a running decommission. Objects already migrated stay on their
// new nodes; the source node is returned to Active state.
func (dm *DecommissionManager) Cancel() error {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	if dm.status == nil {
		return fmt.Errorf("no decommission in progress")
	}
	if dm.status.State == DecommissionCompleted || dm.status.State == DecommissionCancelled {
		return fmt.Errorf("decommission already finished (state: %s)", dm.status.State)
	}

	if dm.cancel != nil {
		dm.cancel()
	}
	return nil
}

// DecommissionNode is the main entry point. It blocks until migration is
// complete, cancelled, or fails. Call from a goroutine if you need it async.
func (dm *DecommissionManager) DecommissionNode(ctx context.Context, nodeID string) error {
	// ---- pre-flight checks -----------------------------------------------
	dm.mu.Lock()
	if dm.status != nil && dm.status.State == DecommissionMigrating {
		dm.mu.Unlock()
		return fmt.Errorf("decommission already in progress for node %s", dm.status.NodeID)
	}
	dm.status = &DecommissionStatus{
		NodeID:    nodeID,
		State:     DecommissionPending,
		StartedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
	ctx, dm.cancel = context.WithCancel(ctx)
	dm.mu.Unlock()

	// ---- validate node exists and is part of the cluster -----------------
	node := dm.lookupNode(nodeID)
	if node == nil {
		return dm.fail(fmt.Errorf("node %s not found in cluster", nodeID))
	}

	// Mark the node as leaving so the rest of the cluster stops routing new
	// writes to it.
	dm.cluster.mu.Lock()
	node.State = NodeStateLeaving
	dm.cluster.mu.Unlock()

	// ---- planning phase --------------------------------------------------
	dm.setState(DecommissionPlanning)

	plan, err := dm.buildPlan(nodeID)
	if err != nil {
		return dm.fail(fmt.Errorf("planning failed: %w", err))
	}

	dm.mu.Lock()
	dm.status.TotalObjects = int64(len(plan.Entries))
	for _, e := range plan.Entries {
		dm.status.TotalBytes += e.ObjectSize
	}
	dm.mu.Unlock()

	// ---- migration phase -------------------------------------------------
	dm.setState(DecommissionMigrating)

	if err := dm.executePlan(ctx, plan); err != nil {
		// Context cancellation is not a failure; it's an explicit cancel.
		if ctx.Err() != nil {
			dm.setState(DecommissionCancelled)
			dm.restoreNode(nodeID)
			return fmt.Errorf("decommission cancelled")
		}
		return dm.fail(err)
	}

	// ---- drain phase: quick verification pass ----------------------------
	dm.setState(DecommissionDraining)

	if err := dm.verifyDrained(ctx, nodeID); err != nil {
		if ctx.Err() != nil {
			dm.setState(DecommissionCancelled)
			dm.restoreNode(nodeID)
			return fmt.Errorf("decommission cancelled during drain")
		}
		return dm.fail(err)
	}

	// ---- complete: remove node from the hash ring ------------------------
	dm.cluster.ring.RemoveNode(nodeID)

	dm.cluster.mu.Lock()
	if n, ok := dm.cluster.nodes[nodeID]; ok {
		n.State = NodeStateDown
	}
	dm.cluster.mu.Unlock()

	now := time.Now().UTC()
	dm.mu.Lock()
	dm.status.State = DecommissionCompleted
	dm.status.CompletedAt = &now
	dm.status.UpdatedAt = now
	dm.mu.Unlock()

	return nil
}

// ---------------------------------------------------------------------------
// Plan construction
// ---------------------------------------------------------------------------

// buildPlan lists every object on the departing node and determines the new
// owner using the hash ring with the node removed.
func (dm *DecommissionManager) buildPlan(nodeID string) (*DecommissionPlan, error) {
	plan := &DecommissionPlan{
		NodeID:    nodeID,
		CreatedAt: time.Now().UTC(),
	}

	// We need a temporary ring without the departing node so we can figure
	// out where each object should land.
	tempRing := dm.cloneRingWithout(nodeID)
	if tempRing.NodeCount() == 0 {
		return nil, fmt.Errorf("no remaining nodes to accept data")
	}

	db := dm.cluster.db
	if db == nil {
		return nil, fmt.Errorf("local database not available")
	}

	// List all objects on this node. We page through the full list to avoid
	// loading everything into memory at once.
	var startAfter string
	for {
		objects, err := db.ListObjects(ObjectListOptions{
			Recursive:  true,
			MaxKeys:    500,
			StartAfter: startAfter,
		})
		if err != nil {
			return nil, fmt.Errorf("listing objects: %w", err)
		}
		if len(objects) == 0 {
			break
		}

		for _, obj := range objects {
			// Only include objects that currently hash to the departing node.
			currentOwner := dm.cluster.ring.GetNode(obj.Path)
			if currentOwner != nodeID {
				continue
			}

			newOwner := tempRing.GetNode(obj.Path)
			if newOwner == "" {
				continue
			}

			plan.Entries = append(plan.Entries, DecommissionPlanEntry{
				ObjectPath: obj.Path,
				ObjectSize: obj.Size,
				TargetNode: newOwner,
			})

			startAfter = obj.Path
		}

		// If we got fewer than requested, we've reached the end.
		if len(objects) < 500 {
			break
		}
	}

	return plan, nil
}

// cloneRingWithout creates a new ConsistentHashRing containing every active
// node except the one being decommissioned.
func (dm *DecommissionManager) cloneRingWithout(excludeNodeID string) *ConsistentHashRing {
	ring := NewConsistentHashRing(256)
	dm.cluster.mu.RLock()
	defer dm.cluster.mu.RUnlock()

	for id, node := range dm.cluster.nodes {
		if id == excludeNodeID {
			continue
		}
		if node.State == NodeStateActive || node.State == NodeStateJoining {
			ring.AddNode(id)
		}
	}
	return ring
}

// ---------------------------------------------------------------------------
// Plan execution
// ---------------------------------------------------------------------------

// executePlan migrates objects with bounded concurrency.
func (dm *DecommissionManager) executePlan(ctx context.Context, plan *DecommissionPlan) error {
	sem := make(chan struct{}, dm.maxConcurrent)

	var wg sync.WaitGroup
	var firstErr atomic.Value // capture the first fatal error

	for i := range plan.Entries {
		if ctx.Err() != nil {
			break
		}

		entry := &plan.Entries[i]

		sem <- struct{}{} // acquire
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-sem }() // release

			if err := dm.migrateObject(ctx, entry); err != nil {
				dm.recordError(fmt.Sprintf("migrate %s: %v", entry.ObjectPath, err))
				firstErr.CompareAndSwap(nil, err)
			}
		}()

		// A small pause between dispatches prevents a thundering herd when the
		// plan contains thousands of objects.
		if dm.batchPause > 0 {
			select {
			case <-ctx.Done():
			case <-time.After(dm.batchPause):
			}
		}
	}

	wg.Wait()

	// If too many errors accumulated, treat as failure.
	dm.mu.Lock()
	failed := dm.status.FailedObjects
	total := dm.status.TotalObjects
	dm.mu.Unlock()

	if total > 0 && failed > 0 && float64(failed)/float64(total) > 0.1 {
		return fmt.Errorf("too many migration failures: %d/%d objects failed", failed, total)
	}

	return nil
}

// migrateObject reads an object from the local DB, sends it to the target
// node via the wire protocol, and — on success — deletes the local copy.
func (dm *DecommissionManager) migrateObject(ctx context.Context, entry *DecommissionPlanEntry) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}

	dm.mu.Lock()
	dm.status.CurrentObject = entry.ObjectPath
	dm.status.UpdatedAt = time.Now().UTC()
	dm.mu.Unlock()

	db := dm.cluster.db

	// Read the object data and metadata from the local store.
	// Use the internal getter to bypass compliance checks — this is a system
	// migration, not a user request.
	data, meta, err := db.GetObjectInternal(entry.ObjectPath, "system")
	if err != nil {
		// Object may have been deleted between plan and execution — not fatal.
		dm.mu.Lock()
		dm.status.FailedObjects++
		dm.mu.Unlock()
		return fmt.Errorf("read object %s: %w", entry.ObjectPath, err)
	}

	metaJSON, err := json.Marshal(meta)
	if err != nil {
		dm.mu.Lock()
		dm.status.FailedObjects++
		dm.mu.Unlock()
		return fmt.Errorf("marshal metadata for %s: %w", entry.ObjectPath, err)
	}

	// Build the transfer payload.
	payload := decommissionTransferPayload{
		ObjectPath:  entry.ObjectPath,
		ContentType: meta.ContentType,
		Data:        data,
		MetaJSON:    metaJSON,
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		dm.mu.Lock()
		dm.status.FailedObjects++
		dm.mu.Unlock()
		return fmt.Errorf("marshal transfer payload: %w", err)
	}

	msg := &WireMessage{
		Type:      MsgDataTransfer,
		NodeID:    dm.cluster.config.NodeID,
		Timestamp: time.Now().UnixNano(),
		Payload:   payloadBytes,
	}

	// Send with retries.
	var sendErr error
	for attempt := 0; attempt < dm.maxRetries; attempt++ {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		targetAddr, err := dm.cluster.GetNodeAddress(entry.TargetNode)
		if err != nil {
			sendErr = fmt.Errorf("resolve target %s: %w", entry.TargetNode, err)
			continue
		}

		resp, err := dm.cluster.transport.Send(targetAddr, msg)
		if err != nil {
			sendErr = fmt.Errorf("send to %s: %w", targetAddr, err)
			time.Sleep(time.Duration(attempt+1) * 500 * time.Millisecond)
			continue
		}

		// Parse the ack.
		var ack decommissionTransferAck
		if resp != nil && resp.Payload != nil {
			if err := json.Unmarshal(resp.Payload, &ack); err == nil && ack.Success {
				sendErr = nil
				break
			} else if err == nil && !ack.Success {
				sendErr = fmt.Errorf("target rejected %s: %s", entry.ObjectPath, ack.Error)
			}
		} else {
			// No explicit ack payload — treat a non-nil response as success
			// (the transport always replies with at least an empty WireMessage).
			sendErr = nil
			break
		}
		time.Sleep(time.Duration(attempt+1) * 500 * time.Millisecond)
	}

	if sendErr != nil {
		dm.mu.Lock()
		dm.status.FailedObjects++
		dm.mu.Unlock()
		return sendErr
	}

	// Object landed safely — clean up the local copy.
	_ = db.DeleteObjectInternal(entry.ObjectPath, "system")

	dm.mu.Lock()
	dm.status.MigratedObjects++
	dm.status.TransferredBytes += int64(len(data))
	dm.status.UpdatedAt = time.Now().UTC()
	dm.status.CurrentObject = ""
	dm.mu.Unlock()

	return nil
}

// ---------------------------------------------------------------------------
// Drain / verification
// ---------------------------------------------------------------------------

// verifyDrained does a second scan to ensure no objects still hash to the
// departing node. Anything found is migrated in a final pass.
func (dm *DecommissionManager) verifyDrained(ctx context.Context, nodeID string) error {
	tempRing := dm.cloneRingWithout(nodeID)
	db := dm.cluster.db
	if db == nil {
		return nil
	}

	var startAfter string
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		objects, err := db.ListObjects(ObjectListOptions{
			Recursive:  true,
			MaxKeys:    500,
			StartAfter: startAfter,
		})
		if err != nil {
			return fmt.Errorf("drain scan: %w", err)
		}
		if len(objects) == 0 {
			break
		}

		for _, obj := range objects {
			currentOwner := dm.cluster.ring.GetNode(obj.Path)
			if currentOwner != nodeID {
				startAfter = obj.Path
				continue
			}

			newOwner := tempRing.GetNode(obj.Path)
			if newOwner == "" {
				startAfter = obj.Path
				continue
			}

			entry := &DecommissionPlanEntry{
				ObjectPath: obj.Path,
				ObjectSize: obj.Size,
				TargetNode: newOwner,
			}
			if err := dm.migrateObject(ctx, entry); err != nil {
				dm.recordError(fmt.Sprintf("drain migrate %s: %v", obj.Path, err))
			}

			startAfter = obj.Path
		}

		if len(objects) < 500 {
			break
		}
	}

	return nil
}

// ---------------------------------------------------------------------------
// Receiving side: handle incoming migrations
// ---------------------------------------------------------------------------

// handleIncomingTransfer is registered as the MsgDataTransfer handler on every
// node so it can accept objects being pushed from a decommissioning peer.
func (dm *DecommissionManager) handleIncomingTransfer(msg *WireMessage) *WireMessage {
	ack := decommissionTransferAck{}

	var payload decommissionTransferPayload
	if err := json.Unmarshal(msg.Payload, &payload); err != nil {
		ack.Error = fmt.Sprintf("unmarshal payload: %v", err)
		return dm.ackMessage(ack)
	}
	ack.ObjectPath = payload.ObjectPath

	db := dm.cluster.db
	if db == nil {
		ack.Error = "local database unavailable"
		return dm.ackMessage(ack)
	}

	// Store the object. We use SystemOperation to skip compliance hooks —
	// the source node already validated everything.
	_, err := db.StoreObject(
		payload.ObjectPath,
		payload.ContentType,
		"system",
		payload.Data,
		&ObjectOptions{SystemOperation: true},
	)
	if err != nil {
		ack.Error = fmt.Sprintf("store object: %v", err)
		return dm.ackMessage(ack)
	}

	ack.Success = true
	return dm.ackMessage(ack)
}

func (dm *DecommissionManager) ackMessage(ack decommissionTransferAck) *WireMessage {
	payload, _ := json.Marshal(ack)
	return &WireMessage{
		Type:      MsgDataTransfer,
		NodeID:    dm.cluster.config.NodeID,
		Timestamp: time.Now().UnixNano(),
		Payload:   payload,
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func (dm *DecommissionManager) lookupNode(nodeID string) *ClusterNode {
	dm.cluster.mu.RLock()
	defer dm.cluster.mu.RUnlock()
	return dm.cluster.nodes[nodeID]
}

func (dm *DecommissionManager) setState(s DecommissionState) {
	dm.mu.Lock()
	defer dm.mu.Unlock()
	if dm.status != nil {
		dm.status.State = s
		dm.status.UpdatedAt = time.Now().UTC()
	}
}

func (dm *DecommissionManager) fail(err error) error {
	dm.mu.Lock()
	defer dm.mu.Unlock()
	if dm.status != nil {
		dm.status.State = DecommissionFailed
		dm.status.UpdatedAt = time.Now().UTC()
		dm.status.Errors = append(dm.status.Errors, err.Error())
	}
	return err
}

func (dm *DecommissionManager) recordError(msg string) {
	dm.mu.Lock()
	defer dm.mu.Unlock()
	if dm.status != nil {
		// Cap the error list to keep memory bounded.
		if len(dm.status.Errors) < 100 {
			dm.status.Errors = append(dm.status.Errors, msg)
		}
	}
}

// restoreNode returns the node to Active state when a decommission is cancelled
// before it finishes.
func (dm *DecommissionManager) restoreNode(nodeID string) {
	dm.cluster.mu.Lock()
	defer dm.cluster.mu.Unlock()
	if n, ok := dm.cluster.nodes[nodeID]; ok {
		n.State = NodeStateActive
	}
}
