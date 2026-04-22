package velocity

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// ReplicationTaskType defines the type of replication operation
type ReplicationTaskType int

const (
	ReplicationPut ReplicationTaskType = iota
	ReplicationDelete
)

// ReplicationConfig holds replication configuration
type ReplicationConfig struct {
	ReplicaCount     int
	WriteQuorum      int
	ReadQuorum       int
	AsyncReplication bool
	MaxRetries       int
	RetryInterval    time.Duration
}

// DefaultReplicationConfig returns sensible defaults
func DefaultReplicationConfig() ReplicationConfig {
	return ReplicationConfig{
		ReplicaCount:     3,
		WriteQuorum:      2,
		ReadQuorum:       1,
		AsyncReplication: true,
		MaxRetries:       3,
		RetryInterval:    5 * time.Second,
	}
}

// ReplicationTask represents a replication operation to be performed
type ReplicationTask struct {
	TaskID     string              `json:"task_id"`
	Type       ReplicationTaskType `json:"type"`
	Bucket     string              `json:"bucket"`
	Key        string              `json:"key"`
	Data       []byte              `json:"data,omitempty"`
	Metadata   *ObjectMetadata     `json:"metadata,omitempty"`
	TargetNode string              `json:"target_node"`
	Retries    int                 `json:"retries"`
	CreatedAt  time.Time           `json:"created_at"`
}

// ReplicationStats tracks replication statistics
type ReplicationStats struct {
	Replicated       int64
	Failed           int64
	Pending          int64
	BytesTransferred int64
	mu               sync.Mutex
}

// ReplicationManager manages object replication across cluster nodes
type ReplicationManager struct {
	config  ReplicationConfig
	cluster *ClusterManager
	db      *DB
	queue   chan ReplicationTask
	running atomic.Bool
	stopCh  chan struct{}
	stats   ReplicationStats
}

// NewReplicationManager creates a new replication manager
func NewReplicationManager(db *DB, cluster *ClusterManager, config ReplicationConfig) *ReplicationManager {
	return &ReplicationManager{
		config:  config,
		cluster: cluster,
		db:      db,
		queue:   make(chan ReplicationTask, 10000),
		stopCh:  make(chan struct{}),
	}
}

// Start begins the replication queue processor
func (rm *ReplicationManager) Start(ctx context.Context) error {
	if !rm.running.CompareAndSwap(false, true) {
		return fmt.Errorf("replication already running")
	}

	// Start multiple workers
	workerCount := 4
	for i := 0; i < workerCount; i++ {
		go rm.processQueue(ctx)
	}

	return nil
}

// Stop stops the replication manager
func (rm *ReplicationManager) Stop() {
	if rm.running.Load() {
		close(rm.stopCh)
		rm.running.Store(false)
	}
}

// ReplicateObject replicates an object to peer nodes
func (rm *ReplicationManager) ReplicateObject(bucket, key string, data []byte, meta *ObjectMetadata) error {
	if rm.cluster == nil {
		return nil // Single node, no replication needed
	}

	// Get target nodes from consistent hash ring
	path := bucket + "/" + key
	targetNodes := rm.cluster.ring.GetNodes(path, rm.config.ReplicaCount)

	localID := rm.cluster.config.NodeID

	for _, nodeID := range targetNodes {
		if nodeID == localID {
			continue // Skip local node
		}

		task := ReplicationTask{
			TaskID:     generateObjectID(),
			Type:       ReplicationPut,
			Bucket:     bucket,
			Key:        key,
			Data:       data,
			Metadata:   meta,
			TargetNode: nodeID,
			CreatedAt:  time.Now().UTC(),
		}

		if rm.config.AsyncReplication {
			select {
			case rm.queue <- task:
				atomic.AddInt64(&rm.stats.Pending, 1)
			default:
				atomic.AddInt64(&rm.stats.Failed, 1)
				return fmt.Errorf("replication queue full")
			}
		} else {
			if err := rm.sendToNode(task); err != nil {
				return err
			}
		}
	}

	return nil
}

// ReplicateDelete replicates a delete to peer nodes
func (rm *ReplicationManager) ReplicateDelete(bucket, key string) error {
	if rm.cluster == nil {
		return nil
	}

	path := bucket + "/" + key
	targetNodes := rm.cluster.ring.GetNodes(path, rm.config.ReplicaCount)
	localID := rm.cluster.config.NodeID

	for _, nodeID := range targetNodes {
		if nodeID == localID {
			continue
		}

		task := ReplicationTask{
			TaskID:     generateObjectID(),
			Type:       ReplicationDelete,
			Bucket:     bucket,
			Key:        key,
			TargetNode: nodeID,
			CreatedAt:  time.Now().UTC(),
		}

		select {
		case rm.queue <- task:
			atomic.AddInt64(&rm.stats.Pending, 1)
		default:
			atomic.AddInt64(&rm.stats.Failed, 1)
		}
	}

	return nil
}

// ReceiveReplication handles an incoming replication from a peer
func (rm *ReplicationManager) ReceiveReplication(task ReplicationTask) error {
	switch task.Type {
	case ReplicationPut:
		if task.Data == nil || task.Metadata == nil {
			return fmt.Errorf("missing data or metadata")
		}
		path := task.Bucket + "/" + task.Key
		_, err := rm.db.StoreObject(path, task.Metadata.ContentType, "replication", task.Data, &ObjectOptions{
			Version:         task.Metadata.Version,
			Tags:            task.Metadata.Tags,
			CustomMetadata:  task.Metadata.CustomMetadata,
			Encrypt:         task.Metadata.Encrypted,
			StorageClass:    task.Metadata.StorageClass,
			SystemOperation: true,
		})
		return err

	case ReplicationDelete:
		path := task.Bucket + "/" + task.Key
		return rm.db.DeleteObjectInternal(path, "replication")

	default:
		return fmt.Errorf("unknown replication type: %d", task.Type)
	}
}

// GetStats returns replication statistics
func (rm *ReplicationManager) GetStats() ReplicationStats {
	return ReplicationStats{
		Replicated:       atomic.LoadInt64(&rm.stats.Replicated),
		Failed:           atomic.LoadInt64(&rm.stats.Failed),
		Pending:          atomic.LoadInt64(&rm.stats.Pending),
		BytesTransferred: atomic.LoadInt64(&rm.stats.BytesTransferred),
	}
}

func (rm *ReplicationManager) processQueue(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-rm.stopCh:
			return
		case task := <-rm.queue:
			atomic.AddInt64(&rm.stats.Pending, -1)
			if err := rm.sendToNode(task); err != nil {
				if task.Retries < rm.config.MaxRetries {
					task.Retries++
					time.AfterFunc(rm.config.RetryInterval, func() {
						select {
						case rm.queue <- task:
							atomic.AddInt64(&rm.stats.Pending, 1)
						default:
						}
					})
				} else {
					atomic.AddInt64(&rm.stats.Failed, 1)
				}
			} else {
				atomic.AddInt64(&rm.stats.Replicated, 1)
				if task.Data != nil {
					atomic.AddInt64(&rm.stats.BytesTransferred, int64(len(task.Data)))
				}
			}
		}
	}
}

func (rm *ReplicationManager) sendToNode(task ReplicationTask) error {
	if rm.cluster == nil || rm.cluster.transport == nil {
		return fmt.Errorf("no transport available")
	}

	addr, err := rm.cluster.GetNodeAddress(task.TargetNode)
	if err != nil {
		return err
	}

	var msgType MessageType
	switch task.Type {
	case ReplicationPut:
		msgType = MsgReplicateObj
	case ReplicationDelete:
		msgType = MsgReplicateDel
	}

	payload, err := json.Marshal(task)
	if err != nil {
		return err
	}

	msg := &WireMessage{
		Type:      msgType,
		NodeID:    rm.cluster.config.NodeID,
		Timestamp: time.Now().UnixNano(),
		Payload:   payload,
	}

	resp, err := rm.cluster.transport.Send(addr, msg)
	if err != nil {
		return err
	}

	if resp != nil && resp.Type == MsgReplicateAck {
		return nil
	}

	return nil
}
