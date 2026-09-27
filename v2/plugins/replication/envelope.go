package replication

// frameEnvelope is the single top-level message shape sent over
// Transport. api.ReplicationTransport.OnReceive only allows one handler
// to be registered at a time, but this plugin has two independent
// producers of outbound traffic (Membership's control protocol and
// fanout's replicated mutation events) — this envelope's Kind field lets
// Plugin's single dispatcher route an inbound frame to whichever of the
// two actually understands it, without either needing to know about the
// other.
type frameEnvelope struct {
	Kind    string      `json:"kind"` // "control" or "replica"
	Control *controlMsg `json:"control,omitempty"`
	Replica *replicaMsg `json:"replica,omitempty"`
}
