package secret

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/oarkflow/velocity/v2/api"
)

// SetStaged stages a Set as part of a cross-plugin api.CrossTx (see
// plugins/transaction) instead of applying it immediately: both the new
// version record and the updated "latest" pointer are sealed/built
// exactly as Set would, then queued via tx.Stage against this plugin's
// own StorageBackend instance. The write only actually happens when the
// caller later calls tx.Commit — so a version number this method computes
// is provisional until Commit succeeds; if the caller never commits (or
// Commit fails), no version was actually consumed.
//
// This is purely additive: Set/Get/Rotate/etc are completely unchanged.
func (p *Plugin) SetStaged(ctx context.Context, tx api.CrossTx, name string, value []byte) (version int, err error) {
	if name == "" {
		return 0, fmt.Errorf("%s: secret name is required", pluginName)
	}
	p.mu.Lock()
	defer p.mu.Unlock()

	latest, err := p.latestVersion(ctx, name)
	if err != nil {
		latest = 0 // not found yet — this Set creates version 1
	}
	version = latest + 1

	sealed, err := p.crypto.Encrypt(ctx, value, aad(name, version))
	if err != nil {
		return 0, fmt.Errorf("%s: sealing %q v%d: %w", pluginName, name, version, err)
	}
	sum := sha256.Sum256(value)
	rec := record{Version: version, Sealed: sealed, Checksum: hex.EncodeToString(sum[:]), CreatedAt: time.Now().UTC()}
	data, err := json.Marshal(rec)
	if err != nil {
		return 0, err
	}

	if err := tx.Stage(p.storage, []api.BatchOp{
		{Entry: api.Entry{Key: versionKey(name, version), Value: data}},
		{Entry: api.Entry{Key: latestKey(name), Value: []byte(strconv.Itoa(version))}},
	}); err != nil {
		return 0, err
	}
	return version, nil
}
