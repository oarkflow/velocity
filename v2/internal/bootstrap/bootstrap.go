// Package bootstrap constructs the shared list of every plugin Velocity v2
// knows how to build, so cmd/velocityd (the server daemon) and cmd/velocity
// (the embedded CLI) boot the identical kernel/plugin set against
// whichever manifest they're given, without duplicating the wiring in two
// places.
package bootstrap

import (
	"github.com/oarkflow/velocity/v2/api"
	"github.com/oarkflow/velocity/v2/kernel"
	authjwt "github.com/oarkflow/velocity/v2/plugins/auth-jwt"
	authldap "github.com/oarkflow/velocity/v2/plugins/auth-ldap"
	authmfa "github.com/oarkflow/velocity/v2/plugins/auth-mfa"
	authoidc "github.com/oarkflow/velocity/v2/plugins/auth-oidc"
	authsts "github.com/oarkflow/velocity/v2/plugins/auth-sts"
	"github.com/oarkflow/velocity/v2/plugins/backup"
	"github.com/oarkflow/velocity/v2/plugins/compliance"
	"github.com/oarkflow/velocity/v2/plugins/configio"
	cryptofips "github.com/oarkflow/velocity/v2/plugins/crypto-fips"
	cryptoxchacha "github.com/oarkflow/velocity/v2/plugins/crypto-xchacha"
	"github.com/oarkflow/velocity/v2/plugins/document"
	"github.com/oarkflow/velocity/v2/plugins/envelope"
	"github.com/oarkflow/velocity/v2/plugins/erasure"
	"github.com/oarkflow/velocity/v2/plugins/extractor"
	"github.com/oarkflow/velocity/v2/plugins/iam"
	"github.com/oarkflow/velocity/v2/plugins/kv"
	"github.com/oarkflow/velocity/v2/plugins/lock"
	"github.com/oarkflow/velocity/v2/plugins/metrics"
	"github.com/oarkflow/velocity/v2/plugins/notifications"
	"github.com/oarkflow/velocity/v2/plugins/object"
	"github.com/oarkflow/velocity/v2/plugins/redisdata"
	"github.com/oarkflow/velocity/v2/plugins/replication"
	"github.com/oarkflow/velocity/v2/plugins/resp"
	"github.com/oarkflow/velocity/v2/plugins/sandbox"
	"github.com/oarkflow/velocity/v2/plugins/search"
	"github.com/oarkflow/velocity/v2/plugins/secret"
	"github.com/oarkflow/velocity/v2/plugins/sql"
	storagelsm "github.com/oarkflow/velocity/v2/plugins/storage-lsm"
	storagemem "github.com/oarkflow/velocity/v2/plugins/storage-mem"
	"github.com/oarkflow/velocity/v2/plugins/web"
)

// AllPlugins constructs every plugin the binary knows how to build. Only
// plugins actually listed with "enabled": true in the manifest are booted
// (see kernel.Manifest.Enabled and Kernel.Boot) — constructing an instance
// here does not start it.
//
// Dependency plugin names passed to constructors (e.g. "storage-lsm" for
// the storageDep parameter) select which concrete backend a consumer
// plugin's Dependencies() waits on for boot ordering; every consumer still
// looks its dependency up by the FIXED SERVICE NAME ("storage", "kv", ...)
// at runtime, not by this plugin name — see docs/ARCHITECTURE.md section
// (c) for why those are two different namespaces.
//
// storageDep/cryptoDep are resolved from the manifest itself (see
// resolveDep below) rather than hardcoded, so a manifest that enables
// storage-mem instead of storage-lsm (e.g. config/velocityd.minimal.json)
// actually works end to end — swapping which backend plugin is enabled in
// the manifest is the whole story for changing it, matching what
// docs/ARCHITECTURE.md promises. A manifest enabling neither, or both,
// falls back to storage-lsm/crypto-xchacha; Boot will surface a clear
// dependency error at that point if the fallback isn't enabled either.
func AllPlugins(manifest kernel.Manifest) []api.Plugin {
	enabled := manifest.Enabled()
	storageDep := resolveDep(enabled, "storage-lsm", "storage-mem", "storage-lsm")
	cryptoDep := resolveDep(enabled, "crypto-xchacha", "crypto-fips", "crypto-xchacha")

	// auth-sts's NewWithDeps treats a non-empty dep name as a HARD
	// Dependencies() requirement (Boot fails if that named plugin isn't
	// also enabled) — so these must only be passed when the corresponding
	// plugin is actually enabled, or enabling auth-sts alone would break
	// boot. Empty string keeps federation for that provider simply
	// unavailable at runtime (a clear "not configured" error), not a boot
	// failure — see plugins/auth-sts's own doc comment.
	stsOIDCDep := optionalDep(enabled, "auth-oidc")
	stsLDAPDep := optionalDep(enabled, "auth-ldap")

	return []api.Plugin{
		storagelsm.New(),
		storagemem.New(),

		cryptoxchacha.New(),
		cryptofips.New(),

		kv.New(storageDep),
		object.New(storageDep),

		authjwt.New(),
		authoidc.New(),

		authldap.New(),
		authsts.NewWithDeps(stsOIDCDep, stsLDAPDep),
		authmfa.NewPlugin(storageDep),

		compliance.NewPlugin(storageDep),

		metrics.NewPlugin(),

		secret.NewPlugin(storageDep, cryptoDep),

		// nodeID/bindAddr/seed are left empty here and are expected to be
		// supplied via the "replication" section of the manifest instead
		// (config takes precedence over these constructor args — see
		// plugins/replication/plugin.go's Init) — defaults to a random
		// node ID bound to 127.0.0.1:0 (an OS-assigned port) if unset.
		replication.NewPlugin("", "", ""),

		search.NewPlugin("kv"),
		sql.NewPlugin("kv"),
		web.NewPlugin("kv", "object", "auth.jwt"),

		backup.NewPlugin(storageDep),
		envelope.NewPlugin(storageDep, cryptoDep),
		iam.NewPlugin(storageDep),
		// Disabled by default in the example manifests — opt-in, since it
		// adds background scan overhead most single-node/dev deployments
		// don't need. See plugins/erasure's doc comment for how an
		// object-storage integration would opt in for large-blob durability.
		erasure.NewPlugin(storageDep),
		notifications.NewPlugin(storageDep),
		lock.NewPlugin("kv"),
		extractor.NewPlugin(),

		redisdata.NewPlugin(storageDep),
		// Listens on :6380 by default (never collides with a real Redis
		// instance's default :6379) — a real RESP2 wire-protocol server so
		// existing Redis clients (redis-cli, go-redis, etc.) can talk to
		// Velocity directly. See v2/benchmarks/comparison/redis/RESULTS.md
		// for real, repeated head-to-head numbers against actual Redis.
		resp.NewPlugin("kv"),

		document.NewPlugin(storageDep),
		configio.NewPlugin("kv"),
		// SandboxService refuses every Run call until "allowed_commands" is
		// explicitly configured — there is no wildcard default-allow. Any
		// manifest enabling "sandbox" MUST set allowed_commands, or the
		// plugin boots successfully but is permanently inert (a safe
		// failure mode, not a bug — see plugins/sandbox's own doc comment).
		sandbox.NewPlugin(),
	}
}

// resolveDep picks preferred if it's enabled; otherwise alternate if IT's
// enabled; otherwise falls back to preferred (letting Boot's own "depends
// on X, which is not enabled" error explain the problem clearly if neither
// ends up enabled).
func resolveDep(enabled map[string]bool, preferred, alternate, fallback string) string {
	if enabled[preferred] {
		return preferred
	}
	if enabled[alternate] {
		return alternate
	}
	return fallback
}

// optionalDep returns name if it's enabled in the manifest, "" otherwise —
// for constructors that treat a non-empty dependency name as a hard boot
// requirement (see the auth-sts federation comment above).
func optionalDep(enabled map[string]bool, name string) string {
	if enabled[name] {
		return name
	}
	return ""
}
