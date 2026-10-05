//go:build race

package kv

// raceEnabledKV mirrors the storage-lsm guard: the race runtime's own
// allocations are counted by testing.AllocsPerRun, so exact-zero allocation
// assertions are not meaningful in a race build.
const raceEnabledKV = true
