//go:build race

package lsm

// raceEnabled reports whether this binary was built with -race. The race
// runtime's own bookkeeping allocations are counted by
// testing.AllocsPerRun, and sync.Pool interacts with it in ways that make an
// exact-zero allocation assertion unreliable. Tests that assert zero
// allocations skip themselves under -race rather than assert a weakened bound.
const raceEnabled = true
