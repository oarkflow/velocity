# Load/Soak and SLO Plan

## SLO Targets (Initial)
- API availability: 99.9%
- Secret read p95 latency: < 100 ms
- Secret write p95 latency: < 200 ms
- Alert processing delay p95: < 30 s

## Test Profiles
- Load test: ramp to target RPS over 30 min.
- Soak test: sustained traffic for 24h.
- Spike test: 3x traffic bursts for 10 min windows.

## Pass Criteria
- Error rate under defined SLO budget.
- No data loss or audit chain corruption.
- No memory/resource leak trend beyond threshold.

## Evidence
- [ ] test report artifact
- [ ] dashboard snapshots
- [ ] incident notes (if any)

