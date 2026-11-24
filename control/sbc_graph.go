// STATUS: V6.3.0 AP-6
package main

// V6.3.0 AP-6: SBC entity identity, decay mathematics and bounded graph
// maintenance. See sbc_fusion.go for the engine API.

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// sbcScoreScale is the rounding scale used for every exposed decayed score
// (six decimal places), so reports and envelope JSON are deterministic instead
// of float-noise driven.
const sbcScoreScale = 1e6

// sbcEntityKey derives the deterministic identity of one finding for the graph.
//
// Documented priority (first usable candidate wins):
//  1. attack-story metadata `sbc_entity` — the kernel identity (e.g. exe inode)
//     a sensor already established for the finding;
//  2. SHA-256 of the executable path (deleted-suffix stripped) — one binary
//     running several times corroborates itself;
//  3. PID + UID + start ticks — a process lifetime identity;
//  4. SHA-256 of the remote endpoint — network-only findings;
//  5. SHA-256 of the evidence root — findings rooted in a correlated chain;
//  6. a per-incident anonymous key (id, otherwise observation time, otherwise the
//     first rule id), so a finding with no stable identity never manufactures
//     corroboration it does not have.
//
// Every key is bounded; paths and endpoints appear only as digests.
func sbcEntityKey(incident XDRIncident) string {
	if declared, ok := giefPrimaryMetadata(incident, giefEntityMetadataKey); ok {
		if identity := boundedText(declared, sbcEntityTextBytes); identity != "" {
			return "meta:" + identity
		}
	}
	if executable := sbcNormalizeExecutable(incident.Executable); executable != "" {
		return "exe:" + sbcHashIdentity(executable)
	}
	if incident.PID > 0 {
		return fmt.Sprintf("proc:%d:%d:%d", incident.PID, incident.UID, incident.StartTicks)
	}
	if remote := boundedText(incident.Remote, sbcEntityTextBytes); remote != "" {
		return "net:" + sbcHashIdentity(remote)
	}
	if root := boundedText(incident.EvidenceRoot, sbcEntityTextBytes); root != "" {
		return "evid:" + sbcHashIdentity(root)
	}
	if identity := boundedText(incident.ID, 64); identity != "" {
		return "anon:" + identity
	}
	if !incident.Time.IsZero() {
		return "anon:" + boundedText(incident.Time.UTC().Format(time.RFC3339Nano), 64)
	}
	return "anon:rule:" + boundedText(giefRuleHint(incident), 48)
}

// sbcNormalizeExecutable strips the kernel's deleted-file marker and the path
// noise so the same binary maps to the same entity across observations.
func sbcNormalizeExecutable(executable string) string {
	cleaned := strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(executable), " (deleted)"))
	if cleaned == "" || cleaned == "." || cleaned == string(filepath.Separator) {
		return ""
	}
	return filepath.Clean(cleaned)
}

// sbcHashIdentity returns the lowercase SHA-256 hex digest of an identity value.
// Case is preserved because Linux paths are case-sensitive.
func sbcHashIdentity(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}

// sbcObservationWeight is the per-family weight one observation adds. A critical
// finding counts double, a high finding one and a half; everything else counts
// as one observation.
func sbcObservationWeight(severity string) float64 {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical":
		return 2.0
	case "high":
		return 1.5
	default:
		return 1.0
	}
}

// sbcDecayFactor returns 2^(-age/halfLife). The exponential form makes the decay
// composable and exact for the canonical values: with a 30 min half-life the
// factor is 1, 0.5, 0.25 and 0.125 at 0, 30, 60 and 90 minutes.
func sbcDecayFactor(age, halfLife time.Duration) float64 {
	if halfLife <= 0 {
		return 0
	}
	if age <= 0 {
		return 1
	}
	return math.Exp2(-float64(age) / float64(halfLife))
}

// sbcRoundScore rounds a decayed score to the documented precision.
func sbcRoundScore(value float64) float64 {
	return math.Round(value*sbcScoreScale) / sbcScoreScale
}

// sbcBoundedFamily converts any value into the closed family set; an unknown
// value falls back to the documented default family.
func sbcBoundedFamily(family string) string {
	family = strings.ToUpper(strings.TrimSpace(family))
	if giefKnownSBCFamily(family) {
		return family
	}
	return SBCDefaultFamily
}

// decayReference returns the reference instant used for decay: an out-of-order
// observation (clock skew, backfill) never inflates the graph, so a `now` before
// lastSeen is folded into lastSeen.
func (ent *sbcEntity) decayReference(now time.Time) time.Time {
	if ent == nil {
		return now
	}
	if now.Before(ent.lastSeen) {
		return ent.lastSeen
	}
	return now
}

// decayedScore returns the summed observation weight decayed to `now`.
func (ent *sbcEntity) decayedScore(now time.Time, halfLife time.Duration) float64 {
	if ent == nil || ent.score <= 0 {
		return 0
	}
	return ent.score * sbcDecayFactor(ent.decayReference(now).Sub(ent.lastSeen), halfLife)
}

// decayedFamilies returns the sorted families whose decayed weight is still
// meaningful at `now`.
func (ent *sbcEntity) decayedFamilies(now time.Time, halfLife time.Duration) []string {
	if ent == nil || len(ent.families) == 0 {
		return nil
	}
	factor := sbcDecayFactor(ent.decayReference(now).Sub(ent.lastSeen), halfLife)
	families := make([]string, 0, len(ent.families))
	for family, weight := range ent.families {
		if weight*factor < sbcDecayEpsilon {
			continue
		}
		families = append(families, family)
	}
	if len(families) == 0 {
		return nil
	}
	sort.Strings(families)
	if len(families) > sbcMaxFamiliesPerEntity {
		families = families[:sbcMaxFamiliesPerEntity]
	}
	return families
}

// decayTo normalises the stored weights from lastSeen to `now`. It never moves
// the reference backwards.
func (ent *sbcEntity) decayTo(now time.Time, halfLife time.Duration) {
	if ent == nil || !now.After(ent.lastSeen) {
		return
	}
	factor := sbcDecayFactor(now.Sub(ent.lastSeen), halfLife)
	ent.score *= factor
	for family, weight := range ent.families {
		decayed := weight * factor
		if decayed < sbcDecayEpsilon {
			delete(ent.families, family)
			continue
		}
		ent.families[family] = decayed
	}
	ent.lastSeen = now
}

// addObservation folds one finding into the entity at `now`.
//
// The family is bounded to the closed eight-family set before it reaches this
// method, so the per-entity family map cannot grow beyond sbcMaxFamiliesPerEntity.
func (ent *sbcEntity) addObservation(family string, weight float64, now time.Time, halfLife time.Duration) {
	if ent == nil {
		return
	}
	ent.decayTo(now, halfLife)
	if ent.families == nil {
		ent.families = make(map[string]float64, sbcMaxFamiliesPerEntity)
	}
	if _, exists := ent.families[family]; !exists && len(ent.families) >= sbcMaxFamiliesPerEntity {
		// Defensive only: cannot happen for the closed family set. Do not grow
		// the map; the observation still counts towards the total score.
		ent.score += weight
		ent.observations++
		return
	}
	ent.families[family] += weight
	ent.score += weight
	ent.observations++
	if ent.firstSeen.IsZero() {
		ent.firstSeen = now
	}
}

// pruneLocked drops entities whose decayed score is below the prune epsilon.
func (f *SBCFusionEngine) pruneLocked(now time.Time) {
	removed := uint64(0)
	for key, ent := range f.entities {
		if ent.decayedScore(now, f.halfLife) < sbcDecayEpsilon {
			delete(f.entities, key)
			removed++
		}
	}
	f.prunings += removed
}

// evictOneLocked removes exactly one entity when the graph is at capacity. The
// victim is deterministic: lowest decayed score, then oldest lastSeen, then
// lexicographically smallest key.
func (f *SBCFusionEngine) evictOneLocked(now time.Time) {
	var victim *sbcEntity
	for _, ent := range f.entities {
		if victim == nil {
			victim = ent
			continue
		}
		victimScore := victim.decayedScore(now, f.halfLife)
		candidateScore := ent.decayedScore(now, f.halfLife)
		switch {
		case candidateScore < victimScore:
			victim = ent
		case candidateScore == victimScore && ent.lastSeen.Before(victim.lastSeen):
			victim = ent
		case candidateScore == victimScore && ent.lastSeen.Equal(victim.lastSeen) && ent.key < victim.key:
			victim = ent
		}
	}
	if victim == nil {
		return
	}
	delete(f.entities, victim.key)
	f.evictions++
}
