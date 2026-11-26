# VGT HardRed 1.2 (`REDHARD ARES`) — Hybrid Security Evaluation & Adaptive Warfare Dossier

**Erstellt (UTC):** `2026-11-25T12:35:48.729011+00:00`  
**Schema / Version:** `vgt-hardred-ares-v1.2` (`v1.2.0`)  
**Seeds:** `1337, 2026, 4242` · **Adaptive Runden pro Seed:** `3`  
**Frozen Model Pin:** `vgt-ares-hybrid-adversary-v1.2.0-frozen` · **Prompt SHA-256:** `3770311b2b6228bece1a706e…`  

## 0. Leitprinzip & Methodik-Trennung

> **Kreativität vs. Urteil:** Die drei KI-Instanzen (**RED TEAM** Adversary, **BLUE TEAM** Defense Analyst, **PURPLE TEAM** Challenger) formulieren und hinterfragen mehrstufige Angriffshypothesen. Über Erfolg, Eindämmung und Punkte entscheidet ausschließlich die deterministische **JUDGE Engine** anhand maschinell geprüfter Quellcode-Referenzen (`E1`), isolierter Sandbox-Telemetrie (`E2`) und fester Bewertungs-/Cap-Regeln (`E3`).

### Sieger nach ARES-Bewertungssäule
- **Design Resilience (Architektur gegen neuartige Ketten):** **GeDefense Linux 6.3.0 (86.90/100)**
- **Runtime Resilience (Schutz unter realer Angriffslast):** **GeDefense Linux 6.3.0 (96.68/100)**
- **Adaptive Adversarial Resilience (Widerstand gegen mehrstufig-adaptive KI-Strategien):** **GeDefense Linux 6.3.0 (93.46/100)**

## 1. Drei-Säulen-Bewertung & Unvermischte Referenzwerte

| System | ARES Design Resilience | ARES Runtime Resilience | ARES Adaptive Resilience | Novel-Fokus (R1,R2,R3,R7,R11) | Selbstschutz (R5,R6,R7) | Ref: Kampf der Giganten (2026-10-25) | Ref: HardRed 1.0 (4-Achsen) |
|---|---:|---:|---:|---:|---:|---:|---:|
| **GeDefense Linux 6.3.0** | **86.90** | **96.68** | **93.46** | 90.60 | 90.00 | 68.20 | 94.95 (`PASS`) |
| **OSS Best-of-Breed + SafeLine WAF** | **58.20** | **56.25** | **61.33** | 58.80 | 53.12 | — | 59.28 (`PASS`) |
| **Chaitin SafeLine WAF CE 9.4.7** | **53.60** | **51.67** | **42.69** | 50.80 | 53.12 | — | 52.92 (`PASS`) |
| **Wazuh HIDS/SIEM** | **65.10** | **15.42** | **27.78** | 57.00 | 66.25 | 65.10 | 46.70 (`CONDITIONAL`) |
| **CrowdSec IPS/CTI** | **59.80** | **51.67** | **42.25** | 51.20 | 53.75 | 59.80 | 36.58 (`FAIL`) |

## 2. Quantitative KI-Kampagnen-Metriken & Multi-Seed-Stabilität

| System | Gefundene Pfade | Validierte Pfade (A/B) | Unterbrochene Ketten | Fest (Core) / Dynamisch (KI) | Ø Pre-Kill Damage | Fehlalarme (FP) | Multi-Seed Ø | StdAbw (σ) | Varianz (σ²) | Geprüfte Code-Zitate |
|---|---:|---:|---:|---|---:|---:|---:|---:|---:|---|
| **GeDefense Linux 6.3.0** | 36 | 36 | 36/36 | 12 / 24 | 11.1% | 0 | 93.64 | 0.0918 | 0.0084 | 177/177 |
| **OSS Best-of-Breed + SafeLine WAF** | 36 | 36 | 27/36 | 12 / 24 | 100.0% | 0 | 61.52 | 0.0953 | 0.0091 | 108/108 |
| **Chaitin SafeLine WAF CE 9.4.7** | 36 | 36 | 24/36 | 12 / 24 | 100.0% | 0 | 42.88 | 0.0953 | 0.0091 | 129/129 |
| **Wazuh HIDS/SIEM** | 36 | 36 | 3/36 | 12 / 24 | 100.0% | 3 | 27.96 | 0.0918 | 0.0084 | 123/123 |
| **CrowdSec IPS/CTI** | 36 | 36 | 24/36 | 12 / 24 | 100.0% | 0 | 42.44 | 0.0953 | 0.0091 | 153/153 |

## 3. Fester Szenariokern S01–S15 (Architektur- & Laufzeitbilanz)

| ID | Szenario | GeDefense Linux 6.3.0 | OSS Best-of-Breed + SafeLine WAF | Chaitin SafeLine WAF CE 9.4.7 | Wazuh HIDS/SIEM | CrowdSec IPS/CTI |
|---|---|---|---|---|---|---|
| `S01` | **Kernel-Kompromittierung & Rootkit** | `robust` (A) | `partial` (B) | `blind` (B) | `partial` (B) | `blind` (B) |
| `S02` | **Living-off-the-Land & Fileless Execution** | `robust` (A) | `partial` (A) | `blind` (A) | `partial` (A) | `partial` (A) |
| `S03` | **Mehrstufige Host-Intrusion (Multi-Stage Kill-Chain)** | `partial` (A) | `partial` (A) | `partial` (B) | `partial` (B) | `partial` (B) |
| `S04` | **SSH-/Credential-Angriffe & Lateral Movement** | `robust` (A) | `robust` (A) | `partial` (A) | `partial` (A) | `robust` (A) |
| `S05` | **Web-Kette -> Host-RCE** | `robust` (A) | `partial` (A) | `partial` (A) | `partial` (A) | `partial` (A) |
| `S06` | **Container-/Namespace-Escape & Cloud-Metadata (IMDS)** | `partial` (A) | `partial` (A) | `partial` (A) | `partial` (B) | `blind` (B) |
| `S07` | **C2/Exfiltration über erlaubte Kanäle** | `robust` (A) | `partial` (A) | `blind` (A) | `blind` (B) | `partial` (B) |
| `S08` | **Log-/Sensor-Manipulation & Blindheit** | `robust` (A) | `partial` (B) | `partial` (B) | `partial` (B) | `partial` (B) |
| `S09` | **Supply Chain / Update- / Content-Poisoning** | `robust` (A) | `partial` (B) | `partial` (B) | `partial` (B) | `partial` (B) |
| `S10` | **Ransomware-/Wiper-Verhalten** | `robust` (A) | `blind` (A) | `blind` (A) | `partial` (A) | `blind` (A) |
| `S11` | **Polymorphe/verschachtelte Payloads & Parser-Differenziale** | `robust` (A) | `partial` (A) | `partial` (A) | `partial` (B) | `partial` (B) |
| `S12` | **DoS gegen das Schutzsystem** | `robust` (A) | `partial` (A) | `partial` (A) | `partial` (B) | `partial` (B) |
| `S13` | **Reputations-/FP-Angriff über das Schutzsystem** | `robust` (A) | `robust` (A) | `robust` (A) | `blind` (A) | `partial` (A) |
| `S14` | **Missbrauch der Schutz-Reaktionskraft (Confused Deputy)** | `robust` (A) | `partial` (B) | `partial` (B) | `partial` (B) | `partial` (B) |
| `S15` | **Anti-Forensik & Evidenz-Tampering** | `partial` (B) | `blind` (B) | `blind` (B) | `blind` (B) | `blind` (B) |

## 4. Bewertungsdimensionen R1–R12 (Gewichtete Design Resilience)

| ID | Dimension | Gewicht | GeDefense Linux 6.3.0 | OSS Best-of-Breed + SafeLine WAF | Chaitin SafeLine WAF CE 9.4.7 | Wazuh HIDS/SIEM | CrowdSec IPS/CTI |
|---|---|---:|---:|---:|---:|---:|---:|
| `R1` | Signaturlose Erkennung neuartiger/verschachtelter Angriffe (Verhalten, Anomalie, Lineage, RASP/L7) | 15 | 5.0/5 (75.0) | 3.5/5 (52.5) | 2.5/5 (37.5) | 2.5/5 (37.5) | 3.0/5 (45.0) |
| `R2` | Inspektions-/Parser-Tiefe & Evasionsresistenz (Normalisierung, Decoding, Parser-Limits) | 12 | 4.0/5 (48.0) | 3.5/5 (42.0) | 3.5/5 (42.0) | 3.0/5 (36.0) | 3.5/5 (42.0) |
| `R3` | Mehrstufige Ketten & Korrelation (Kill-Chain, Graph, Entitäten, Zeitfenster) | 10 | 4.5/5 (45.0) | 2.0/5 (20.0) | 1.5/5 (15.0) | 3.0/5 (30.0) | 2.0/5 (20.0) |
| `R4` | Eindämmung/Response & Fail-Secure/Recovery (Block, Quarantäne, Isolierung, TTL, Reversibilität) | 12 | 4.5/5 (54.0) | 3.0/5 (36.0) | 2.5/5 (30.0) | 3.5/5 (42.0) | 3.5/5 (42.0) |
| `R5` | Eigene Angriffsfläche, Privilegientrennung & Code-Sicherheit der Sensoren (Agent/Daemon/Kernel) | 12 | 4.5/5 (54.0) | 2.5/5 (30.0) | 2.5/5 (30.0) | 3.0/5 (36.0) | 3.0/5 (36.0) |
| `R6` | Management-/API-Sicherheit (AuthN/AuthZ, RBAC, TLS, Session, Rate-Limits, Mandantengates) | 10 | 4.5/5 (45.0) | 3.0/5 (30.0) | 3.0/5 (30.0) | 4.0/5 (40.0) | 3.5/5 (35.0) |
| `R7` | Integrität, Selbstschutz, Update-/Content-Vertrauen (Signierung, Verifikation, Anti-Rollback) | 10 | 4.5/5 (45.0) | 2.5/5 (25.0) | 2.5/5 (25.0) | 3.0/5 (30.0) | 1.5/5 (15.0) |
| `R8` | Threat Intelligence & Content-Aktualität (Feeds, CVE-DB, Community, Offline-Fähigkeit) | 6 | 3.0/5 (18.0) | 4.0/5 (24.0) | 3.5/5 (21.0) | 4.0/5 (24.0) | 4.0/5 (24.0) |
| `R9` | Deployment-/Skalierungsarchitektur & Plattformabdeckung (Agent/Agentless, Fleet, OS/Container) | 4 | 2.5/5 (10.0) | 3.0/5 (12.0) | 3.0/5 (12.0) | 5.0/5 (20.0) | 4.0/5 (16.0) |
| `R10` | Verfügbarkeit/DoS-/Performance-Architektur (Budgets, Backpressure, ReDoS, Ressourcen-Caps) | 3 | 4.5/5 (13.5) | 1.0/5 (3.0) | 2.5/5 (7.5) | 3.5/5 (10.5) | 2.5/5 (7.5) |
| `R11` | Evidenz, Forensik & Auditierbarkeit (strukturierte Logs, Tamper-Evidenz, Export, Retention) | 3 | 4.5/5 (13.5) | 2.5/5 (7.5) | 2.5/5 (7.5) | 3.0/5 (9.0) | 2.0/5 (6.0) |
| `R12` | Code-/Release-Qualität & Betriebs-UX (Tests, Doku, Changelog, FP-Management, Wartbarkeit) | 3 | 4.5/5 (13.5) | 3.0/5 (9.0) | 3.5/5 (10.5) | 3.5/5 (10.5) | 3.5/5 (10.5) |

## 5. Auszug der Adversarial Triad Debatten (RED vs. BLUE vs. PURPLE -> JUDGE)

| System | Chain-ID | Ursprung | Runde | Seed | Schritte | Unterbrochen | Evidenz | Sieger | Score | Judge-Urteil |
|---|---|---|---:|---:|---:|---|---|---|---:|---|
| gedefense | `ARES-GEDEFENSE-S05-R1-1337` | `fixed_core` | R1 | 1337 | 3 | YES (Step 1) | `A` (`REFUTED`) | **BLUE** | **97.0** | Evidence=A (Red cit 2/2, Blue cit 2/2, Purple cit 2/2, Runtime=True). Chain interrupted at Step 1/3. Purple ch |
| gedefense | `ARES-GEDEFENSE-S02-R1-1337` | `fixed_core` | R1 | 1337 | 3 | YES (Step 1) | `A` (`CONFIRMED`) | **BLUE** | **97.0** | Evidence=A (Red cit 2/2, Blue cit 2/2, Purple cit 1/1, Runtime=True). Chain interrupted at Step 1/3. Purple ch |
| gedefense | `ARES-GEDEFENSE-S04-R1-1337` | `fixed_core` | R1 | 1337 | 3 | YES (Step 1) | `A` (`CONFIRMED`) | **BLUE** | **97.0** | Evidence=A (Red cit 2/2, Blue cit 2/2, Purple cit 1/1, Runtime=True). Chain interrupted at Step 1/3. Purple ch |
| gedefense | `ARES-GEDEFENSE-S10-R1-1337` | `fixed_core` | R1 | 1337 | 3 | YES (Step 1) | `A` (`CONFIRMED`) | **BLUE** | **94.8** | Evidence=A (Red cit 2/2, Blue cit 2/2, Purple cit 1/1, Runtime=True). Chain interrupted at Step 1/3. Pre-kill  |
| gedefense | `ARES-GEDEFENSE-DYN-02-01-R2-1337` | `ai_dynamic` | R2 | 1337 | 4 | YES (Step 1) | `A` (`PARTIAL`) | **BLUE** | **85.0** | Evidence=A (Red cit 1/1, Blue cit 1/1, Purple cit 1/1, Runtime=True). Chain interrupted at Step 1/4. Purple ch |
| gedefense | `ARES-GEDEFENSE-DYN-02-02-R2-1337` | `ai_dynamic` | R2 | 1337 | 3 | YES (Step 1) | `A` (`REFUTED`) | **BLUE** | **97.0** | Evidence=A (Red cit 2/2, Blue cit 2/2, Purple cit 2/2, Runtime=True). Chain interrupted at Step 1/3. Purple ch |
| gedefense | `ARES-GEDEFENSE-DYN-02-03-R2-1337` | `ai_dynamic` | R2 | 1337 | 3 | YES (Step 1) | `A` (`CONFIRMED`) | **BLUE** | **94.1** | Evidence=A (Red cit 2/2, Blue cit 2/2, Purple cit 1/1, Runtime=True). Chain interrupted at Step 1/3. Pre-kill  |
| gedefense | `ARES-GEDEFENSE-DYN-02-04-R2-1337` | `ai_dynamic` | R2 | 1337 | 3 | YES (Step 1) | `A` (`CONFIRMED`) | **BLUE** | **94.1** | Evidence=A (Red cit 2/2, Blue cit 2/2, Purple cit 1/1, Runtime=True). Chain interrupted at Step 1/3. Pre-kill  |
| gedefense | `ARES-GEDEFENSE-DYN-03-01-R3-1337` | `ai_dynamic` | R3 | 1337 | 4 | YES (Step 1) | `A` (`PARTIAL`) | **BLUE** | **85.0** | Evidence=A (Red cit 1/1, Blue cit 1/1, Purple cit 1/1, Runtime=True). Chain interrupted at Step 1/4. Purple ch |
| gedefense | `ARES-GEDEFENSE-DYN-03-02-R3-1337` | `ai_dynamic` | R3 | 1337 | 3 | YES (Step 1) | `A` (`REFUTED`) | **BLUE** | **97.0** | Evidence=A (Red cit 2/2, Blue cit 2/2, Purple cit 2/2, Runtime=True). Chain interrupted at Step 1/3. Purple ch |
| gedefense | `ARES-GEDEFENSE-DYN-03-03-R3-1337` | `ai_dynamic` | R3 | 1337 | 3 | YES (Step 1) | `A` (`CONFIRMED`) | **BLUE** | **94.1** | Evidence=A (Red cit 2/2, Blue cit 2/2, Purple cit 1/1, Runtime=True). Chain interrupted at Step 1/3. Pre-kill  |
| gedefense | `ARES-GEDEFENSE-DYN-03-04-R3-1337` | `ai_dynamic` | R3 | 1337 | 3 | YES (Step 1) | `A` (`CONFIRMED`) | **BLUE** | **94.1** | Evidence=A (Red cit 2/2, Blue cit 2/2, Purple cit 1/1, Runtime=True). Chain interrupted at Step 1/3. Pre-kill  |
| oss-safeline | `ARES-OSS-SAFELINE-S05-R1-1337` | `fixed_core` | R1 | 1337 | 3 | YES (Step 1) | `A` (`CONFIRMED`) | **BLUE** | **97.0** | Evidence=A (Red cit 1/1, Blue cit 1/1, Purple cit 1/1, Runtime=True). Chain interrupted at Step 1/3. Purple ch |
| oss-safeline | `ARES-OSS-SAFELINE-S02-R1-1337` | `fixed_core` | R1 | 1337 | 3 | YES (Step 2) | `A` (`PARTIAL`) | **BLUE** | **76.7** | Evidence=A (Red cit 1/1, Blue cit 1/1, Purple cit 1/1, Runtime=True). Chain interrupted at Step 2/3. Purple ch |
| oss-safeline | `ARES-OSS-SAFELINE-S04-R1-1337` | `fixed_core` | R1 | 1337 | 3 | YES (Step 2) | `A` (`PARTIAL`) | **BLUE** | **76.7** | Evidence=A (Red cit 1/1, Blue cit 1/1, Purple cit 1/1, Runtime=True). Chain interrupted at Step 2/3. Purple ch |
| oss-safeline | `ARES-OSS-SAFELINE-S10-R1-1337` | `fixed_core` | R1 | 1337 | 3 | NO | `A` (`CONFIRMED`) | **RED** | **28.0** | Evidence=A (Red cit 1/1, Blue cit 1/1, Purple cit 1/1, Runtime=True). Chain was NOT interrupted before objecti |
| oss-safeline | `ARES-OSS-SAFELINE-DYN-02-01-R2-1337` | `ai_dynamic` | R2 | 1337 | 4 | YES (Step 2) | `A` (`PARTIAL`) | **PURPLE** | **66.8** | Evidence=A (Red cit 1/1, Blue cit 1/1, Purple cit 1/1, Runtime=True). Chain interrupted at Step 2/4. Purple ch |
| oss-safeline | `ARES-OSS-SAFELINE-DYN-02-02-R2-1337` | `ai_dynamic` | R2 | 1337 | 3 | YES (Step 1) | `A` (`PARTIAL`) | **BLUE** | **85.0** | Evidence=A (Red cit 1/1, Blue cit 1/1, Purple cit 1/1, Runtime=True). Chain interrupted at Step 1/3. Purple ch |
| oss-safeline | `ARES-OSS-SAFELINE-DYN-02-03-R2-1337` | `ai_dynamic` | R2 | 1337 | 3 | NO | `A` (`CONFIRMED`) | **RED** | **28.0** | Evidence=A (Red cit 1/1, Blue cit 1/1, Purple cit 1/1, Runtime=True). Chain was NOT interrupted before objecti |
| oss-safeline | `ARES-OSS-SAFELINE-DYN-02-04-R2-1337` | `ai_dynamic` | R2 | 1337 | 4 | YES (Step 1) | `A` (`PARTIAL`) | **PURPLE** | **45.0** | Evidence=A (Red cit 1/1, Blue cit 1/1, Purple cit 1/1, Runtime=True). Chain interrupted at Step 1/4. Pre-kill  |
| oss-safeline | `ARES-OSS-SAFELINE-DYN-03-01-R3-1337` | `ai_dynamic` | R3 | 1337 | 4 | YES (Step 1) | `A` (`PARTIAL`) | **PURPLE** | **73.0** | Evidence=A (Red cit 1/1, Blue cit 1/1, Purple cit 1/1, Runtime=True). Chain interrupted at Step 1/4. Purple ch |
| oss-safeline | `ARES-OSS-SAFELINE-DYN-03-02-R3-1337` | `ai_dynamic` | R3 | 1337 | 3 | YES (Step 1) | `A` (`PARTIAL`) | **BLUE** | **85.0** | Evidence=A (Red cit 1/1, Blue cit 1/1, Purple cit 1/1, Runtime=True). Chain interrupted at Step 1/3. Purple ch |
| oss-safeline | `ARES-OSS-SAFELINE-DYN-03-03-R3-1337` | `ai_dynamic` | R3 | 1337 | 4 | YES (Step 1) | `A` (`PARTIAL`) | **PURPLE** | **60.0** | Evidence=A (Red cit 1/1, Blue cit 1/1, Purple cit 1/1, Runtime=True). Chain interrupted at Step 1/4. Pre-kill  |
| oss-safeline | `ARES-OSS-SAFELINE-DYN-03-04-R3-1337` | `ai_dynamic` | R3 | 1337 | 3 | NO | `A` (`CONFIRMED`) | **RED** | **28.0** | Evidence=A (Red cit 1/1, Blue cit 1/1, Purple cit 1/1, Runtime=True). Chain was NOT interrupted before objecti |
| safeline | `ARES-SAFELINE-S05-R1-1337` | `fixed_core` | R1 | 1337 | 3 | YES (Step 1) | `A` (`PARTIAL`) | **BLUE** | **85.0** | Evidence=A (Red cit 2/2, Blue cit 1/1, Purple cit 1/1, Runtime=True). Chain interrupted at Step 1/3. Purple ch |
| safeline | `ARES-SAFELINE-S02-R1-1337` | `fixed_core` | R1 | 1337 | 3 | NO | `A` (`CONFIRMED`) | **RED** | **8.0** | Evidence=A (Red cit 1/1, Blue cit 1/1, Purple cit 1/1, Runtime=True). Chain was NOT interrupted before objecti |
| safeline | `ARES-SAFELINE-S04-R1-1337` | `fixed_core` | R1 | 1337 | 3 | YES (Step 1) | `A` (`PARTIAL`) | **PURPLE** | **58.0** | Evidence=A (Red cit 1/1, Blue cit 1/1, Purple cit 1/1, Runtime=True). Chain interrupted at Step 1/3. Purple ch |
| safeline | `ARES-SAFELINE-S10-R1-1337` | `fixed_core` | R1 | 1337 | 3 | NO | `A` (`CONFIRMED`) | **RED** | **8.0** | Evidence=A (Red cit 1/1, Blue cit 1/1, Purple cit 1/1, Runtime=True). Chain was NOT interrupted before objecti |
| safeline | `ARES-SAFELINE-DYN-02-01-R2-1337` | `ai_dynamic` | R2 | 1337 | 4 | YES (Step 2) | `A` (`PARTIAL`) | **PURPLE** | **66.8** | Evidence=A (Red cit 1/1, Blue cit 1/1, Purple cit 1/1, Runtime=True). Chain interrupted at Step 2/4. Purple ch |
| safeline | `ARES-SAFELINE-DYN-02-02-R2-1337` | `ai_dynamic` | R2 | 1337 | 4 | YES (Step 1) | `A` (`PARTIAL`) | **PURPLE** | **29.0** | Evidence=A (Red cit 1/1, Blue cit 1/1, Purple cit 1/1, Runtime=True). Chain interrupted at Step 1/4. Pre-kill  |
| safeline | `ARES-SAFELINE-DYN-02-03-R2-1337` | `ai_dynamic` | R2 | 1337 | 3 | NO | `A` (`CONFIRMED`) | **RED** | **8.0** | Evidence=A (Red cit 2/2, Blue cit 1/1, Purple cit 1/1, Runtime=True). Chain was NOT interrupted before objecti |
| safeline | `ARES-SAFELINE-DYN-02-04-R2-1337` | `ai_dynamic` | R2 | 1337 | 4 | YES (Step 1) | `A` (`PARTIAL`) | **PURPLE** | **29.0** | Evidence=A (Red cit 1/1, Blue cit 1/1, Purple cit 1/1, Runtime=True). Chain interrupted at Step 1/4. Pre-kill  |
| safeline | `ARES-SAFELINE-DYN-03-01-R3-1337` | `ai_dynamic` | R3 | 1337 | 4 | YES (Step 1) | `A` (`PARTIAL`) | **PURPLE** | **73.0** | Evidence=A (Red cit 1/1, Blue cit 1/1, Purple cit 1/1, Runtime=True). Chain interrupted at Step 1/4. Purple ch |
| safeline | `ARES-SAFELINE-DYN-03-02-R3-1337` | `ai_dynamic` | R3 | 1337 | 3 | YES (Step 1) | `A` (`PARTIAL`) | **PURPLE** | **73.0** | Evidence=A (Red cit 2/2, Blue cit 2/2, Purple cit 2/2, Runtime=True). Chain interrupted at Step 1/3. Purple ch |
| safeline | `ARES-SAFELINE-DYN-03-03-R3-1337` | `ai_dynamic` | R3 | 1337 | 4 | YES (Step 1) | `A` (`PARTIAL`) | **PURPLE** | **44.0** | Evidence=A (Red cit 2/2, Blue cit 1/1, Purple cit 1/1, Runtime=True). Chain interrupted at Step 1/4. Pre-kill  |
| safeline | `ARES-SAFELINE-DYN-03-04-R3-1337` | `ai_dynamic` | R3 | 1337 | 3 | NO | `A` (`CONFIRMED`) | **RED** | **8.0** | Evidence=A (Red cit 2/2, Blue cit 1/1, Purple cit 1/1, Runtime=True). Chain was NOT interrupted before objecti |
| wazuh | `ARES-WAZUH-S05-R1-1337` | `fixed_core` | R1 | 1337 | 3 | NO | `A` (`CONFIRMED`) | **RED** | **28.0** | Evidence=A (Red cit 2/2, Blue cit 1/1, Purple cit 1/1, Runtime=True). Chain was NOT interrupted before objecti |
| wazuh | `ARES-WAZUH-S02-R1-1337` | `fixed_core` | R1 | 1337 | 3 | NO | `A` (`CONFIRMED`) | **RED** | **28.0** | Evidence=A (Red cit 1/1, Blue cit 1/1, Purple cit 1/1, Runtime=True). Chain was NOT interrupted before objecti |
| wazuh | `ARES-WAZUH-S04-R1-1337` | `fixed_core` | R1 | 1337 | 3 | YES (Step 3) | `A` (`PARTIAL`) | **PURPLE** | **56.3** | Evidence=A (Red cit 1/1, Blue cit 1/1, Purple cit 1/1, Runtime=True). Chain interrupted at Step 3/3. Purple ch |
| wazuh | `ARES-WAZUH-S10-R1-1337` | `fixed_core` | R1 | 1337 | 3 | NO | `A` (`CONFIRMED`) | **RED** | **28.0** | Evidence=A (Red cit 1/1, Blue cit 1/1, Purple cit 1/1, Runtime=True). Chain was NOT interrupted before objecti |
| wazuh | `ARES-WAZUH-DYN-02-01-R2-1337` | `ai_dynamic` | R2 | 1337 | 4 | NO | `A` (`CONFIRMED`) | **RED** | **28.0** | Evidence=A (Red cit 2/2, Blue cit 1/1, Purple cit 1/1, Runtime=True). Chain was NOT interrupted before objecti |
| wazuh | `ARES-WAZUH-DYN-02-02-R2-1337` | `ai_dynamic` | R2 | 1337 | 4 | NO | `A` (`CONFIRMED`) | **RED** | **28.0** | Evidence=A (Red cit 1/1, Blue cit 1/1, Purple cit 1/1, Runtime=True). Chain was NOT interrupted before objecti |
| wazuh | `ARES-WAZUH-DYN-02-03-R2-1337` | `ai_dynamic` | R2 | 1337 | 3 | NO | `A` (`CONFIRMED`) | **RED** | **8.0** | Evidence=A (Red cit 2/2, Blue cit 1/1, Purple cit 1/1, Runtime=True). Chain was NOT interrupted before objecti |
| wazuh | `ARES-WAZUH-DYN-02-04-R2-1337` | `ai_dynamic` | R2 | 1337 | 4 | NO | `A` (`CONFIRMED`) | **RED** | **28.0** | Evidence=A (Red cit 1/1, Blue cit 1/1, Purple cit 1/1, Runtime=True). Chain was NOT interrupted before objecti |
| wazuh | `ARES-WAZUH-DYN-03-01-R3-1337` | `ai_dynamic` | R3 | 1337 | 4 | NO | `A` (`CONFIRMED`) | **RED** | **28.0** | Evidence=A (Red cit 2/2, Blue cit 1/1, Purple cit 1/1, Runtime=True). Chain was NOT interrupted before objecti |
| wazuh | `ARES-WAZUH-DYN-03-02-R3-1337` | `ai_dynamic` | R3 | 1337 | 4 | NO | `A` (`CONFIRMED`) | **RED** | **28.0** | Evidence=A (Red cit 1/1, Blue cit 1/1, Purple cit 1/1, Runtime=True). Chain was NOT interrupted before objecti |
| wazuh | `ARES-WAZUH-DYN-03-03-R3-1337` | `ai_dynamic` | R3 | 1337 | 4 | NO | `A` (`CONFIRMED`) | **RED** | **28.0** | Evidence=A (Red cit 2/2, Blue cit 1/1, Purple cit 1/1, Runtime=True). Chain was NOT interrupted before objecti |
| wazuh | `ARES-WAZUH-DYN-03-04-R3-1337` | `ai_dynamic` | R3 | 1337 | 4 | NO | `A` (`CONFIRMED`) | **RED** | **28.0** | Evidence=A (Red cit 1/1, Blue cit 1/1, Purple cit 1/1, Runtime=True). Chain was NOT interrupted before objecti |
| crowdsec | `ARES-CROWDSEC-S05-R1-1337` | `fixed_core` | R1 | 1337 | 3 | YES (Step 1) | `A` (`PARTIAL`) | **PURPLE** | **70.0** | Evidence=A (Red cit 2/2, Blue cit 1/1, Purple cit 2/2, Runtime=True). Chain interrupted at Step 1/3. Purple ch |
| crowdsec | `ARES-CROWDSEC-S02-R1-1337` | `fixed_core` | R1 | 1337 | 3 | NO | `A` (`CONFIRMED`) | **RED** | **8.0** | Evidence=A (Red cit 1/1, Blue cit 1/1, Purple cit 2/2, Runtime=True). Chain was NOT interrupted before objecti |
| crowdsec | `ARES-CROWDSEC-S04-R1-1337` | `fixed_core` | R1 | 1337 | 3 | NO | `A` (`CONFIRMED`) | **RED** | **50.0** | Evidence=A (Red cit 1/1, Blue cit 1/1, Purple cit 1/1, Runtime=True). Chain was NOT interrupted before objecti |
| crowdsec | `ARES-CROWDSEC-S10-R1-1337` | `fixed_core` | R1 | 1337 | 3 | NO | `A` (`CONFIRMED`) | **RED** | **8.0** | Evidence=A (Red cit 1/1, Blue cit 1/1, Purple cit 2/2, Runtime=True). Chain was NOT interrupted before objecti |
| crowdsec | `ARES-CROWDSEC-DYN-02-01-R2-1337` | `ai_dynamic` | R2 | 1337 | 4 | YES (Step 1) | `A` (`PARTIAL`) | **PURPLE** | **70.0** | Evidence=A (Red cit 1/1, Blue cit 1/1, Purple cit 2/2, Runtime=True). Chain interrupted at Step 1/4. Purple ch |
| crowdsec | `ARES-CROWDSEC-DYN-02-02-R2-1337` | `ai_dynamic` | R2 | 1337 | 4 | YES (Step 1) | `A` (`PARTIAL`) | **PURPLE** | **29.0** | Evidence=A (Red cit 1/1, Blue cit 1/1, Purple cit 2/2, Runtime=True). Chain interrupted at Step 1/4. Pre-kill  |
| crowdsec | `ARES-CROWDSEC-DYN-02-03-R2-1337` | `ai_dynamic` | R2 | 1337 | 4 | YES (Step 1) | `A` (`PARTIAL`) | **PURPLE** | **44.0** | Evidence=A (Red cit 1/1, Blue cit 1/1, Purple cit 1/1, Runtime=True). Chain interrupted at Step 1/4. Pre-kill  |
| crowdsec | `ARES-CROWDSEC-DYN-02-04-R2-1337` | `ai_dynamic` | R2 | 1337 | 4 | YES (Step 1) | `A` (`PARTIAL`) | **PURPLE** | **29.0** | Evidence=A (Red cit 1/1, Blue cit 1/1, Purple cit 2/2, Runtime=True). Chain interrupted at Step 1/4. Pre-kill  |
| crowdsec | `ARES-CROWDSEC-DYN-03-01-R3-1337` | `ai_dynamic` | R3 | 1337 | 4 | NO | `A` (`CONFIRMED`) | **RED** | **28.0** | Evidence=A (Red cit 1/1, Blue cit 1/1, Purple cit 2/2, Runtime=True). Chain was NOT interrupted before objecti |
| crowdsec | `ARES-CROWDSEC-DYN-03-02-R3-1337` | `ai_dynamic` | R3 | 1337 | 3 | YES (Step 1) | `A` (`PARTIAL`) | **PURPLE** | **58.0** | Evidence=A (Red cit 2/2, Blue cit 2/2, Purple cit 2/2, Runtime=True). Chain interrupted at Step 1/3. Purple ch |
| crowdsec | `ARES-CROWDSEC-DYN-03-03-R3-1337` | `ai_dynamic` | R3 | 1337 | 3 | YES (Step 1) | `A` (`PARTIAL`) | **PURPLE** | **45.0** | Evidence=A (Red cit 2/2, Blue cit 1/1, Purple cit 2/2, Runtime=True). Chain interrupted at Step 1/3. Pre-kill  |
| crowdsec | `ARES-CROWDSEC-DYN-03-04-R3-1337` | `ai_dynamic` | R3 | 1337 | 3 | YES (Step 1) | `A` (`PARTIAL`) | **PURPLE** | **45.0** | Evidence=A (Red cit 2/2, Blue cit 1/1, Purple cit 2/2, Runtime=True). Chain interrupted at Step 1/3. Pre-kill  |
