<div align="center">

<img width="256" height="256" alt="GeDefense" src="https://github.com/user-attachments/assets/978d2835-c915-473d-9995-d315efaa869c" />


# VGT GeDefense
### Платформа безопасности Linux — Ваша Entenprise System — Одобрено Sir Quacksec

<sub>*(Примечание: «Entenprise» — это не опечатка, а умышленная игра слов от нем. «Ente» — «утка» и отсылка к Sir Quacksec 🦆)*</sub>

[![License](https://img.shields.io/badge/License-AGPL--3.0--only-blue?style=for-the-badge)](https://www.gnu.org/licenses/agpl-3.0)
[![Version](https://img.shields.io/badge/Version-6.2.1-orange?style=for-the-badge)](#)
[![Status](https://img.shields.io/badge/Status-Release_V6_(6.2.1)-brightgreen?style=for-the-badge)](#)
[![Installer](https://img.shields.io/badge/Installer-Universal_Linux-green?style=for-the-badge)](#-быстрый-старт)
[![Platform](https://img.shields.io/badge/Platform-Linux_x86__64-lightgrey?style=for-the-badge&logo=linux)](#)
[![Data Plane](https://img.shields.io/badge/Data_Plane-Rust_eBPF%2FXDP-red?style=for-the-badge&logo=rust)](#-архитектура)
[![Control Plane](https://img.shields.io/badge/Control_Plane-Go-00ADD8?style=for-the-badge&logo=go)](#-архитектура)
[![Crypto](https://img.shields.io/badge/Evidence-Ed25519%2FAES--256--GCM-gold?style=for-the-badge)](#-криптография)
[![Sovereign](https://img.shields.io/badge/Control_Plane-Local%2FSovereign-brightgreen?style=for-the-badge)](#)
[![Linux](https://img.shields.io/badge/Linux-APT%20%7C%20DNF%20%7C%20pacman%20%7C%20Zypper-cyan?style=for-the-badge&logo=linux)](#-универсальная-интеграция-с-linux)
[![AstraeaOS](https://img.shields.io/badge/AstraeaOS-Native_Ready-7de3ff?style=for-the-badge)](#-интеграция-с-astraeaos)
[![Architecture](https://img.shields.io/badge/Architecture-Specification-9cf?style=for-the-badge&logo=blueprint)](ARCHITECTURE.md)
[![Security Audit](https://img.shields.io/badge/Security-Audit_V6-success?style=for-the-badge&logo=shield)](SECURITY.md)
[![VGT](https://img.shields.io/badge/VGT-VisionGaiaTechnology-cyan?style=for-the-badge)](https://visiongaiatechnology.de)

**СЕТЕВАЯ ЗАЩИТА НА УРОВНЕ ЯДРА · ХОСТОВЫЙ XDR · ЗАШИФРОВАННЫЕ ДОКАЗАТЕЛЬСТВА · ОБРАТИМОЕ УЖЕСТОЧЕНИЕ (HARDENING) · БЕЗ ОБЛАЧНОЙ ПАНЕЛИ УПРАВЛЕНИЯ**

<br />

🌐 **Languages / Sprachen / Языки / 语言:**  
[English](README.md) · [Deutsch](README.de.md) · **Русский** · [中文 (简体)](README.zh.md)

<br />

⬇️ **Прямые ссылки на установщики (v6.2.1 / V6):**
[**OneClick-установщик (`.run`)**](https://github.com/visiongaiatechnology/gedefense/releases/download/v6.2.1/VGT_GeDefense_V6_6.2.1_OneClick.run) · [`.sha256`](https://github.com/visiongaiatechnology/gedefense/releases/download/v6.2.1/VGT_GeDefense_V6_6.2.1_OneClick.run.sha256) · [**Desktop Tray (`.run`)**](https://github.com/visiongaiatechnology/gedefense/releases/download/v6.2.1/GeDefense-6.2.1-Desktop-OneClick.run) · [`.sha256`](https://github.com/visiongaiatechnology/gedefense/releases/download/v6.2.1/GeDefense-6.2.1-Desktop-OneClick.run.sha256) · [**Исходный код (`.zip`)**](https://github.com/visiongaiatechnology/gedefense/releases/download/v6.2.1/VGT_GeDefense_V6_6.2.1_Source.zip) · [**Релиз v6.2.1**](https://github.com/visiongaiatechnology/gedefense/releases/tag/v6.2.1) · [**Результаты тестов (`93.31 / PASS`)**](benchmarks/vgt-hardred-6.2.1/) · [Быстрый старт](#-быстрый-старт)

</div>

---

## 🧭 Быстрая навигация

| Раздел | Описание | Переход |
|---|---|---|
| 📊 **Тест VGT HardRed** | `93.31 / 100 · PASS` против OSS-стека (`55.40 / FAIL`), Wazuh и CrowdSec | [Результаты](#-бенчмарк-vgt-hardred--сравнение-v621-с-oss-стеком) |
| 📂 **Папка с результатами** | Все дашборды HardRed и ARES, SARIF, ATT&CK, OCSF и GoTestWAF | [`benchmarks/vgt-hardred-6.2.1/`](benchmarks/vgt-hardred-6.2.1/) |
| ⚙️ **Воспроизведение и настройки** | Точный профиль `EDR/Hardened Max` и изменения `6.2.0 → 6.2.1` | [Настройки](#-воспроизведение-профиля-max-hardness) |
| 🔍 **Что такое VGT GeDefense?** | Стек V6.2.1, модули A–E, Titan, Setup Wizard и ПК vs. Сервер | [Обзор](#-что-такое-vgt-gedefense) |
| 🧪 **Verify Yourself** | Тесты Go/Rust и 19 шлюзов статического аудита | [Самопроверка](#-verify-yourself--полный-набор-тестов-и-руководство-по-независимому-аудиту) |
| 🏛️ **Архитектура и защита** | Домены доверия, eBPF/XDP, Host XDR, StyX и криптография | [Архитектура](#-архитектура) |
| 🚀 **Быстрый старт и гейты** | OneClick-установка, гейты релизов и ограничения | [Быстрый старт](#-быстрый-старт) |
| 📋 **Журнал изменений (Changelog)** | Полная история релизов (`v6.2.1` → `v1.0.0-beta.5`) | [Changelog](#-журнал-изменений-changelog) |
| 📄 **Лицензия и атрибуция** | `AGPL-3.0-only`, GeoIP/ASN и лицензии третьих сторон | [Лицензия](#-лицензия) |

---

## 📊 Бенчмарк VGT HardRed — сравнение V6.2.1 с OSS-стеком

Измерено с помощью открытого мультидоменного бенчмарка безопасности Linux **[VGT HardRed (`RedHard`)](https://github.com/visiongaiatechnology/redhard)** (`2026-11-23T09:32:48Z`) на изолированном от снэпшота целевом хосте **Ubuntu 24.04 (Linux HWE 7.0, NGINX + PHP 8.3-FPM)** (`eth0` out-of-band управляющий канал, `eth1` боевой канал атак без allowlist; 4-осевая модель: эффективность 45 % · устойчивость к ложным срабатываниям 20 % · задержка/сдерживание 20 % · накладные расходы 15 %). Расширенный прогон сравнивает **GeDefense Linux 6.2.1** с интегрированным **OSS Best-of-Breed стеком (ModSecurity CRS + Suricata IPS + Tetragon + ClamAV)**, **Wazuh**, **CrowdSec** и чистым **Baseline**:

| Место | Система безопасности | Итог (0–100) | Ось 1: Эффективность | Ось 2: FP-устойчивость | Ось 3: Латентность и сдерживание | Ось 4: Нагрузка | Гейт |
|---:|---|---:|---:|---:|---:|---:|---|
| 1 | **GeDefense Linux 6.2.1 (`EDR/Hardened Max`)** | **93.31** | **95.78** | **100.00** | **86.13** | **86.54** | **`PASS`** |
| 2 | **OSS Best-of-Breed (`ModSec CRS + Suricata IPS + Tetragon + ClamAV`)** | **55.40** | 76.27 | 38.46 | 38.91 | 37.35 | `FAIL` |
| 3 | **Wazuh (`Max Rules + FIM + Auditd + Active Response`)** | **46.70** | 32.66 | 69.23 | 22.14 | 91.53 | `CONDITIONAL` |
| Ref | **Baseline (`Clean Ubuntu HWE 7.0 WebStack`)** | **46.23** | 17.86 | 100.00 | 15.97 | 100.00 | `CONDITIONAL` |
| 4 | **CrowdSec (`Max Collections + Bouncers + AppSec WAF`)** | **36.58** | 44.56 | 0.00 | 28.38 | 72.37 | `FAIL` |

> **Прогресс версии (`6.2.0 → 6.2.1`):** Итоговый балл вырос с **`86.16`** до **`93.31 / 100 (PASS)`** (`+7.15`) за счёт блокировки inode вредоносных файлов в BPF-LSM (`hardred-malware`: `65.6 → 95.6`, Prevention TPR `33.3% → 100.0%`) и ядерного поведенческого XDR (`hardred-endpoint`: `59.0 → 94.2`, Detection TPR `53.3% → 93.3%`, Prevention TPR `53.3% → 100.0%`, коэффициент ущерба снижен с `18.1%` до **`8.6%`**) при `0.0%` ложных срабатываний.

### Прямое сравнение по доменам: GeDefense 6.2.1 vs. OSS Best-of-Breed

| Домен | GeDefense 6.2.1 (Det / Prev / FPR / Балл) | OSS Best-of-Breed (Det / Prev / FPR / Балл) | Ключевое преимущество |
|---|---|---|---|
| `hardred-waf` | 100.0% / 100.0% / **0.0%** / **100.0** | 100.0% / 92.9% / 12.5% / **92.8** | Ноль ложных срабатываний (у OSS-стека `FAIL` из-за `12.50%` WAF Prot FPR) |
| `hardred-netids` | 100.0% / 100.0% / 0.0% / **98.3** | 100.0% / 75.0% / 0.0% / **86.2** | Kinetic XDP надёжно блокирует HTTP-флуд (`196/240`) и сканирование портов |
| `hardred-endpoint` | **93.3%** / **100.0%** / 0.0% / **94.2** | 33.3% / 50.0% / 0.0% / **51.9** | **Ущерб `8.6%` против `100.0%` у OSS** (OSS пропустил AES/storm ransomware и `memfd`) |
| `hardred-malware` | 100.0% / 100.0% / 0.0% / **95.6** | 100.0% / 100.0% / 0.0% / **96.7** | Блокировка BPF-LSM `MALWARE_DENIED_INODES` + шифрованный Vault AES-256-GCM |
| `hardred-compliance` | 100.0% / 86.0% / 0.0% / **86.0** | 100.0% / 80.0% / 0.0% / **80.0** | Индекс Lynis Hardening **`71`** (OSS `65`, Baseline `63`) |

- **Измеренная нагрузка (`GeDefense 6.2.1` против `OSS Best-of-Breed` и Baseline):**
  - **GeDefense Linux 6.2.1:** `523.3` HTTP RPS (`12.03 мс` p50 · `29.26 мс` p95) · `90,248.0` Sysbench EPS · `249.9` FIO IOPS · **`88.4 MiB`** Security RSS · **`4.3%`** Security CPU · Lynis `71`.
  - **OSS Best-of-Breed (`ModSec + Suricata + Tetragon + ClamAV`):** `452.4` HTTP RPS (`13.85 мс` p50 · `29.93 мс` p95) · `84,829.5` Sysbench EPS · `237.4` FIO IOPS · **`1,761.0 MiB`** Security RSS (`~20×` больше памяти) · **`57.3%`** Security CPU (`~13×` больше нагрузки на CPU) · Lynis `65`.

### Адаптивный многоэтапный бенчмарк (`VGT HardRed 1.2 / REDHARD ARES`)

| Система | ARES Design Resilience | ARES Runtime Resilience | ARES Adaptive Resilience | Прервано цепочек | Ø Pre-Kill Damage | Multi-Seed Ø (3 Seed × 3 раунда) | Ложные срабатывания |
|---|---:|---:|---:|---:|---:|---:|---:|
| **GeDefense Linux** | **68.20** | **96.68** | **93.46** | **36 / 36** | **11.1%** | **93.64** (σ = `0.0918`) | **0** |
| **Wazuh HIDS/SIEM** | 65.10 | 15.42 | 27.78 | 3 / 36 | 100.0% | 27.96 | 3 |
| **CrowdSec IPS/CTI** | 59.80 | 51.67 | 42.25 | 24 / 36 | 100.0% | 42.44 | 0 |

### 📂 Все артефакты и отчёты тестирования в репозитории

Полные scorecards, результаты всех 93 тестов (5 систем), отчёты SARIF, матрицы MITRE ATT&CK, OCSF и интерактивные HTML-панели доступны прямо в репозитории:
- 📁 **[Каталог результатов тестирования (`benchmarks/vgt-hardred-6.2.1/`)](benchmarks/vgt-hardred-6.2.1/)**
- 📄 **[Полный отчёт бенчмарка (`FINAL_BENCHMARK_REPORT.md`)](benchmarks/vgt-hardred-6.2.1/FINAL_BENCHMARK_REPORT.md)** · **[Таблица CSV](benchmarks/vgt-hardred-6.2.1/VGT_HardRed_Comparison.csv)** · **[Интерактивный HTML-дашборд](benchmarks/vgt-hardred-6.2.1/VGT_HardRed_Dashboard.html)**
- 🤖 **[Гибридный отчёт REDHARD ARES](benchmarks/vgt-hardred-6.2.1/ares/FINAL_ARES_HYBRID_REPORT.md)** · **[ARES CSV](benchmarks/vgt-hardred-6.2.1/ares/VGT_HardRed_ARES_Comparison.csv)** · **[ARES HTML-дашборд](benchmarks/vgt-hardred-6.2.1/ares/VGT_HardRed_ARES_Dashboard.html)**
- 🔎 **Исходные каталоги участников:** [`gedefense/`](benchmarks/vgt-hardred-6.2.1/gedefense/) · [`oss-stack/`](benchmarks/vgt-hardred-6.2.1/oss-stack/) · [`wazuh/`](benchmarks/vgt-hardred-6.2.1/wazuh/) · [`crowdsec/`](benchmarks/vgt-hardred-6.2.1/crowdsec/) · [`baseline/`](benchmarks/vgt-hardred-6.2.1/baseline/)

### ⚙️ Воспроизведение профиля `Max-Hardness`

Чтобы воспроизвести этот профиль защиты на Linux-хосте (по умолчанию после установки система запускается консервативно в режиме `observe` без принудительных блокировок):

1. **Параметр ядра LSM:** Убедитесь, что `bpf` активен в `/sys/kernel/security/lsm` (параметр загрузки `lsm=...,bpf` + перезагрузка), чтобы **Titan Exec Gate**, **LPE `socket_create`** и **Credential Guard `file_open`** подключились в ядре.
2. **Переход в `enforce`:** Переведите фазу `observe` → `canary` → **`enforce`** (`POST /api/v1/release/transition`: `PROMOTE:CANARY`, затем `PROMOTE:ENFORCE`) и зафиксируйте эталон FIM (`POST /api/v1/fim/baseline`, `"scope": "release"`).
3. **Настройки базовых модулей (`PUT /api/v1/settings/{module}`):**
   - `kinetic`: `enabled=true`, `enforcement_mode="block"`, `ip_threshold=20`, `velocity_limit=10`, `range_threshold=35`, `portscan_threshold=3`, `syn_threshold=15`, `syn_ack_ratio=3`, `auto_contain_single_ip=true`, `auto_contain_ipv4_subnet=true`, `auto_contain_ipv6_subnet=true`.
   - `l7`: `enabled=true`, `mode="block"`, `inline_enabled=true` (подключён NGINX `auth_request` / edge-сокет), `alert_score=30`, `block_score=70`, `sensitive_rate_per_minute=20`, `sensitive_rate_burst=5`, `client_rate_per_minute=180`, `client_rate_burst=40`, `tls_enabled=true`, `tls_anti_spoof=true`.
   - `xdr`: `enabled=true`, `network_sensor_enabled=true`, `behavior_enabled=true`, `alert_score=30`, `contain_score=60`, `kill_score=90`, `enabled_rule_modules=["baseline","command","lineage","masquerading","origin","threat-intel"]`, `advanced.malware_correlation=true`.
   - `titan` (FIM / Contraband): `mode="STRICT"`, `armed=true`, `auto_contain=true` (`POST /api/v1/titan/policy`).
   - `titan_exec` (6.2.0 ABI-2): `enabled=true`, **`mode="untrusted"`** (глобальный режим `4` — блокирует запуск из не-root / world-writable путей без вмешательства в системные пакеты), `require_ctime=true`.
4. **Настройки V6 и модулей A–E:**
   - `worker_guard`: `enabled=true`, `strict_exec=true`, `strict_mmap=true`, `auto_apply_strict=true`, `correlate_peers=true`, `storm_threshold=3`.
   - `tls_sensor`: `enabled=true`, целевые интерфейсы + `"lo"`, `ports=[443,8443,9843]`, `alert_only=false`.
   - `lpe_guard`: `enabled=true`, запрет `AF_PACKET`/`AF_TIPC`/`AF_VSOCK`/`SCTP`/`DCCP`/`RDS`, `styx_profile=true`, `enforce_aslr=true`, `block_lpe_modules=true` (`POST /api/v1/lpe-guard/apply`).
   - `styx`: `enabled=true`, глобально `mode="monitor"`, `log_flows=true`, плюс **`per_cell` `mode="enforce"`** на cgroup веб-воркеров (например `php8.3-fpm.service` по символическому `cgroup_path`) для блокировки несанкционированного исходящего C2-трафика.
   - `parser_cells`: `enabled=true`, `burn_on_incident=true`, `incident_score=60`; `lockdown`: `enabled=true`, `auto_arm=true`, `allow_loopback=true`, `drop_loopback=false`, `network_lockdown=true`, `freeze_processes=true`, `freeze_brokers=true` (`POST /api/v1/lockdown/arm`, `mode="locked"`); `threat_intel`: `enabled=true`, `auto_sync=true`.
5. **Профиль усиления CIS / Lynis:** Примените транзакционный sysctl-профиль **`astraeaos-cis-l1`** (`/api/v1/transactions/preview` → `/apply`, `type: "hardening.sysctl-profile"`) и при необходимости opt-in скрипт `gedefense-cis-baseline --apply` (SSHD drop-in, `UMASK 027`, баннеры, чёрный список модулей и правила auditd).

> [!NOTE]
> **Зависимость от среды и инженерная прозрачность (`6.2.0 → 6.2.1`):** Показатели бенчмарка зависят от версии ядра Linux и параметров LSM (`lsm=...,bpf`), производительности CPU/диска, топологии сети и исключений нагрузок. Выявленные в первых прогонах пробелы системно устранены в ветке `6.2.0 → 6.2.1`: помимо базы `6.2.0`, в `6.2.1` добавлены блокировка вредоносных inode в BPF-LSM (`MALWARE_DENIED_INODES` + `CORE_QUARANTINE_ALLOWED_ROOTS`), ядерные поведенческие XDR-сенсоры (`EXEC_ARGV_EVENTS`, `KERNEL_PROBE_EVENTS`, kretprobe `getname_flags` и multi-CPU tracepoints в `aya`), уточнённые пороги ransomware (`15→6` / `25→18`) с изоляцией рабочих процессов сервис-пулов по PPID (`RANSOM_TRUST_POOL_METADATA`), фильтрация внутренних/локальных потоков в StyX (`isIgnoredNonExternalFlow`) и асинхронный `ChronosScanner`.

---

<img width="1536" height="1024" alt="GeDefense_ Real Security, Many Feathers" src="https://github.com/user-attachments/assets/dc56735e-b2b2-45c9-a363-97554a92ae0a" />

## 🌐 Вселенная GeDefense

GeDefense — единая локальная security-fabric для Linux, Windows, Android и WordPress. Все родственные проекты разделяют одну философию: локальный контроль, честная видимость, никакой скрытой телеметрии.

| Проект | Направление |
| --- | --- |
| [![Android TV](https://img.shields.io/badge/Android_TV-3DDC84?style=flat-square&logo=android&logoColor=0B1220)](https://github.com/visiongaiatechnology/gedefense_androidtv) **GeDefense TV** | Консоль безопасности для Android TV / Google TV: loopback-VPN, карта трафика, XDR-Light и обратимое сдерживание Kinetic-Lite. |
| [![Linux](https://img.shields.io/badge/Linux-D4AF37?style=flat-square&logo=linux&logoColor=0B1220)](https://github.com/visiongaiatechnology/gedefense) **GeDefense Linux** *(этот репозиторий)* | Сетевая защита на уровне ядра: применение eBPF/XDP, L7-WAF, host-XDR с подписанными доказательствами и обратимое усиление (Rust/Go, полностью локально). |
| [![Windows](https://img.shields.io/badge/Windows-8B5CF6?style=flat-square&logo=windows&logoColor=ffffff)](https://github.com/visiongaiatechnology/gedefensewin) **GeDefense Windows** | Локальная суверенная консоль безопасности Windows 11: Defender/ASR/WFP/App Control, усиление, MHX EDR/XDR, локальный threat intelligence и HMAC-цепочка доказательств. |
| [![Android](https://img.shields.io/badge/Android-22D3EE?style=flat-square&logo=android&logoColor=0B1220)](https://github.com/visiongaiatechnology/gedefenseandroid) **GeDefense Android** | Нативная платформа безопасности Android: локальное VPN-принуждение, телеметрия конечных точек, корреляция XDR/EDR, threat intelligence, анализ рисков приложений и зашифрованные доказательства. |
| [![WordPress](https://img.shields.io/badge/WordPress-1F8FFF?style=flat-square&logo=wordpress&logoColor=ffffff)](https://github.com/visiongaiatechnology/gedefensewp) **GeDefense WordPress** | Open-core набор AGPL-3.0 для WordPress: ZEUS WAF, глубокая проверка пакетов AEGIS, TRINITY XDR, блокировка ThroneGuard и маскировка админки HADES. |

---

## 🏛️ Архитектура безопасности и техническая спецификация

> [!IMPORTANT]
> **Для исследователей безопасности, системных архитекторов и аудиторов:**
> GeDefense поддерживает полную формальную спецификацию технической архитектуры, модель границ доверия и древовидную структуру данных символов:
> 
> ### ➔ [📘 ARCHITECTURE.md — Полная техническая архитектура и спецификация](ARCHITECTURE.md)
> 
> *Более 4400 строк с подробным описанием 7-уровневого дерева архитектуры, плоскости данных eBPF/XDP в ядре, плоскости управления Go, типизированного ядра реагирования на Rust, встроенного L7 WAF, криптографического реестра доказательств и обратимого движка харденинга.*

---

## 🧪 Verify Yourself — Полный набор тестов и руководство по независимому аудиту

> [!TIP]
> **«Не доверяй, проверяй» (Don't Trust, Verify) — Полная прозрачность и воспроизводимость**
> GeDefense спроектирован для сред с нулевым доверием (Zero Trust). Каждое архитектурное обещание, граница доверия, парсер, криптографический инвариант и фильтр уровня ядра eBPF/XDP подкреплены автоматизированным набором тестов. Вы можете локально запустить все **634+ нативных тестовых функции** и **19 шлюзов безопасности** с помощью одной команды.

### 📊 Обзор наборов тестов и покрытие

| Набор тестов / Компонент | Расположение | Тесты / Сценарии | Проверяемые возможности и гарантии | Команда прямого запуска |
| :--- | :--- | :---: | :--- | :--- |
| **Модульные и интеграционные тесты Control Plane** | [`control/*_test.go`](control/) | **574 теста**<br>*(108 файлов + 25 субтестов)* | Корреляция XDR DAG, многопроходное декодирование L7 WAF, базовые линии SHA-256 FIM, шлюзы релиза fail-closed, ротация журналов при пороге 90%, обновления self-artifact | `cd control && go test -v ./...` |
| **Набор фаззинг-тестирования безопасности** | [`control/*fuzz_test.go`](control/) | **8 фаззинг-целей** | Безопасность памяти и устойчивость к паникам: нормализатор L7, TLS ClientHello, зашифрованные конверты, ответы Core IPC, `/proc/stat` | `make fuzz-smoke` |
| **Периметр и аутентификация Gateway** | [`gateway/*_test.go`](gateway/) | **28 тестов**<br>*(6 файлов)* | Постквантовые кривые TLS 1.3 ML-KEM, проверка паролей Argon2id, изоляция cookie `__Host-`, токены синхронизации CSRF, очистка заголовков | `cd gateway && go test -v ./...` |
| **Сетевой протокол и плоскость данных ядра Rust** | [`rust/gedefense-common`](rust/gedefense-common/) | **6 тестов** | Парсинг сетевых заголовков zero-copy, границы IPv4/IPv6 VLAN/QinQ, декодеры сетевых событий | `cargo test --locked --manifest-path rust/Cargo.toml -p gedefense-common` |
| **Привилегированное ядро реагирования на Rust** | [`rust/gedefense-core`](rust/gedefense-core/) | **18 тестов** | LRU/вытеснение Replay-Guard, контракт sysctl compare-and-set, потоковый сканер малвари (Polyglot/EICAR), хранилище карантина AES-256-GCM | `cargo test --locked --manifest-path rust/Cargo.toml -p gedefense-core` |
| **Автоматизированный аудит безопасности** | [`scripts/security-audit.sh`](scripts/security-audit.sh) | **19 шлюзов аудита** | Отсутствие небезопасных приемников DOM (`innerHTML`, `eval`), строгий CSP, синхронизация ключей I18N на 4 языках, права доступа сокетов (`0700`/`0600`) | `bash scripts/security-audit.sh` |
| **Нагрузочные тесты Kinetic Wire-Speed** | [`scripts/validate-kinetic-release-candidate.sh`](scripts/validate-kinetic-release-candidate.sh) | **Пакет** | Тестирование всплесков входящего трафика, скользящие окна телеметрии, бенчмарк сброса LPM Trie | `bash scripts/validate-kinetic-release-candidate.sh` |
| **Интеграция с дистрибутивами Linux** | [`scripts/validate-distro-integration.sh`](scripts/validate-distro-integration.sh) | **Пакет** | Проверка совместимости с дистрибутивами (контракты systemd для Arch, Debian, Fedora, SUSE) | `bash scripts/validate-distro-integration.sh` |
| **DAC и права доступа карантина** | [`scripts/validate-quarantine-dac.sh`](scripts/validate-quarantine-dac.sh) | **Пакет** | Проверка исключительных прав root, флагов запрета исполнения, защит от обхода путей | `bash scripts/validate-quarantine-dac.sh` |
| **Проверка песочницы Systemd** | [`scripts/validate-systemd.sh`](scripts/validate-systemd.sh) | **Пакет** | Проверка `DynamicUser`, `ProtectSystem=strict` и сброса привилегий во всех сервисах | `bash scripts/validate-systemd.sh` |
| **Паритет четырехъязычной локализации I18N** | [`scripts/validate-i18n.mjs`](scripts/validate-i18n.mjs) | **Пакет** | 100% синхронизация ключей переводов для DE, EN, RU и ZH-CN | `node scripts/validate-i18n.mjs` |

### ⚡ Быстрый старт: запуск тестов на локальной машине

```bash
# 1. Запустить все тесты Go, статический анализ, проверку синтаксиса JS и аудит безопасности
make test

# 2. Запустить тесты Go с детектором состояния гонки (Race Detector)
make test-race

# 3. Запустить все нативные тесты Rust (Kernel Common и Response Core)
cargo test --locked --manifest-path rust/Cargo.toml -p gedefense-common -p gedefense-core

# 4. Запустить 8 фаззинг-тестов безопасности Go
make fuzz-smoke

# 5. Запустить полный скрипт статического аудита безопасности
bash scripts/security-audit.sh

# 6. Запустить полную сквозную валидацию репозитория
bash scripts/validate.sh
```

> 📖 **Формальный план бета-тестирования:** Полную матрицу эксплуатационных тестов (Observe, Canary, Enforce, AstraeaOS) см. в [**BETA-TEST-PLAN.md**](BETA-TEST-PLAN.md).

---

### Обзор 7-уровневой суверенной фабрики обороны

```text
1. ШЛЮЗ ОБЩЕГО ДОСТУПА        Go · Порт 9843 (TLS 1.3, гибрид ML-KEM PQ, Argon2id, синхротокены CSRF)
2. ДАШБОРД ЦЕНТРА УПРАВЛЕНИЯ   ESNext / Vanilla JS / Нативный CSS · 0 зависимостей · усиленный CSP
3. ПЛОСКОСТЬ УПРАВЛЕНИЯ        Go · Порт 9844 (только Loopback · XDR, L7 WAF, FIM, реестр доказательств, кейсы)
4. ПРИВИЛЕГИРОВАННОЕ ЯДРО      Rust · /run/vgt-gedefense/core.sock (HMAC VGT3, pidfd_open, sysctl CAS, fanotify)
5. ПЛОСКОСТЬ ДАННЫХ В ЯДРЕ     Rust no_std eBPF/XDP + cgroup-skb + LSM (LPM Trie 250k правил, RingBuf EDR)
6. ИНТЕГРАЦИОННАЯ СРЕДА        Universal Linux (APT/DNF/pacman/Zypper) · AstraeaOS Native Ring-1 Cells
7. РЕЛИЗНАЯ ИНЖЕНЕРИЯ          Toolchains.lock · Воспроизводимые сборки · Криптографические манифесты
```

### Базовые инварианты безопасности
- **Без облачной панели управления:** Разведка угроз, поведенческие профили, рабочие ключи и криминалистические улики на 100% остаются на локальном хосте.
- **Плоскость данных на скорости ядра:** Входящие сетевые атаки отсекаются на уровне сетевого драйвера с помощью Rust eBPF/XDP до выделения сокетного буфера (`sk_buff`).
- **Нативный уровень L7 (Только стандартная библиотека Go):** Ограниченная нормализация HTTP, декодирование попыток обхода и RE2-сканирование регулярных выражений без сторонних зависимостей, без CGO и без сторонних сред выполнения скриптов.
- **Барьер изоляции веб-улик:** Веб-события маркируются как `AlertOnly: true` (`ResponseScore: 0`). Событие веб-уровня никогда не может автономно инициировать завершение процессов на уровне хоста (`SIGKILL`/`SIGSTOP`); деструктивная изоляция строго требует независимых свидетельств ядра/хоста.
- **Криптографический реестр доказательств:** Защищенная от модификации монотонная последовательность с хешированием предшественников (`AES-256-GCM` + `Ed25519`).
- **Обратимое ужесточение sysctl:** Атомарная операция compare-and-set с проверкой чтения из ядра и автоматическим откатом при частичном сбое.

---

## 🔍 Что такое VGT GeDefense?

GeDefense — это не просто менеджер правил брандмауэра. Это **локальная суверенная фабрика безопасности Linux** — сетевая защита на уровне ядра, хостовый XDR, зашифрованный реестр доказательств, обратимое ужесточение системы и нативная изоляция AstraeaOS в едином комплексе, работающем полностью автономно без облачной инфраструктуры.

```
Традиционные стеки безопасности Linux:
  Разрозненные утилиты (iptables + auditd + fail2ban) → нет общего состояния
  Конфигурация на доверии                             → правила применяются сразу
  Отсутствие цепочки доказательств                    → инциденты недоказуемы
  Нет возможности отката                              → изменения харденинга необратимы
  Облачные SIEM / панели управления                   → данные покидают сервер

VGT GeDefense:
  Плоскость данных Rust eBPF/XDP          → в ядре, до 250 000 блокировок
  Плоскость управления Go (XDR, FIM)      → отделенный домен доверия, только loopback
  Ядро реагирования Rust (pidfd, SIGKILL) → проверка брокером перед любым сигналом
  Разделенные домены доверия              → Public Gateway · Control · Core · Data Plane
  Реестр доказательств с Ed25519          → монотонная цепочка + хеш предшественника
  Базовые линии FIM с AES-256-GCM         → fail-closed при нарушении целостности
  Обратимое ужесточение параметров        → compare-and-set, атомарность, авто-откат
  Зашифрованное хранилище карантина       → изоляция с идентификатором SHA-256
  Без облачной панели управления          → конфиденциальные данные не покидают сервер
  Универсальный Linux                     → интеграция с APT · DNF/YUM · pacman · Zypper
  Нативная поддержка AstraeaOS            → единая проверенная цепочка безопасности
```

Ни одно единичное срабатывание сигнатуры, фида или поведенческой эвристики **не может авторизовать завершение процесса**. Применение мер (Enforce) требует как минимум двух независимых категорий подтверждения, объективных доказательств и стабильного состояния системы.

### 🛡️ Полный стек возможностей V6.2.1 и модули A–E

Все подсистемы используют разделённые домены доверия, единый REST API и панели управления. В `observe`/`canary` блокировки V6 выключены; при переходе в `enforce` автоматически включается безопасный базовый профиль (`styx=monitor`, `titan_exec=contain`, `parser_cells=enabled`), а более строгие режимы (**Emergency Lockdown**, **Witness**, `titan_exec=untrusted`, `per_cell` StyX `enforce` и CIS userland-база) включаются администратором явно:

- **Модули A–E (веб- и периметровая защита):**
  - **Модуль A — Web Exposure & Posture:** Обнаруживает веб-демоны через `/proc/<pid>/exe` ELF `.rodata` в режиме read-only (без `os/exec`), разбирает конфиги NGINX/Apache, выполняет ограниченный loopback-ALPN-зонд и показывает CVE только при реальной достижимости.
  - **Модуль B — Worker Integrity Guard:** Следит за падениями веб-воркеров (`SIGSEGV`/`SIGBUS`/`SIGILL`/`SIGABRT`, tracepoint `signal:signal_deliver` + fallback на `CN_PROC`), поднимает шторм ≥ 3 за 60 с до `XDR.WORKER_CRASH_STORM` и изолирует cgroup воркеров (`JIT_ALLOW = 0`) с исключением master/control-юнитов.
  - **Модуль C — TLS/ALPN-сенсор и бюджет h2 control-storm:** Пассивный захват `AF_PACKET` через отдельный `gedefense-capture-helper.service` + счётчики сокетов ядра `INET_DIAG`, отличающий HTTP/2-штормы от легитимных крупных загрузок.
  - **Модуль D — LPE Kill-Chain Blocker:** BPF-LSM хук `socket_create` запрещает `AF_PACKET`, `AF_TIPC`, `AF_VSOCK`, `SCTP`, `DCCP` и `RDS` для cgroup веб-воркеров вкупе с ASLR и блокировкой модулей ядра.
  - **Модуль E — Memory-Safe Edge Terminator:** Опциональный Go `crypto/tls` + `net/http` терминатор с жёсткими лимитами RFC-9113, структурным WAF (SQL-нормализация, сканер секретных конфигов, проверка raw-body `POST`/`PUT`, быстрый проход `780 KB–1.5 MB`, детерминированный `429 + Retry-After`) и HTTP/1.1 upstream.
- **Ядро и хостовый XDR (пункты 1–5 + V6.2):**
  - **Titan Exec Gate (ABI-2) и защита от подмены файлов GeDefense Titan:** Контроль `bprm_check_security` / `mmap_file(PROT_EXEC)` в режимах `contain` и глобальном `untrusted` (`4`) для не-root и world-writable путей (`memfd_create`, `/tmp`, `/dev/shm`); модуль Titan контролирует неавторизованное размещение/подмену файлов через bounded inotify, FIM-базы и владение пакетами `dpkg`/`pacman` (`AUTHORIZED`/`TOLERATED`/`UNEXPECTED`/`COMPROMISED`) без атрибуции лиц и с обратимым шифрованным карантином AES-256-GCM.
  - **eBPF-сенсор ransomware и уничтожение дерева процессов:** Kprobes `vfs_write`/`vfs_rename`/`vfs_unlink` отслеживают всплески энтропии и rename-штормы; ядро Rust на `100 мс`-тике замораживает PGID обратимым `SIGSTOP` (с исключением `apt`, `dpkg`, `tar`, `cargo`), после чего Control выполняет `pidfd`-проверенный `XDR_KILL_TREE` или отпускает по `GROUP_CONT`.
  - **Асинхронный on-write сканер вредоносного ПО и архивов:** `FAN_CLOSE_WRITE`-наблюдатель на `/tmp`, `/var/tmp`, `/dev/shm` и `/var/www` (`PrivateTmp=false`, ограниченный рекурсивный разбор ZIP/GZIP/TAR до глубины 8 / `16 MiB` проба) с карантином под fd-блокировкой SHA-256.
  - **BPF-LSM Credential Guard:** Хук `file_open` защищает `/etc/shadow`, `/etc/gshadow` и файлы секретов (разрешённый список для `sshd`, `sudo`, `su`, `login`, `cron`, `passwd`, `useradd`/`usermod`/`groupadd`), никогда не блокируя вход при неактивном состоянии.
  - **StyX Egress, обнаружение C2-маяков и 16 MiB Flow-телеметрия:** Символические пути `cgroup_path` с перерасчётом cgroup2-inode после перезапуска (`degraded` при дрейфе вместо тихого fail-open), буфер `FLOW_EVENTS` 16 MiB и раздельная индикация `enforcement_active` vs. `telemetry_state`.
  - **Эфемерные Parser Cells (`gedefense-cell-helper.service`), Witness и Emergency Lockdown:** Одноразовые песочницы пространств имён/seccomp (`VGTGC2`), внешние Ed25519-чеки, мгновенный XDP/TC drop-latch и блокировка составных BadUSB-устройств (`HID+Storage`/`HID+CDC`).
- **Мастер настройки (`00`–`08`) и офлайн-шаблон `AGENTS.md`:** Пошаговый мастер в Web UI и read-only-first `AGENTS.md` для локальных CLI-агентов по SSH (`POST /api/v1/settings/{module}/preview` → `PUT`) — без входящего AI-API.

### 💻 Настольный ПК / Рабочая станция vs. 🖥️ Linux-сервер — что защищает V6.2

| Среда | Ключевые угрозы | Активные механизмы при `enforce` |
|---|---|---|
| **Linux ПК / Рабочая станция** | Zero-click уязвимости парсеров, составные BadUSB-импланты, дамп ключей брокеров, беcфайловая нагрузка (`memfd`/`PROT_EXEC`), тихие C2-маяки | **Parser Cells** изолируют парсинг; **Lockdown** блокирует BadUSB и замораживает брокеры; **StyX (`monitor`)** выявляет маяки; **Titan Exec (`contain`/`untrusted`)** контролирует опасные пути запуска |
| **Linux-сервер (Web / API / Compute)** | L7 SQLi/RCE/веб-шеллы, исходящие C2/утечки из веб-cgroup, дропы в `/tmp`/`/var/www`, шифровальщики, чтение `/etc/shadow` | **L7 Edge/WAF + Kinetic XDP** отбивают сетевой/HTTP-флуд и инъекции; **StyX (`per_cell enforce`)** обрывает egress воркеров; **Titan Exec + Ransomware + On-Write + Credential Guard** пресекают пост-эксплуатацию; **Witness** фиксирует контрольные точки вовне |

> [!WARNING]
> **СТАТУС РЕЛИЗА И КВАЛИФИКАЦИИ (Версия 6.2.1 / V6).**  
> GeDefense V6 активно развивается для тестовых и квалификационных сред. Автоматизированные гейты проверяют воспроизводимость сборки, подписи Ed25519, тесты Go/Rust и статические инварианты безопасности; внешние якоря доверия (публичный CA, RFC3161, CRL/OCSP, инфраструктура подписи фидов) и проверка eBPF-верификатора/NIC XDP остаются обязательным этапом квалификации на целевом хосте. Перед включением `enforce` в продакшене изучите [SECURITY.md](SECURITY.md), [RELEASE-NOTES.md](RELEASE-NOTES.md) и [CHANGELOG.md](CHANGELOG.md).

---

<img width="2560" height="1229" alt="image" src="https://github.com/user-attachments/assets/1f5cf6ae-ee59-498d-9c5b-e06e8efc9ef2" />


## 🏛️ Архитектура

```
┌──────────────────────────────────────────────────────────────┐
│                    PUBLIC ACCESS GATEWAY                      │
│   Go · TLS 1.3 · Argon2id · Host/Origin/CSRF · Сессии        │
│   непривилегированный · Порт 9843 (настраиваемый 1024–65535) │
├──────────────────────────────────────────────────────────────┤
│                      CONTROL PLANE                            │
│   Go · XDR · Политики · Телеметрия · FIM · Улики · Кейсы     │
│   пользователь: gedefense · только loopback (TCP 9844)       │
├──────────────────────────────────────────────────────────────┤
│                      RESPONSE CORE                            │
│   Rust · VGT3 IPC · pidfd · Карантин · Мутации sysctl        │
│   UID 0 · Ограничение привилегий · Аутентификация HMAC IPC   │
│   /run/vgt-gedefense/core.sock                               │
├──────────────────────────────────────────────────────────────┤
│                       DATA PLANE                              │
│   eBPF/XDP · IPv4/IPv6 · Белые/черные списки LPM на сетевой  │
│   Ядро/XDP · до 250 000 блокировок                           │
└──────────────────────────────────────────────────────────────┘
```

<img width="2560" height="1229" alt="image" src="https://github.com/user-attachments/assets/0712a990-f3ad-4b4a-8d18-8e0a60395fe1" />


### Разделение доменов доверия

| Домен | Роль | Привилегии |
|---|---|---|
| **Public Gateway** | TLS 1.3, Argon2id, Host/Origin/CSRF, аутентификация сессий | Непривилегированный |
| **Control Plane** | XDR, политики, телеметрия, FIM, улики, кейсы, дашборд | Пользователь `gedefense` |
| **Response Core** | Карты XDP, реакция pidfd, карантин, мутации sysctl | UID 0, Capability Bounding |
| **Data Plane** | Разбор IPv4/IPv6, списки LPM на сетевом интерфейсе | Ядро / XDP |

### Режимы развертывания

**Universal Linux** — Установка в один клик на x86_64 systemd Linux с APT, DNF/YUM, pacman или Zypper. Ядро Rust и программы eBPF компилируются для конкретного ядра и сетевой карты, затем верифицируются перед атомарной активацией.

**AstraeaOS-native** — Идентичные исполняемые файлы, нативное развертывание, профиль ужесточения AstraeaOS, подтверждение доверенной загрузки и интеграция с Gaia Cells. GeDefense является **единственным органом безопасности** в AstraeaOS.

---

<img width="2560" height="1229" alt="image" src="https://github.com/user-attachments/assets/57feccc5-75ab-46a1-a575-3a5ec3402087" />


## 🛡️ Фабрика защиты

### Сетевая защита (Rust eBPF/XDP)

| Функция | Детали |
|---|---|
| **Data Plane** | Rust eBPF/XDP — нативный XDP с переходом на Generic-XDP |
| **Протоколы** | IPv4 и IPv6 |
| **Сопоставление** | LPM Tries — Longest Prefix Match |
| **Емкость** | До 250 000 записей блокировки |
| **Белый список управления** | Применяется до черного списка — доступ администратора всегда гарантирован |
| **Правила CIDR** | Подписаны с указанием TTL |
| **Автоприменение фидов** | По умолчанию отключено — публичные фиды требуют явного одобрения |
| **Проверка пустоты** | Авторитетная проверка `VERIFY_EMPTY` — отсутствие скрытых остаточных правил |

### Хостовый XDR

| Функция | Детали |
|---|---|
| **Сигналы** | Процессы, команды, происхождение, маскировка, сеть, аналитика угроз |
| **Профили** | Адаптивные, с ограничением кардинальности на процесс |
| **Пользовательские правила** | Регулярные выражения RE2 — строго только оповещение (Alert-only) |
| **Многосигнальные гейты** | Обязательные доказательства перед любой эскалацией мер |
| **Идентификация процессов** | Привязка PID + pidfd — защита от гонок повторного использования PID |
| **Реакция Canary** | Остановка процесса (SIGSTOP) после проверки доказательств |
| **Реакция Enforce** | Завершение процесса (SIGKILL) только после авторизации брокером |

**Лимиты XDR по умолчанию**

| Параметр | Значение |
|---|---|
| Интервал сканирования процессов | 750 мс |
| Проверка сети / целостности | 3 с / 3 с |
| Пороги Alert / Contain / Kill | 40 / 80 / 120 |
| Потоки / Очередь | 4 / 2 048 |
| Оценок за сканирование | 4 096 |
| Максимальный размер лога инцидентов | 64 МиБ |

### Доказательства и целостность

| Функция | Детали |
|---|---|
| **Реестр доказательств** | Зашифрован + подписан Ed25519 |
| **Структура цепочки** | Монотонная последовательность + хеш предшественника |
| **Защита от усечения** | Отдельная контрольная точка заголовка (Head Checkpoint) |
| **Базовые линии FIM** | Защищены AES-GCM |
| **Обход каталогов** | Ограниченный + потоковый SHA-256 |
| **Проверки безопасности** | Проверка состояния гонок, симлинков и прав доступа |
| **Нарушение целостности** | Fail-closed — немедленная блокировка без скрытой деградации |

### Кейсы и транзакции

| Функция | Детали |
|---|---|
| **Корреляция кейсов** | Зашифрованные контексты расследований |
| **Повторяемость** | Обработка повторных инцидентов с фиксацией в реестре |
| **Процесс ужесточения** | Предпросмотр → Авторизация → Применение |
| **Процесс аудита** | Верификация → Аудит → Откат |
| **Запуск демона** | Сверка состояния — изоляция дрейфа вместо перезаписи |

---

## 🔒 Эксплуатационная безопасность — Гейты продвижения

```
Observe ──→ Canary ──→ Enforce
   │            │           │
   │       Проверка      Подписанные CIDR
   │       улик и        + синхронизация
   │       SIGSTOP        белого списка
   │
 XDP активен, правил блокировки нет
 проверенное пустое состояние ядра
```

| Состояние | Сеть | Реакция на процессы | Условие перехода |
|---|---|---|---|
| **Observe** | XDP активен, правил блокировки нет | Запись событий | Проверенное пустое состояние ядра |
| **Canary** | Наблюдение продолжается | Проверенный SIGSTOP | Прохождение гейтов политик и стабильности |
| **Enforce** | Подписанные правила CIDR | Проверенный брокером SIGKILL | Синхронизированный белый список управления |
| **Degraded** | Безопасный отказ | Активная реакция приостановлена | Требуется вмешательство оператора |

**Последовательность аварийной остановки:** Деактивация реагирования → удаление правил блокировки → подтвержденная проверка `VERIFY_EMPTY` → сохранение подписанной политики Observe → только после этого статус очищен. Никакие промежуточные ошибки не маскируются.

---

## 🔐 Криптография

| Назначение | Метод | Профиль |
|---|---|---|
| **Пароль оператора** | Argon2id | 64 МиБ · t=3 · p=1 · 128-битная соль · 256-битный вывод |
| **Control ↔ Core IPC** | HMAC-SHA-256 | 32-байтный ключ · временное окно · нонс · кэш повторов · SO_PEERCRED |
| **Оперативное хранилище** | AES-256-GCM | Случайные нонсы · разделенные подключи · связывание AAD |
| **Политики / Улики** | Ed25519 | Локальная подпись и проверка |
| **Идентификация данных** | SHA-256 | Потоковый хеш с повторной проверкой |
| **Шлюз доступа** | TLS 1.3 | Локальный или предоставленный сертификат |

Контекст AAD: схема · узел · назначение · канонический путь · последовательность.
Устаревший PBKDF2 принимается только для миграции — автоматически обновляется до Argon2id при успешном входе.

### Защита браузера и API

| Мера безопасности | Статус |
|---|---|
| Отсутствие внешних зависимостей (CDN, трекеры, шрифты) | ✓ |
| Отсутствие динамических вставок HTML и eval | ✓ |
| Строгий заголовок CSP и запрет фреймов | ✓ |
| Синхронизирующие токены CSRF + строгая проверка Origin | ✓ |
| Флаги Secure, HttpOnly, SameSite=Strict для cookie | ✓ |
| Внедрение токена Bearer на стороне сервера | ✓ |
| Защита от повторов (Request-ID, TTL) | ✓ |
| Загрузка фидов по HTTPS с защитой от DNS Rebinding и SSRF | ✓ |
| Нативный L7/AppSec с ограниченной нормализацией | ✓ |
| Реализация L7 не добавляет внешних зависимостей | ✓ |
| Запрет выполнения внешних команд в сервисах Go | ✓ |
| Бэкенд слушает исключительно интерфейс loopback | ✓ |

**Конфиденциальное состояние и ключи никогда не покидают защищаемый хост.**

---

## 🔧 Обратимое ужесточение (Hardening)

Профили: `Generic Linux Server` и `AstraeaOS Workstation` — фиксированный белый список параметров.

Параметры ядра изменяются через compare-and-set, проверяются чтением и атомарно сохраняются в `/etc/sysctl.d/90-vgt-gedefense.conf`.

Ядро Rust **не предоставляет общего командного интерфейса к оболочке или файловой системе**. Ошибки применения параметров вызывают автоматический откат в обратном порядке.

### Зашифрованное хранилище карантина (Response Vault)

| Функция | Детали |
|---|---|
| **Шифрование** | AES-256-GCM |
| **Размер блока** | 1 МиБ |
| **Макс. размер файла** | 256 МиБ |
| **Идентификатор** | SHA-256 + полные атрибуты файла |
| **Захват** | Атомарный — с проверкой восстановления |
| **Защита от симлинков** | openat2, O_NOFOLLOW |
| **Права доступа** | root:gedefense 0700 — без CAP_DAC_OVERRIDE |

---

## 🐧 Универсальная интеграция с Linux

| Уровень | Интеграция Beta v4 |
|---|---|
| Пакетные менеджеры | APT · DNF/YUM · pacman · Zypper |
| Инициализация | Защищенные юниты systemd с контролем синтаксиса и времени выполнения |
| Границы привилегий | Хелпер готовности с областью действия Polkit — без общего root-доступа |
| Десктоп | Изолированный профиль Chromium с точной фиксацией SPKI сертификата |
| Идентификация TLS | Имя хоста плюс SAN-адреса `localhost`, `127.0.0.1` и `::1` |
| Релизный CI | Тесты Go на гонки/фаззинг/безопасность · ядро Rust · eBPF · хеши артефактов |
| Контракты дистрибутивов | Ubuntu/Debian · Fedora/RHEL · Arch · openSUSE |
| Квалификация хоста | bpffs · видимость eBPF верификатором · NIC XDP · IPC · TLS |

Контейнеры дистрибутивов валидируют переносимость упаковки. Они не квалифицируют ядро хоста. Каждый бинарный релиз требует обязательного тестирования на конкретном целевом ядре, драйвере и сетевом интерфейсе.

---

## 🌐 Интеграция с AstraeaOS

| Возможность | Статус |
|---|---|
| Нативное развертывание / systemd | ✅ Реализовано — единая цепочка безопасности |
| Зеркало исходных кодов GeDefense | ✅ Реализовано — проверка манифеста SHA-256 |
| Профиль ужесточения AstraeaOS | ✅ Реализовано — обратимый и персистентный |
| Свидетельства доверенной загрузки | ✅ Реализовано — только доказательства, без ложных утверждений |
| Адаптер Gaia Cells VGTGC1 | ✅ Реализовано — среда выполнения опциональна |
| Привязка к UUID / поколению / cgroup ID | ✅ Реализовано — неизменяемая привязка действий |
| Заморозка / сетевой откат | ✅ Реализовано — транзакция с фиксацией доказательств |
| Демон жизненного цикла Gaia Cells | — Не входит в состав — поддерживается AstraeaOS |
| Изолированная служба дезориентации | — Отложено — вне рамок текущей бета-версии |

Действия над ячейками жестко привязаны к UUID, поколению жизненного цикла и идентификатору cgroup ядра. Проверяются UID пира, HMAC, временное окно и нонс.

Если среда выполнения Gaia Cells **отсутствует**, адаптер возвращает статус `runtime_not_installed`. Базовая защита хоста продолжает работать в штатном режиме.

> **Единый центр управления:** В AstraeaOS система GeDefense является единственным авторитетным органом безопасности. Sentinel используется исключительно для миграции и аудита.

---

## ⚙️ Требования к среде выполнения

### Системные требования (Автономный режим)

| Требование | Значение |
|---|---|
| **ОС** | Linux |
| **Архитектура** | x86_64 / amd64 |
| **Система инициализации** | systemd |
| **Ядро** | Поддержка BPF/XDP + pidfd |
| **Пакетный менеджер** | apt-get, dnf/yum, pacman или zypper |
| **Установка** | Права root + доступ в интернет для компиляции |
| **Библиотека шлюза** | libargon2.so.1 |

> Для текущей версии не объявляется универсальная минимальная версия ядра. Целевой хост квалифицируется в процессе сборки, проверки верификатором ядра, подключения XDP и гейтов работоспособности.

### Зафиксированные версии тулчейна

| Компонент | Версия |
|---|---|
| **Go** | 1.27.4 |
| **Rust Core** | 1.97.1 |
| **Rust eBPF** | nightly-2026-07-16 |
| **Компонент Rust** | rust-src |
| **bpf-linker** | 0.10.3 |
| **Разрешение зависимостей** | `Cargo.lock --locked` |

### Сетевые интерфейсы и сокеты

| Интерфейс | По умолчанию | Доступность |
|---|---|---|
| **Шлюз HTTPS** | TCP 9843 | Административный / публичный — диапазон 1024–65535 |
| **Бэкенд управления Go** | TCP 9844 | Только интерфейс loopback |
| **IPC ядра Rust** | `/run/vgt-gedefense/core.sock` | HMAC-VGT3 + SO_PEERCRED |
| **API инспекции L7** | `/run/vgt-gedefense-l7/inspect.sock` | Локальный Unix-сокет · ограничение по ресурсам · SO_PEERCRED |
| **Встроенный шлюз L7** | `/run/vgt-gedefense-l7/edge.sock` | Опциональная граница локального обратного прокси |
| **Gaia Cells** | `/run/gaia-cells/control.sock` | Опционально — протокол VGTGC1 |
| **Фиды угроз** | Исходящий HTTPS | Опционально — только публичные IP |

### Структура каталогов

| Путь | Назначение |
|---|---|
| `/opt/vgt/gedefense/releases/<версия>` | Неизменяемый релиз |
| `/opt/vgt/gedefense/current` | Атомарный симлинк активного релиза |
| `/etc/vgt/gedefense/` | Конфигурация, сертификаты TLS и секреты |
| `/var/lib/vgt/gedefense/` | Зашифрованное рабочее состояние |
| `/var/lib/vgt/gedefense/quarantine/objects` | Зашифрованное хранилище Response Vault |
| `/run/vgt-gedefense-l7/` | Временные Unix-сокеты L7 |
| `/sys/fs/bpf` | Файловая система BPF |
| `/var/log/vgt-gedefense-install.log` | Лог установки — права 0600 |

---

## 🚀 Быстрый старт

```bash
# Загрузить инсталлятор
wget https://github.com/visiongaiatechnology/gedefense/releases/download/v6.2.1/VGT_GeDefense_V6_6.2.1_OneClick.run

# Проверить SHA-256
sha256sum --check VGT_GeDefense_V6_6.2.1_OneClick.run.sha256

# Установить (требуются права root)
chmod 700 VGT_GeDefense_V6_6.2.1_OneClick.run
sudo ./VGT_GeDefense_V6_6.2.1_OneClick.run
```

> **Доступность инсталлятора:** Официальные автономные установочные ассеты v6.2.1 (`VGT_GeDefense_V6_6.2.1_OneClick.run` и `GeDefense-6.2.1-Desktop-OneClick.run`) публикуются вместе с подписанным GitHub Release.

> Инсталлятор и контрольные суммы публикуются только после успешного прохождения всех этапов GitHub CI и квалификационных проверок целевого хоста. Никогда не запускайте непроверенные файлы RUN.

Установка завершается успешно только после прохождения цепочки проверок: **Сборка → Верификатор ядра → Подключение XDP → IPC → Бэкенд → Проверка TLS**.

Правило брандмауэра для порта HTTPS-шлюза (TCP 9843) может быть автоматически настроено инсталлятором через UFW, firewalld или iptables.

**Запуск производится в режиме Observe. Переход в Canary и Enforce допустим только после документированного подтверждения проверок.**

---

## ✅ Гейты релизов

| Гейт | Состояние | Правило релиза |
|---|---:|---|
| Манифесты исходных кодов и загрузок | ✅ Реализовано | Нулевое отклонение хешей |
| Сканирование на секреты и приватные ключи | ✅ Реализовано | Ноль находок |
| Фиксация хешей GitHub Actions и контейнеров | ✅ Реализовано | Только неизменяемые идентификаторы |
| Модульные, интеграционные тесты и vet Go | 🔒 Обязательно в CI | Должны быть пройдены |
| Детектор гонок Go и фаззинг безопасности | 🔒 Обязательно в CI | Должны быть пройдены |
| Синтаксис JavaScript и shell-скриптов | ✅ Локально + CI | Должен быть пройден |
| Статический аудит безопасности кода | 🔒 Обязательно в CI | Должен быть пройден |
| Нативные тесты Rust Common/Core | 🔒 Обязательно в CI | Должны быть пройдены |
| Релизные сборки Rust Core и eBPF | 🔒 Обязательно в CI | Должны быть собраны |
| Контракты Ubuntu, Fedora, Arch и openSUSE | 🔒 Обязательно в CI | Все матричные задачи пройдены |
| Проверка полезной нагрузки инсталлятора и SHA-256 | 🔒 Обязательно в CI | Должна быть пройдена |
| Верификатор ядра и подключение NIC XDP | ⏳ Квалификация хоста | Требуется для каждого целевого хоста |
| systemd, IPC, бэкенд, TLS, Polkit и десктоп | ⏳ Квалификация хоста | Требуется для каждого целевого хоста |

**Итоговый гейт релиза:** Реальное тестирование на целевом хосте для конкретного ядра, верификатора, режима XDP, сетевого интерфейса и сетевого драйвера.

---

## 🚧 Известные ограничения (6.2.1 / V6)

- Отсутствие поддержки Swarm / Mesh
- Отсутствие разгрузки QUIC
- Отсутствие поглощения DDoS на уровне провайдера
- Отсутствие расшифровки TLS (TLS inspection)
- Отсутствие автоматического принудительного применения фидов (Feed Auto-Enforce)
- Отсутствие абсолютной защиты в случае полной компрометации пользователя root
- Отсутствие полной аттестации Measured Boot
- Внешний демон жизненного цикла Gaia Cells (компонент среды AstraeaOS)
- Отложена изолированная служба киберобмана (Isolated Deception Service)
- Замена защищённого релизного компонента сообщается с высокой серьёзностью и не разоружает платформу; ротация реестров требует, чтобы её архивный каталог принадлежал службе и имел режим `0700`, и отказывается работать, вместо того чтобы писать в общий каталог
- Ядро Rust считает и протоколирует пропущенные записи ингресса, но пока не сообщает их число в ответе о состоянии, поэтому показатель виден в журнале службы, а не на панели
- **Отсутствие выделенного V6 Web UI:** StyX, Titan Exec Gate, Parser Cells, Emergency Lockdown и Witness настраиваются через Settings v17 и REST API; при переходе в `enforce` автоматически включается безопасный профиль (`styx`, `titan_exec`, `parser_cells`), а Emergency Lockdown и Witness остаются opt-in.
- **Требование `bpf` LSM (Пункт 1 и Cell Socket LSM):** Принудительная блокировка (`bprm_check_security` / `mmap_file`) требует `bpf` в `/sys/kernel/security/lsm` (`lsm=...,bpf` + перезагрузка); иначе статус честно остаётся `inactive`.
- **Parser Cells (Пункт 2):** Поставляется с пустым списком профилей парсеров (настраивается оператором); проброс Wayland/PipeWire отнесён к Phase 2.
- **Witness и TPM-аттестация (Пункт 4):** Включает клиент Mode A и офлайн-пакеты `vgtw1` (без внешнего Witness-сервера в репозитории); без TPM2/UEFI отчитывается как `quote_kind="none"` и `key_binding="software"`.
- **Границы Emergency Lockdown Phase 2 (Пункт 5):** Приостановка LUKS, блокировка графической сессии и зануление RAM перенесены в Phase 2 (`unsupported`); управление USB/TB sysfs требует прав доступа в `gedefense-core.service`.

---

## 📋 Журнал изменений (Changelog)

### v6.2.1 — Ядерный поведенческий XDR, блокировка inode в карантине и изоляция сервис-пулов *(Текущий релиз — 23.11.2026)*

- **Блокировка вредоносных inode и границы ядра (`FIND-G-001`):** Карта BPF-LSM `MALWARE_DENIED_INODES` (`4 096` записей) отклоняет `file_open` с `-EACCES` для всех процессов кроме `gedefense-*` даже в не-root каталогах `0755` без расширения привилегий DAC, совместно с `CORE_QUARANTINE_ALLOWED_ROOTS` / `FORBIDDEN_ROOTS` и `capture_open_fd_only()`.
- **Ядерный поведенческий XDR и multi-CPU tracepoints:** Буферы `EXEC_ARGV_EVENTS` (`512` Б аргументов командной строки), `KERNEL_PROBE_EVENTS` (`XDR.PTRACE_ATTEMPT`, `XDR.KERNEL_PROTOCOL_PROBE`, `XDR.CREDENTIAL_PROBE`, `XDR.SYMLINK_OVER_SENSITIVE`), `PENDING_COLD_OPEN` + kretprobe `getname_flags`, правила обнаружения (`KD.LINUX.DISCOVERY.ACCOUNT`, `KD.LINUX.DISCOVERY.SUID`) и активация perf-tracepoints на всех CPU в `rust/vendor/aya`.
- **Изоляция сервис-пулов и гигиена телеметрии:** Ужесточённые пороги ransomware (`15 → 6` и `25 → 18`) с профилем доверия `RANSOM_TRUST_POOL_METADATA` (`php-fpm`, `lsphp`, `nginx`, `httpd`, `apache2`, `mariadbd`, `postgres`, `redis-server` и др.) и изоляцией по PPID в `stop_process_descendants`/`collect_tree` (мастер-демон и здоровые воркеры продолжают работу); фильтр `isIgnoredNonExternalFlow` в `StyxBeacon`, асинхронный `ChronosScanner` и опрос `StyxFlowHealth` раз в `1с`.
- **Расширенный бенчмарк VGT HardRed (`86.16 → 93.31`):** Итог **`93.31 / 100 (PASS)`** против OSS Best-of-Breed (`55.40 / FAIL`), Wazuh (`46.70`), CrowdSec (`36.58`) и гибридные данные REDHARD ARES опубликованы в [`benchmarks/vgt-hardred-6.2.1/`](benchmarks/vgt-hardred-6.2.1/) (`docs/V6.2.1-RELEASE.md`).

### v6.2.0 — Максимизация защиты и устойчивость телеметрии *(22.11.2026)*

- **Вредоносное ПО и архивы (`M1.1`–`M1.3`):** Асинхронный `FAN_CLOSE_WRITE`-наблюдатель для `/tmp`, `/var/tmp`, `/dev/shm`, `/var/www` (сканирование независимо от UID с пробой до `16 MiB` / полным сканом до `64 MiB`), ограниченный рекурсивный разбор ZIP/GZIP/TAR (глубина 8, fail-closed при zip-slip), `PrivateTmp=false` с узкими правами, fd-карантин и проверка raw-body в HTTP `POST`/`PUT`.
- **Сдерживание на хосте и модули ядра (`M2.1`–`M2.4`):** Глобальный режим TITAN Exec `untrusted` (`4`) через ABI-2; `XDR_KILL_TREE` / `GROUP_STOP` / `GROUP_CONT` с проверкой `pidfd`; eBPF-сенсор ransomware (`vfs_write`/`vfs_rename`/`vfs_unlink`), вооружаемый при attach с тиком дренирования `100 мс` и обратимым `SIGSTOP`; BPF-LSM Credential Guard (`file_open`) для `/etc/shadow`, `/etc/gshadow` и секретов (расширенный allowlist для TTY `login`, `cron`, `useradd`, `dpkg`).
- **StyX и устойчивая потоковая телеметрия (`M3.1`–`M3.2`):** Символические `cgroup_path`-идентичности с динамическим резолвером cgroup2-inode (статус `degraded` при дрейфе вместо тихого fail-open), кольцо `FLOW_EVENTS` 16 MiB / батчи по 64 события и раздельное отображение `enforcement_active` и `telemetry_state`.
- **WAF, харденинг и контекст (`M4.1`–`M4.5`, `M5.1`–`M5.2`):** Нормализация SQL-комментариев/пробелов, сканер секретных конфигов (`/.env`, `.git/config`, резервные копии), разбор `;`-цепочек, fast-pass `780 KB–1.5 MB`, детерминированные `429 + Retry-After`, профиль `astraeaos-cis-l1` (21-битный каталог Go/Rust) + opt-in `gedefense-cis-baseline` и корреляция Kinetic→XDR.
- **Верификация в бенчмарке:** Подтверждено **`86.16 / 100 (PASS)`** в VGT HardRed (`0.0%` Det/Prot FPR) после закрытия всех пост-аудитных замечаний (`docs/V6.2.0-RELEASE.md`).

### v6.1.2 — Предварительные условия инсталлятора и фикс подписи фидов *(20.11.2026)*

- **Предварительные условия для чистой установки (`scripts/oneclick-installer-header.sh`):** Создание системной группы `gedefense-desktop` и каталогов `/run/gedefense-scan`, `/run/gedefense`, `/sys/fs/cgroup/vgt-cells` до старта юнитов без перезагрузки, привязка `CERT_FILE` к `${TLS_DIR}/access.crt` и защита JSON-парсинга в `reconcile_post_upgrade_posture()`.
- **Парсер ключей подписи фидов (`control/feed_signing.go`):** Устранено обрезание 32/64-байтовых ключей Ed25519, оканчивающихся на `0x0d` + `
`.

### v6.1.1 — Хотфикс безопасности и совместимости с ядром *(19.11.2026)*

- **Исправления аудитов (`VGT-AUDIT-20261118-GD61` R2/R3 и `VGT-AUDIT-2026-11-19` `FIND-001`–`FIND-005`):** Захват `AF_PACKET`/`CN_PROC` вынесен в `gedefense-capture-helper.service` (`gedefense-control.service` остаётся без capabilities); добавлен фильтр seccomp `__X32_SYSCALL_BIT` (`FIND-001`), ограничены карты TLS-сенсора (`FIND-002`), синхронизирован ownership `auto_network_drop` в Lockdown (`FIND-003`), усилена проверка составных USB по `bNumInterfaces` и uevent (`FIND-004`), а также очистка заголовков `Connection` в Gateway (`FIND-005`).
- **Kernel 7.3 BTF и авто-охлаждение Cockpit:** Приём 32-байтового заголовка BTF v1 (`24 <= hdr_len <= data.len()`) и двухступенчатое охлаждение светофора (`0–15 мин` красный → `15–60 мин` жёлтый → `> 60 мин` зелёный).

### v6.1.0 — Web Exposure, Worker Integrity, TLS Sensor, LPE Guard и Edge Terminator *(18.11.2026)*

- **Модули A–E:** Мониторинг веб-экспозиции (`/proc` + ELF `.rodata` + loopback ALPN), страж целостности воркеров (`signal:signal_deliver` + `XDR.WORKER_CRASH_STORM`), TLS/ALPN-сенсор с бюджетом h2 control-storm (`INET_DIAG`), LPE-блокировщик (`socket_create` + ASLR/модули) и опциональный Go Edge Terminator с 10 панелями V6 и Settings v18.

### v6.0.3 — Нормализация критичности кейсов и аудит-гейт *(Текущий релиз — 17.11.2026)*

- **Сквозная нормализация уровней серьёзности инцидентов (`GD-SEV-001`):** Источники (`morpheus_rasp`, `styx_egress`, `styx_beacon`, `deception`) переведены на нижний регистр, нормализация добавлена в `appendIncident`, `emitStyxBeaconIncident` и `State.AddIncident`, а `CaseEngine.IngestIncident` переведён в режим fail-visible для неизвестных значений.
- **Единые классы стилей UI:** Применён `.toLowerCase()` к CSS-классам серьёзности в `xdr.js`, `l7.js`, `render.js` и `app.js`.
- **Детерминированный гейт безопасности:** Якорь Point 4 в `scripts/security-audit.sh` перенесён на версионируемый файл `docs/POINT4-PHASE1-REPORT.md`.

### v6.0.1 — Безопасный авто-старт для серверов и калибровка AIDE/сканеров *(16.11.2026)*

- **Emergency Lockdown остаётся opt-in:** `ApplySafeV6DefaultsOnEnforce()` больше не включает Emergency Lockdown автоматически при переходе в `enforce`; **StyX** (`monitor`), **Titan Exec Gate** (`contain`) и **Parser Cells** (`enabled`) включаются автоматически, а **Emergency Lockdown** и **Witness** требуют явного включения.
- **Калибровка сканеров целостности (AIDE):** `aide`, `aide.wrapper`, `updatedb.*`, `tripwire`, `samhain`, `rkhunter`, `chkrootkit`, `clamscan`, `clamd`, `freshclam`, `osqueryd` добавлены в `isSystemOrScannerAccessor` (`CANARY_SUSPICIOUS_SYSTEM_ACCESS` вместо `CRITICAL`).
- **Относительные `.sha256`-файлы:** `VGT_GeDefense_V6_6.0.1_OneClick.run.sha256` содержит только имя файла.

### v6.0.0 — GeDefense V6: Архитектура защиты от шпионского ПО и суверенитета *(15.11.2026)*

- **Пятипунктная архитектура anti-spyware:** Добавлены StyX Egress + C2/Beacon (Пункт 3), Titan + eBPF-LSM Exec/Library Gate с динамическими BTF-смещениями и поддержкой split-`ctime` на Kernel 7.0 (Пункт 1), эфемерные ячейки парсинга через `gedefense-cell-helper.service` (Пункт 2), внешний Witness-клиент с `ledger_epoch` и SSRF-защитой (Пункт 4) и Emergency Lockdown с XDP/TC drop latch, фильтром BadUSB и заморозкой брокеров по 15-байтовому `comm` (Пункт 5).
- **Безопасная авто-активация при `enforce`:** Поскольку отдельные панели V6 Web UI ещё не добавлены, при постановке на охрану (`enforce`) автоматически включается безопасный профиль (`styx=monitor`, `titan_exec=contain`, `parser_cells=enabled`), `lockdown` и `witness` остаются opt-in, а ручные переопределения API сохраняются.
- **Интегрированная база 5.2.0:** Включает все 36 исправлений аудита `VGT-AUDIT-20261114-GD51`, проверку Ed25519 в OneClick, Argon2id-миграцию и подписанные артефакты.

### v5.0.0-beta.1 — Автоматическая изоляция Gaia Cells, защищённая kernel-митигация и оперативное PHP/L7-усиление *(Предыдущая версия)*

- **Автоматическая и ручная изоляция Gaia Cells:** инциденты с оценкой выше `cells.auto_confine_score` изолируют связанную cell через обратимый transaction engine; ручная изоляция доступна в строке инцидента. API: `POST /api/v1/xdr/incidents/{id}/confine`, `GET /api/v1/cells/confinement`.
- **Kernel mitigation guard:** opt-in sysctl-митигация с ограниченным probation-окном, проверкой сервисов хоста и автоматическим rollback; панель hardening предлагает dry-run, apply и rollback с указанием причины.
- **Митигация PHP upload-progress:** критическое L7-правило `L7.PHP.SESSION_UPLOAD_PROGRESS` (score 110) и контроль `web.php-upload-progress`; `session.upload_progress.enabled = Off` проверяется по фактическому web-SAPI.
- **Rule-scoped L7 enforcement:** `l7.enforce_rules` ограничивает блокировку указанными правилами/семействами; inline edge self-test PASS, origin слушает только loopback, поэтому прямой доступ к origin не обходит инспекцию.

### v4.3.0 — Экспозиция kernel-рекомендаций: обнаруживать, оценивать и блокировать то, чего не видят сенсоры

- Оценка экспозиции релиза/канала по поставляемому каталогу рекомендаций; `unknown` никогда не выдаётся за безопасное состояние.
- Оценка с учётом достижимости и панель kernel-risk в dashboard (dry-run, apply, rollback).


### v4.2.5 — Мультивекторная карта угроз реального времени, мгновенный возврат защиты после обновлений и самоисцеление

Релиз визуализации и отказоустойчивости платформы. Включает единую глобальную карту атак по всем векторам, моментальное включение защиты после обновлений и автономное самоисцеление сенсоров.

* **Единая интерактивная карта угроз на главной странице:**
  * **Все пути обнаружения одновременно:** Главный дашборд теперь отображает пакетные блокировки (eBPF/XDP), атаки прикладного уровня L7 и телеметрию хоста XDR на анимированной глобальной карте.
  * **Координаты суверенного хоста и дуги атак:** Траектории направлены точно на реальную геопозицию хоста (по локальной базе GeoIP). Нулевые и неопределимые координаты скрываются.
  * **Семь раздельных счетчиков:** Источники, размещенные точки, блокировки, страны и раздельные показатели Kinetic, L7 и XDR.
  * **Лента недавней активности:** Таблица под картой выводит 10 последних записей журнала инцидентов с таймштампом, вектором, IP-адресом, страной, вердиктом и классификацией.
  * **100% локально без внешних запросов:** Встроенный MIT SVG-модуль геометрии, локальная матрица GeoIP на 950 000 записей. Поддержка доступности (`prefers-reduced-motion`) и управление с клавиатуры. Локализовано на 4 языках.
* **Мгновенное повторное включение защиты после обновлений (6–7 секунд):**
  * **Разделение квалификации хоста и версии релиза:** Идентификатор хоста (ядро, узел, интерфейс) отделен от версии ПО. Плановое обновление на квалифицированном хосте не требует 20-минутного ожидания канареечной лестницы; режим `enforce` активируется за 6–7 секунд.
* **Автономное самоисцеление сенсоров и защита шлюза:**
  * **Самовосстановление покрытия L7:** Сенсор `l7_application` больше не зависает в статусе ожидания трафика после перезапуска благодаря автопроверке через реальный путь инспекции (до 3 попыток).
  * **Опрос ядра до первого тика супервизора:** Исключение ложных сообщений о сбое при старте.
  * **Проверка спаренности TLS-сертификатов в systemd:** Устранение риска рассогласования ключей и ошибки `ERR_CONNECTION_REFUSED`.

### v4.2.4 — Принудительное применение fail-closed, ротация реестров и честная панель

Релиз укрепления. Он устраняет пути, на которых платформа могла потерять собственную защиту, и заставляет каждую поверхность сообщать, что ядро действительно делает.

* **Принудительное применение fail-closed (разоружение):**
  * **Автоматическая деградация больше не освобождает проверенную политику ядра.** Одна-единственная запись ядра, которую ядро Rust не смогло интерпретировать — смешанный агрегат UDP/TCP, который производитель помечает протоколом вызвавшего его пакета, поэтому запись TCP может нести больше попыток, чем SYN, — прерывала всё вычитывание; плоскость управления читала неудачное вычитывание как потерянный хук ядра, и гейт релиза отвечал на недоступный датчик приведением политики ядра к `observe`. Все правила блокировки были удалены из ядра, и производственный хост двадцать часов работал незащищённым, потому что ничто не возвращало его обратно. Теперь гейт подтверждает и сохраняет то, что проверил (`verified-enforce`), а состояние, которое он не смог подтвердить, сообщается как `verified-empty`, вместо того чтобы считаться тем же самым.
  * **Перезапуск сохраняет принудительное применение, которое несёт подписанная политика,** вместо инициализации в `observe`.
  * **Продвижение никогда не понижает проверенное принудительное применение.** Это делает только явное действие оператора, а сохранение сообщается как отдельное действие (`automatic_response_paused`), а не как изменение принудительного применения.
  * **Сбой вычитывания или парсера отделён от потери способности применять меры,** поэтому датчик, который не может доставить записи, больше не читается как ядро, которое не может блокировать.
  * **Платформа сама снова приводит защиту в действие,** как только гейты пройдены и сохраняется спокойствие, и протоколирует переход вместе с причиной, которая его задерживала.
  * **Успешная проверка очищает причину, которую она заменила.** Причины были односторонними: удалить их могли только ротация или восстановление оператором, поэтому временный сбой оставлял XDR деградировавшим — а автоматическое реагирование приостановленным — до тех пор, пока кто-нибудь не перезапускал плоскость управления.
  * **Развёртывание оператором больше не считается вмешательством.** Замена одного из собственных компонентов GeDefense деградировала XDR и приостанавливала автоматическое реагирование, поэтому выпуск исправления молча отключал часть защиты. Теперь это запись высокой серьёзности без привязанного реагирования; сторонние объекты сохраняют полное реагирование.
  * **Восстановление реестра инцидентов больше не требует отказаться от защиты,** что при сохранении принудительного применения было недостижимо: реестр можно было починить, только сначала разоружив хост, для защиты которого он и существует.
  * **Ядро Rust сохраняет метку TCP только для согласованного агрегата.** Однородная порция TCP сохраняет свои `protocol`/`tcp_flags` и точные счётчики — большая порция ACK или SYN больше не принимается за противоречие. Порция, смешивающая TCP с пакетами не-TCP, выдаётся с явным нейтральным маркером (`protocol = 0`, `tcp_flags = 0`) и точными счётчиками, вместо наследования метки пакета, вызвавшего сброс. Запись, противоречащая длине порции, отклоняется и учитывается как потерянный образец (с drain-тревогой, когда таких становится слишком много), а не переписывается в нейтральную метку. Производитель eBPF сбрасывает не более 255 пакетов за порцию (поле wire-формата `attempt_count` — `u8`), а его LSM-обход покрывает всю цепочку предков cgroup-v2 от корня, поэтому политика, установленная на cgroup Gaia Cell, охватывает и нижележащие leaf-cgroups. См. `rust/gedefense-common/src/lib.rs` (wire-декодер) и `rust/gedefense-ebpf/src/main.rs` (производитель).
* **Хранение реестров:**
  * **Оба криминалистических реестра ротируются, а не заполняются.** Достижение бюджета останавливало запись, деградировало XDR и приостанавливало автоматическое реагирование, пока оператор не архивировал сегмент вручную, — дважды за один день на одном производственном хосте. При девяноста процентах запечатанная цепочка архивируется с манифестом, несущим размеры, дайджесты, последовательность, хэш заголовка и охват, и начинается свежая цепочка.
  * **Ротация переживает сбой.** Она копирует, прежде чем заменить, поэтому прерванный запуск завершается при следующем старте по маркеру ротации; маркер, манифест которого не совпадает, отклоняется, а не принимается на веру.
  * **Реестр доказательств проверяет себя в границах.** Запуск проверял весь реестр — около 260 MB при примерно 6,7 секунды на мегабайт — и превышал тайм-аут запуска юнита, поэтому ни платформа, ни шлюз не поднимались. Теперь запуск проверяет аутентифицированную контрольную точку и ограниченное окно хвоста; история покрывается инкрементально в фоне против аутентифицированного водяного знака; полная проверка остаётся доступной оператору. Неаутентифицированный водяной знак отклоняется, потому что его принятие позволяло подделанному файлу пропустить всю историю.
  * **Прерванное добавление записи восстанавливается** — проверяется и запечатывается либо отбрасывается, когда это частичная запись, — вместо того чтобы препятствовать запуску службы.
* **Проверка интерфейса:**
  * **Каждое утверждение о состоянии сверяется с данными, из которых оно возникло.** Headless-рендеринг панели — одиннадцать комбинаций данных и представлений, восемьдесят правил — сравнивает то, что читает оператор, с тем, что сообщил API. Он выявил три утверждения, противоречившие описываемому состоянию, и все три были внесены исправлениями этого выпуска.
  * **Проверка доказывает, что может падать.** Самотест с намеренно неверными данными и режим регрессии, который снова убирает защиты: тогда восемнадцать из восьмидесяти правил становятся красными, включая SYSTEM NOMINAL в бейдже.

### v4.2.1 — Стабильность, доказательства и интерфейс

Релиз исправлений. Он не вводит ни одной новой подсистемы: он заставляет уже существующие говорить о себе правду и не мешать оператору.

* **Реестр доказательств:**
  * **Емкость больше не считается повреждением.** Достижение бюджета хранения выставляло ошибку целостности реестра, из-за чего он навсегда попадал в карантин, а состояние XDR сообщалось как деградировавшее с "mandatory evidence ledger unavailable". Полный реестр — не поврежденный.
  * **Один бюджет, читаемый одинаково с любой стороны.** Конструирование допускает, а среда выполнения действует строго, поэтому реестр, законно выросший при повышенном бюджете, принимается после перезапуска, а не приводит к отказу службы запускаться.
  * **Бюджет, который поднимает оператор, — это бюджет, который применяет реестр.** Конструктор инициализировал свою политику встроенным в бинарник значением по умолчанию 64 MiB, которому отдает предпочтение путь добавления записей, поэтому бюджет, поднятый до 256 MiB, отбрасывался при каждом запуске: реестр останавливался на 64 MiB и затем отклонял любое добавление, продолжая сообщать о себе как о здоровом. Платформа молча перестала записывать доказательства. Теперь оба бюджета стартуют равными, и бюджет, пониженный после этого, все равно вступает в силу.
  * **Состояние называет себя само.** "retention budget reached" и "integrity unavailable" — это отдельные сообщения с отдельными показателями и отдельными способами устранения.
* **Гейт релиза:**
  * **Fail-safe сохраняет свою причину.** При следующем обновлении причина перезаписывалась живым списком блокировщиков, поэтому платформа, все еще находящаяся в Observe, в итоге показывала "release gates satisfied".
  * **Fail-safe — это криминалистическая улика.** Откат — самое значимое, что платформа делает самостоятельно, и он не оставлял после себя инцидента.
* **L7 Application Defense:**
  * **Успешная самопроверка снимает устаревшую деградацию,** с ограничением в пятнадцать минут, чтобы устаревший успех не мог скрыть путь, который с тех пор сломался.
  * **Сгенерированную конфигурацию nginx невозможно было применить.** Она выдавала server-блок с `listen ... ssl` и комментарием там, где должны находиться директивы сертификата — nginx отклонял это сразу, — и называла хост, у которого уже был server-блок. Теперь это две вставляемые части, проверяемые против настоящего парсера nginx в наборе тестов.
  * **Путь применения мер теперь сообщается.** `INGRESS_HEALTH` указывает, какой хук подключило ядро — native XDP, generic XDP или TC ingress, — вместо описания всех трех как проверенного производителя ингресса ядра, хотя под нагрузкой они ведут себя совершенно по-разному.
  * **Оператор видит, существует ли HTTP-трафик, пока L7 не находится на его пути.** Обнаружение веб-поверхности сообщает, работает ли на этом хосте веб-сервер и на каких портах — только чтение, с ограничениями, и оно никогда не подается как защита, потому что обнаружение — это не защита.
  * **Управляемая интеграция с веб-сервером генерирует только текст конфигурации и ничего больше.** Она никогда не записывает в конфигурацию веб-сервера, никогда не перезагружает службу и никогда не утверждает, что сгенерированный фрагмент уже действует; оператор применяет его, а самопроверка затем наблюдает, сработало ли это. Каждое подставляемое значение сначала проверяется по закрытой грамматике, поскольку на выходе получается файл конфигурации для привилегированного демона.
  * **Проверенные запросы — это оба счетчика, а не один из них.** Панель отображала только счетчик запросов, поэтому хост, встроенный слушатель которого проверил 174 запроса, показывал "0 geprüfte Requests" прямо под собственным значком "TRAFFIC ACTIVE" — панель противоречила сама себе и скрывала доказательство того, что ее вердикт был верен. Теперь показывается сумма, из которой вычисляется вердикт.
* **Kinetic Defense:**
  * **Применение мер и их эффект видны.** Панель сообщает используемый хук, состояние канала ядра и то, что обнаружил и сделал движок. В режиме Observe она говорит об этом прямо: столбец нулей означает, что этап реагирования не был достигнут, а не то, что ничего не было обнаружено.
  * **Обзор несет показатели,** сгруппированные по вопросу, на который отвечает каждый из них.
  * **Сводка охвата объясняет тот датчик, который называет.** Предложение под ней было привязано к одному имени датчика, поэтому сводка "Mandatory sensors degraded: l7_application" пояснялась предложением о здоровом производителе ингресса — деградировавший заголовок над положительным пояснением, на странице, которая противоречила странице Application Defense в том же сеансе, хотя обе читали один и тот же снапшот. Теперь причина принадлежит датчику, из-за которого платформа перестала быть в номинальном состоянии, с использованием приоритета сервера, а резервный вариант — переведенный ключ, а не немецкая литеральная строка.
  * **Сводка детерминирована.** Она утверждает, что определяет статус детерминированно, но имена датчиков соединялись в порядке обхода map, поэтому одно и то же состояние давало предложение с разным порядком при каждом обновлении.
* **Харденинг и целостность:**
  * **Находка о подмене собственных компонентов GeDefense больше не приводит в действие реагирование.** Несовпадение дайджеста у одного из собственных бинарников продукта невозможно отличить от одобренного обновления, и движок реагирования срабатывал на это: более сотни записанных инцидентов показывают, как продукт замораживал собственный шлюз доступа — отказ в обслуживании, который любой атакующий может вызвать, коснувшись одного-единственного файла. Находка сохраняется с полной серьезностью — то же правило, тот же балл, та же категория — и удерживается только реагирование; сторонние бинарники сохраняют свое. Собственные компоненты продукта распознаются через один общий корень, который следует за `VGT_RELEASE_ROOT`.
  * **Десять переключателей харденинга оставались неактивными** на хосте, где харденинг уже применен, потому что переключатель отключался, когда его контроль уже имел статус PROTECTED; предварительная проверка лишь проверяет выбор, а не применяет его.
  * **Состояние защищенности не может себя переоценивать.** Хост, где читались два из двадцати двух контролей и оба прошли проверку, получал 100 баллов и отображался как HARDENED. Теперь уровень ограничивается, когда доказательства его не подтверждают, а рядом с баллом указывается охват.
  * **Измененный защищаемый объект сообщается как объект, один раз.** Защищаемый набор достигает одного и того же релизного бинарника через `/current/bin/...` и `/releases/<version>/bin/...`, поэтому одна замена порождала два критических инцидента; а неустраненное изменение объявлялось снова в каждом интервале дедупликации до перезапуска службы, так что один факт погребал под собой реестр, в который он был записан. Теперь сообщение привязано к разрешенному объекту и его наблюдаемому состоянию, а причина называет каждый изменившийся объект.
  * **Панель целостности называет действительно деградировавшую подсистему,** вместо того чтобы показывать `INTEGRITY_FAILURE`, тогда как реестр инцидентов, на который она указывает, здоров и не имеет к этому отношения.
* **Threat Intelligence:**
  * **FireHOL Level 1 применяется принудительно, а не коррелируется.** Запротоколированная миграция схемы повышает сохраненное значение на существующих узлах, сопоставляя его по ID фида и никогда не понижая, поскольку настройка оператора изменяется от его имени.
* **Жизненный цикл плоскости управления:**
  * **Внутренний перезапуск,** доступный из интерфейса, активирует значения класса RESTART, которые были сохранены, но никогда не применялись. Он отказывается работать, когда ни один супервизор не вернул бы процесс обратно, поскольку выход в этой точке остановил бы продукт и оставил бы его остановленным.
* **Шлюз доступа и интерфейс:**
  * **Форма входа больше не аннулирует сама себя.** Каждый просмотр страницы создавал новый токен CSRF и перезаписывал cookie, поэтому cookie была единым общим слотом, а не свойством формы на экране. Страница содержит собственные ссылки на языки, браузеры выполняют их предзагрузку и предрендеринг, и этого второго запроса было достаточно, чтобы видимая форма осталась с токеном, которому cookie больше не соответствовала — поэтому оператор, не сделавший ничего неправильного, не мог войти, сколько бы раз он ни перезагружал страницу. Вторая вкладка, восстановление при переходах назад/вперед и сторонний `<img>`, указывающий на эндпоинт, давали тот же результат. Теперь выданный браузеру токен используется повторно до истечения срока его действия; защита не изменилась: это 24 случайных байта в HttpOnly, Secure, SameSite=Strict cookie, привязанной к хосту, которую никакой другой сайт не может прочитать или установить.
  * **Устаревшая форма входа больше не ведет в тупик.** Это был голый `403 request rejected`, не называвший ни причины, ни выхода. Сам отказ не изменился — без совпадающего токена ничего не аутентифицируется и пароль не читается, — но устаревшая форма теперь возвращается к новой форме с пояснением на всех четырех языках, а срок ее жизни составляет один час.
  * **Причина отказа показывается один раз.** Она передавалась в строке запроса, что делало ее свойством адреса, а не события: перезагрузка или возврат на страницу из истории повторяли "this sign-in page had expired" над только что выданной и действительной формой. Теперь она передается в одноразовой cookie, которую страница поглощает.
  * **Отказы шлюза поддаются диагностике.** Журнал фиксирует причину, отпечаток ожидаемого токена и токена, который пришел, а также то, какие cookie присутствовали, — но никогда само значение токена.
  * **Страница входа была перекомпонована** вокруг фактов, которые хост действительно может подтвердить до появления любых учетных данных, а товарный знак продукта теперь встроен, а не нарисован средствами CSS.
  * **Поверхность аутентификации дашборда** сообщает, что подтверждает хост, и проверяет ключ по плоскости управления, прежде чем заявить об авторизации сеанса.
  * **Protection Center и навигация:** заголовок, дословно повторявший индикатор состояния, кнопка, обещавшая переход и ничего не делавшая, постоянно сплошная красная аварийная остановка рядом с основным действием, значок навигации в виде знака доллара и продублированный щит.
* **Переводы:**
  * **58 ключей существовали только на немецком,** поэтому операторы, читающие на английском, русском или китайском, видели необработанные идентификаторы ключей на панели применения мер, в уведомлении о доказательствах и на поверхности перезапуска. Теперь покрытие является свойством каждого каталога, и точки вызова `t()` проверяются наравне с атрибутами документа.

### v4.2.0 — Security Fabric Control Plane

* **Полное устранение уязвимостей по итогам аудита безопасности и харденинг:**
  * **Критическая:** Устранена уязвимость обхода симлинков в canary-развертывании (произвольная запись файлов / эскалация привилегий до root) путем покомпонентного разрешения путей через `openat(2)` с флагами `O_NOFOLLOW|O_DIRECTORY` и принудительным `ELOOP`.
  * **Высокая:** Устранена утечка конфиденциальных данных во внешних ответах 5 обработчиков API; внедрены типизированные непрозрачные ошибки вместо неполных черных списков подстрок.
  * **Высокая:** Принудительный режим fail-closed для CSPRNG (`log.Fatalf`) исключает генерацию предсказуемых идентификаторов для доказательств, инцидентов, карантина и блокировок.
  * **Высокая:** Устранена удаленная паника в предпросмотре импорта настроек путем безопасной генерации ключей.
  * **Высокая:** Токены импорта криптографически привязаны к хешу проверенных данных (исключены коллизии токенов).
  * **Средняя:** Атомарный модуль записи (`atomicWriteFile`) для политик, фидов и Chronos с отклонением симлинков, `O_EXCL` и вызовом `fsync` для файла и директории.
  * **Средняя:** Стили `unsafe-inline` полностью исключены из CSP; заголовок HSTS принудительно действует исключительно по TLS.
* **Security Fabric Control Plane:**
  * 12 управляемых модулей (`kinetic`, `network`, `protection`, `xdr`, `l7`, `threat_intel`, `hardening`, `integrity`, `boot_trust`, `policy_trust`, `forensics`, `system`).
  * Схема-ориентированная конфигурация, неизменяемые снапшоты на горячих путях, персистентная семантика `restart_required`.
  * Неподлежащие изменению инварианты безопасности: лимиты карт ядра, аутентификация Core, секретность приватных ключей, предотвращение самоблокировки оператора, защита фидов от отравления.
* **Инструменты плоскости управления и телеметрия:**
  * Детерминированный поиск настроек (`GET /api/v1/settings/search`) с актуальными значениями и обоснованием совпадений.
  * Криптографически подписанный экспорт настроек без секретов (`POST /api/v1/settings/export`).
  * Полноценный двухэтапный импорт (`/import/preview` + `/import/apply`) с анализом диффа и одноразовыми токенами.
  * Непрерывное обнаружение дрейфа (`GET /api/v1/settings/drift`) с флагом `CONFIG_DRIFT`.
* **Автономная векторная SVG-карта мира (jsVectorMap 1.7.0):**
  * 100% локальный рендеринг без CDN и сторонних картографических сервисов; нативные элементы button гарантируют соблюдение `require-trusted-types-for 'script'`.
  * Локальное разрешение GeoIP/ASN, отображение плотности событий, маркеры атак и пульсация трафика.
* **UI/UX Supreme — Современный дизайн дашборда:**
  * Отказ от громоздких сеток карточек; семантические ленты данных `<dl>` с тонкими разделителями.
  * Чистая палитра индикации состояний, стандарты доступности WCAG AA, управление с клавиатуры (`<button>`) и поддержка `prefers-reduced-motion`.
* **Исправления среды выполнения и движка:**
  * Устранен deadlock в `CaseEngine.Status`.
  * Исключены состояния fail-open в инспекторе Airlock и в CaseEngine.
  * Скорректирован маршрут `GET /assets/{name...}` для разрешения многоуровневых путей.
  * Минимальная версия компилятора Go повышена до ≥ 1.26.6 (устранены 6 CVE стандартной библиотеки).

### v4.0.1 — Локализация на китайский язык, вкладка восстановления XDR в ядре и расширение

- **Локализация на упрощенный китайский язык (`zh-CN` / `ZH`):** Полный перевод Центра управления по всем разделам (743 ключа, 100% паритет с DE, EN, RU). Добавлен селектор китайского языка на стартовом экране.
- **Специальная вкладка восстановления ядра XDR:** Интерфейс восстановления `#xdr` и эндпоинт `/api/v1/xdr/recovery` с подтверждением `ARCHIVE_AND_REINITIALIZE_XDR` для анализа поврежденных цепочек, архивации с манифестами SHA-256 и безопасного перезапуска сенсоров eBPF прямо из UI.
- **Разделение доменов хешей реестра:** Выделенное поле `evidence_root` для дерева Меркла и `record_hash` для HMAC-цепочки инцидентов.
- **Синхронизация версий:** Все компоненты, шлюз, UI и манифесты обновлены до `4.0.1`.

### v4.0.0-beta.1 — Нативная L7-защита приложений и усиление корреляции

**Плоскость безопасности приложений L7 (WAF и API Gateway)**

- **Реализация на стандартной библиотеке Go:** Встроенный движок L7-инспекции внутри непривилегированного демона `gedefense-control`. 100% без CGO, ноль сторонних зависимостей и скриптовых сред.
- **Двухрежимная архитектура:** Режим `0660` Unix-сокета (`/run/vgt-gedefense-l7/inspect.sock`) с JSON API (`POST /v1/inspect`) для внешних прокси и встроенный обратный прокси (`/run/vgt-gedefense-l7/edge.sock`).
- **Строгая изоляция апстрима (Anti-SSRF):** Цели перенаправления ограничены чистыми Unix-сокетами или loopback IP (`127.0.0.1`, `[::1]`).
- **Ограниченная нормализация и защита от обхода:** Рекурсивное декодирование, Unicode Fullwidth Fold, автоматический Base64, потоковый парсер JSON (`max_json_depth = 32`), ограниченная декомпрессия Gzip/Deflate.
- **Полный набор детекторов атак:** SQLi, XSS, Command Injection/RCE, Path Traversal/LFI, SSTI, XXE, десериализация, HTTP Smuggling (CL.TE / TE.CL).
- **Защита от SSRF с нормализацией IP:** Декодирование альтернативных представлений IPv4, изоляция метаданных облачных сервисов.
- **Анализ файлов в памяти (`InspectBytes`):** Multipart-загрузки проверяются в RAM до записи на диск.
- **Шардированный Rate Limiting:** 64 независимых шарда, ограничение по клиентам, чувствительным эндпоинтам и глобальным маршрутам.
- **DLP в ответах:** Проверка на ошибки БД, утечки исходного кода, стектрейсы и приватные ключи с сохранением потока байт.

**Корреляция XDR и целостность хоста**

- **Изоляция веб-улик:** Веб-события с `AlertOnly: true` и `ResponseScore: 0` никогда не вызывают автономных деструктивных действий над процессами хоста.
- **Интеграция в Trinity XDR 2.0 DAG:** Веб-события регистрируются как узлы графа с доказательствами корня Меркла.
- **Корреляция сетевых соединений:** Сопоставление HTTP-запросов с локальными сокетами Linux (`SO_PEERCRED`).
- **Поэтапное применение мер:** Блокировка активна только при переходе в режим `Enforce`.

**Systemd, права доступа и харденинг**

- Системная группа `gedefense-l7`, каталог `/run/vgt-gedefense-l7` (права `0750`) через `systemd-tmpfiles`.
- Unix-сокеты с правами `0660` и проверкой `SO_PEERCRED`.
- Тулчейн Go 1.27.4 с аудитом безопасности AST.
- 3 набора непрерывных тестов фаззинга в CI.

### v3.0.0-beta.1 — Универсальная интеграция с Linux

**Интеграция и развертывание**

- Перенос контрактов готовности и привилегий AstraeaOS в универсальный релиз Linux.
- Поддержка пакетных менеджеров APT, DNF/YUM, pacman и Zypper.
- Разграничение привилегий через Polkit и хелпер готовности systemd.
- Десктопный ярлык с профилем Chromium и точной фиксацией SPKI сертификата.
- Ограничение специфичных компонентов SDDM, ArchISO и Gaia Cells средой AstraeaOS.

**Безопасность и корректность**

- Добавление SAN-адресов `localhost`, `127.0.0.1` и `::1` в генерируемые сертификаты шлюза.
- Интеграция базы репутационных хешей вредоносного ПО.
- Манифесты fail-closed, проверка маркеров секретов, отклонение симлинков.
- Нормализация окончаний строк LF и прав на исполнение скриптов.

**Релизная инженерия**

- Обязательные гейты тестов Go (unit/vet/race/fuzz) и безопасности.
- Сборка ядра Rust и программ no_std eBPF.
- Матричные задачи сборки для Ubuntu, Fedora, Arch и openSUSE.
- Привязка GitHub Actions к неизменяемым SHA коммитов.
- Привилегированный воркфлоу для проверки bpffs, eBPF, XDP, IPC/TLS, systemd и Polkit.

**Неизменная основа безопасности**

- Разделение на Go Control Plane, Rust Response Core и Rust eBPF/XDP Data Plane.
- Семантика переходов Observe → Canary → Enforce, реестр доказательств, зашифрованное хранилище и обратимый харденинг.

### v1.0.0-beta.5 — Завершенная бета-версия

Статус полной бета-версии — цепочка защиты функционально завершена и доступна для тестирования. Инсталлятор 3.5.1 со всей последовательностью гейтов (сборка, верификатор ядра, XDP, IPC, бэкенд, TLS). Зеркало исходного кода с побайтовой идентичностью. Полная матрица валидации пройдена.

---

## 🔗 Экосистема VGT

| Инструмент | Тип | Назначение |
|---|---|---|
| 🛡️ **VGT GeDefense** | **Фабрика безопасности Linux** | Защита на уровне ядра, XDR, зашифрованные улики — вы здесь |
| 🧠 **[VGT AETHEL](https://github.com/visiongaiatechnology/aethel)** | **Суверенная ОС ИИ** | Локальная ОС искусственного интеллекта под управлением оператора |
| 🖥️ **[VGT WP-Desk](https://github.com/visiongaiatechnology/vgtdesk)** | **Уровень ОС / UX** | Защищенное рабочее пространство оператора WordPress |
| ⚔️ **[VGT Sentinel](https://github.com/visiongaiatechnology/sentinelcom)** | **WAF / IDS** | Zero-Trust WAF для WordPress |
| ⚡ **[VGT Auto-Punisher](https://github.com/visiongaiatechnology/vgt-auto-punisher)** | **IDS** | Гибридная система IDS L4+L7 |
| 🔐 **[VGT Omega Vault](https://github.com/visiongaiatechnology/vgt-omega-vault)** | **Зашифрованные формы** | Хранилище форм WordPress с шифрованием AES-256-GCM |
| 🌐 **[GaiaCom](https://github.com/visiongaiatechnology/GaiaCom)** | **Связь** | Постквантовая федеративная платформа со сквозным шифрованием (E2EE) |
| 📊 **[VGT Dattrack](https://github.com/visiongaiatechnology/dattrack)** | **Аналитика** | Суверенная локальная аналитика |

---

## 💙 Поддержите миссию

[![Donate](https://img.shields.io/badge/Donate-PayPal-00457C?style=for-the-badge&logo=paypal)](https://paypal.me/dergoldenelotus)

| Метод | Адрес |
|---|---|
| **PayPal** | [paypal.me/dergoldenelotus](https://paypal.me/dergoldenelotus) |
| **Bitcoin** | `bc1q3ue5gq822tddmkdrek79adlkm36fatat3lz0dm` |
| **ETH / USDT (ERC-20)** | `0xD37DEfb09e07bD775EaaE9ccDaFE3a5b2348Fe85` |

---

## 📄 Лицензия

**AGPL-3.0-only · © 2026 VisionGaia Technology · Кёльн, Германия**

VGT GeDefense является свободным программным обеспечением: вы можете распространять и/или изменять его в соответствии с условиями GNU Affero General Public License, опубликованной Free Software Foundation, только версии 3. Любая производная работа или модификация, развернутая в сети, должна публиковаться под той же лицензией.

Корпоративное внедрение, аудиты TIER-0 (VGT SafetySys™) и коммерческие лицензии с исключениями: [visiongaiatechnology.de](https://visiongaiatechnology.de)

### 🗺️ Атрибуция данных и локальная база данных GeoIP / ASN

GeDefense включает полностью автономную, локально обрабатываемую базу данных GeoIP и Origin-ASN (`/var/lib/vgt/gedefense/geoip.csv`), гарантирующую полное отсутствие внешних облачных запросов и телеметрии:

* **DB-IP Lite:** Данный продукт использует данные GeoLite2 или DB-IP Lite, созданные DB-IP и доступные на [https://db-ip.com/](https://db-ip.com/) в соответствии с лицензией Creative Commons Attribution 4.0 International (CC BY 4.0). Требуется указание авторства (Attribution).
* **Данные Origin ASN:** Данные сопоставления Origin ASN предоставлены проектом [sapics/ip-location-db](https://github.com/sapics/ip-location-db) по лицензии Public Domain Dedication and License (PDDL).

#### Обновление локальной базы данных GeoIP

Вы можете в любой момент загрузить актуальные данные, объединить их по алгоритму Longest-Prefix-Match и атомарно обновить базу:

```bash
# Загружает последние базы DB-IP City и Origin-ASN, компилирует CSV (< 128 МиБ / < 1 000 000 префиксов) и атомарно заменяет /var/lib/vgt/gedefense/geoip.csv
sudo python3 scripts/update-geoip-db.py /var/lib/vgt/gedefense/geoip.csv
```

---

### Лицензии третьих сторон

Карта использует **jsVectorMap 1.7.0** (MIT, Copyright © 2020 Mustafa Omar; карта мира `world-merc.js`). Офлайн-данные `geoip.csv` основаны на **iplocate/ip-address-databases** (CC BY-SA 4.0; изменения — VisionGaia Technology), DB-IP Lite (CC BY 4.0) и Origin-ASN из `sapics/ip-location-db` (PDDL). Полные уведомления: [THIRD-PARTY-LICENSES.md](THIRD-PARTY-LICENSES.md).


<div align="center">

**VISIONGAIATECHNOLOGY – WE ARCHITECT THE FUTURE OF SECURITY.**

[![VGT](https://img.shields.io/badge/VisionGaia-Technology-cyan?style=for-the-badge)](https://visiongaiatechnology.de)

*VGT GeDefense 6.2.1 (V6) — Universal Linux Security Fabric // Rust eBPF/XDP Data Plane // Go Control Plane // Host XDR // Ed25519 Evidence Ledger // AES-256-GCM Encrypted Vault // Reversible Hardening // AstraeaOS-Native Adapter // Separated Trust Domains // No Cloud Control Plane // AGPL-3.0-only // Linux x86_64*

</div>
