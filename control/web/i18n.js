'use strict';

const VERSION = '1.0.0-beta.5';
const SUPPORTED = new Set(['de', 'en', 'ru']);
const LOCALES = { de: 'de-DE', en: 'en-US', ru: 'ru-RU' };

const messages = {
  de: {
    'app.title': `GeDefense ${VERSION} · VisionGaiaTechnology`,
    'skip.content': 'Zum Inhalt',
    'nav.label': 'Hauptnavigation',
    'brand.powered': 'powered by VisionGaiaTechnology',
    'nav.overview': 'Übersicht', 'nav.xdr': 'GeDefense XDR', 'nav.network': 'Netzwerk',
    'nav.policy': 'Policy Trust', 'nav.forensics': 'Forensik', 'nav.release': 'Beta Release',
    'nav.settings': 'Einstellungen', 'nav.system': 'System',
    'top.operator': 'Operator-Key', 'top.support': 'VGT unterstützen', 'top.language': 'Sprache',
    'view.overview.eyebrow': 'SOVEREIGN DEFENSE FABRIC', 'view.overview.title': 'Übersicht',
    'view.xdr.eyebrow': 'CORRELATION & RESPONSE', 'view.xdr.title': 'GeDefense XDR',
    'view.network.eyebrow': 'XDP POLICY CONTROL', 'view.network.title': 'Netzwerk',
    'view.policy.eyebrow': 'SIGNED TRUST STATE', 'view.policy.title': 'Policy Trust',
    'view.forensics.eyebrow': 'AUTHENTICATED EVIDENCE', 'view.forensics.title': 'Forensik',
    'view.release.eyebrow': 'PRODUCTION BETA GATE', 'view.release.title': 'Beta Release',
    'view.settings.eyebrow': 'RUNTIME DEFENSE CONTROL', 'view.settings.title': 'Einstellungen',
    'view.system.eyebrow': 'NODE DIAGNOSTICS', 'view.system.title': 'System',
    'overview.kicker': `GEDEFENSE ${VERSION} // FULL STACK BETA`,
    'overview.heading': 'Abwehr, die den Host als Gesamtsystem versteht.',
    'overview.description': 'Rust-XDP, signierte Policy-Snapshots und Linux-XDR korrelieren Netzwerk, Prozesse, Integrität und Verhalten – lokal, nachvollziehbar und ohne Cloud-Abhängigkeit.',
    'metric.kernel': 'Kernel Core', 'metric.xdr': 'XDR Engine', 'metric.rules': 'Aktive Regeln',
    'metric.anomalies': 'Anomalien', 'metric.uptime': 'Uptime',
    'metric.ipc': 'IPC-Prüfung', 'metric.sensorInit': 'Sensorinitialisierung',
    'metric.signedCidrs': 'signierte CIDR-Policies', 'metric.adaptive': 'adaptive Abweichungen',
    'network.pulse': 'NETWORK PULSE', 'network.throughput': 'Echtzeit-Durchsatz',
    'network.chartLabel': 'Netzwerkdurchsatz', 'network.interface': 'Interface',
    'stream.title': 'Letzte Ereignisse',
    'xdr.description': 'Prozess-, Netzwerk-, Herkunfts-, Integritäts- und Verhaltenssignale werden als unabhängige Kategorien bewertet.',
    'xdr.processes': 'Überwachte Prozesse', 'xdr.processDetail': 'aktuelle PID-Identitäten',
    'xdr.flows': 'Externe Flows', 'xdr.flowDetail': 'prozesskorreliert',
    'xdr.evaluations': 'Evaluierungen', 'xdr.pipeline': 'begrenzte Worker-Pipeline',
    'xdr.queue': 'Queue', 'xdr.profiles': 'Profile', 'xdr.loadProfiles': 'Profile laden',
    'xdr.incidents': 'Korrelierte Incidents', 'xdr.behavior': 'Verhaltensprofile',
    'table.time': 'Zeit', 'table.score': 'Score', 'table.process': 'Prozess', 'table.signals': 'Signale',
    'table.decision': 'Entscheidung', 'table.result': 'Ergebnis', 'table.executable': 'Executable',
    'table.samples': 'Samples', 'table.avgConnections': 'Ø Verbindungen', 'table.avgTargets': 'Ø Ziele',
    'table.knownPorts': 'Bekannte Ports', 'table.lastSignal': 'Letztes Signal',
    'network.heading': 'Netzwerkverteidigung',
    'network.description': 'CIDR-Regeln werden normalisiert, zeitlich begrenzt und als signierter Policy-Snapshot persistiert.',
    'network.newRule': 'Regel setzen', 'network.target': 'Ziel-IP oder CIDR', 'network.reason': 'Begründung',
    'network.reasonPlaceholder': 'Anomales Scan-Verhalten', 'network.ttl': 'Gültigkeit',
    'network.15m': '15 Minuten', 'network.1h': '1 Stunde', 'network.6h': '6 Stunden', 'network.24h': '24 Stunden',
    'network.activate': 'Policy aktivieren', 'network.sync': 'Threat Feeds synchronisieren',
    'network.rules': 'Blockregeln', 'network.feedVectors': 'Feed-Vektoren',
    'table.target': 'Ziel', 'table.source': 'Quelle', 'table.reason': 'Begründung', 'table.expiry': 'Ablauf', 'table.status': 'Status',
    'policy.heading': 'Policy Trust', 'policy.description': 'Jede persistente Regelgeneration wird deterministisch serialisiert, AES-256-GCM-verschlüsselt und mit Ed25519 signiert.',
    'policy.signer': 'Signer', 'policy.signerDetail': 'lokaler Ed25519-Vertrauensanker', 'policy.generation': 'Generation',
    'policy.generationDetail': 'monotoner Policy-Stand', 'policy.lastUpdate': 'Letztes Update', 'policy.updateDetail': 'UTC-signierter Snapshot',
    'policy.lifecycle': 'Policy-Lebenszyklus', 'policy.apiValidation': 'API-Validierung', 'policy.strictJson': 'striktes JSON + Replay-Schutz',
    'policy.mutation': 'State-Mutation', 'policy.normalized': 'normalisierte CIDR-Regel', 'policy.signature': 'Ed25519-Signatur',
    'policy.deterministic': 'deterministische Generation', 'policy.core': 'Rust Core', 'policy.ipc': 'authentifiziertes VGT3 IPC',
    'forensics.heading': 'Forensik', 'forensics.description': 'Incidents werden redigiert, AES-256-GCM-verschlüsselt, HMAC-verkettet und gegen einen atomischen Head-Checkpoint geprüft.',
    'forensics.export': 'Export erstellen', 'forensics.chain': 'Incident-Kette', 'forensics.initializing': 'Initialisierung',
    'forensics.incidents': 'Incidents', 'forensics.records': 'authentifizierte Records', 'forensics.responses': 'Reaktionen',
    'forensics.broker': 'Broker-Entscheidungen', 'forensics.history': 'Incident-Historie', 'table.id': 'ID',
    'table.severity': 'Severity', 'table.summary': 'Zusammenfassung', 'table.action': 'Action',
    'release.heading': 'Beta Release Control',
    'release.description': 'Aktive Reaktion wird ausschließlich stufenweise freigegeben. Observe, Canary und Enforce besitzen eigene Gesundheits-, Soak- und Rollbackbedingungen.',
    'release.phase': 'Phase', 'release.startPhase': 'Startphase', 'release.readiness': 'Readiness',
    'release.gateCheck': 'Gate-Prüfung', 'release.heartbeat': 'Core Heartbeat', 'release.failures': 'aufeinanderfolgende Fehler',
    'release.change': 'Phase wechseln', 'release.target': 'Zielphase', 'release.canary': 'Canary / Contain',
    'release.enforce': 'Enforce', 'release.observe': 'Zurück zu Observe', 'release.reason': 'Freigabegrund',
    'release.reasonPlaceholder': 'Canary nach abgeschlossener Beobachtungsphase', 'release.confirmation': 'Explizite Bestätigung',
    'release.submit': 'Gate prüfen und wechseln', 'release.confirmationHint': 'Bestätigungen: PROMOTE:CANARY, PROMOTE:ENFORCE oder RETURN:OBSERVE.',
    'release.emergency': 'Emergency Stop', 'release.emergencyDescription': 'Persistiert einen lokalen Stop-Anker, setzt Netzwerk und XDR auf Observe und blockiert jede erneute Promotion bis zur manuellen Aufhebung.',
    'release.emergencyReasonPlaceholder': 'Unerwartetes Reaktionsverhalten erkannt', 'release.emergencySubmit': 'Aktive Reaktion sofort sperren',
    'release.clearReason': 'Aufhebungsgrund', 'release.clearReasonPlaceholder': 'Ursache geprüft, System bleibt zunächst in Observe',
    'release.clearSubmit': 'Emergency Stop aufheben', 'release.conditions': 'Freigabebedingungen',
    'release.kernelState': 'Kernel Fail-safe', 'release.kernelStateDetail': 'XDP-Leerzustand muss bestätigt sein',
    'settings.heading': 'Einstellungen', 'settings.description': 'Module und Reaktionsschwellen werden live geändert, AES-256-GCM-verschlüsselt sowie HMAC-authentifiziert persistiert und ohne Neustart übernommen.',
    'settings.components': 'Aktive Komponenten', 'settings.xdr': 'XDR Sensor', 'settings.xdrDetail': 'Prozesse, Integrität und Reaktionspipeline',
    'settings.network': 'Netzwerk-Korrelation', 'settings.networkDetail': 'Externe Flows den Prozessen zuordnen',
    'settings.behavior': 'Behavior Learning', 'settings.behaviorDetail': 'Adaptive, MAC-geschützte Prozessprofile',
    'settings.feeds': 'Threat Feeds', 'settings.feedsDetail': 'Öffentliche Präfixe lokal zur Korrelation stagen',
    'settings.autoFeeds': 'Automatischer Feed-Sync', 'settings.autoFeedsDetail': 'Synchronisierung im konfigurierten Intervall',
    'settings.autoDegrade': 'Auto-Degrade', 'settings.autoDegradeDetail': 'Bei Core-, Policy- oder Sensorfehlern auf Observe zurückfallen',
    'settings.tuning': 'Intervalle und Schwellen', 'settings.processScan': 'Prozess-Scan (ms)', 'settings.networkScan': 'Netzwerk-Scan (s)',
    'settings.alert': 'Alert Score', 'settings.contain': 'Contain Score', 'settings.kill': 'Kill Score',
    'settings.save': 'Einstellungen verschlüsselt speichern', 'settings.allowlist': 'Management-Allowlist',
    'settings.required': 'Pflicht vor Enforce', 'settings.ipCidr': 'IP oder CIDR', 'settings.add': 'Hinzufügen',
    'settings.ruleModules': 'Regelmodule verschalten', 'settings.observeOnly': 'Nur in Observe/Degraded änderbar',
    'settings.moduleCommand': 'Integrierte RE2-Kommandoerkennung', 'settings.moduleOrigin': 'memfd, gelöschte und temporäre Executables',
    'settings.moduleLineage': 'Eltern-Kind-Prozesskorrelation', 'settings.moduleMasquerading': 'Prozessname gegen Executable-Pfad',
    'settings.moduleThreat': 'Remote-IP gegen gestagte Präfixe', 'settings.moduleBaseline': 'Lokale Prozess- und Netzwerkbaseline',
    'settings.customRules': 'Eigene RE2-Regeln', 'settings.alertOnly': 'Nur Signal/Score, niemals direkte Kill-Autorisierung',
    'settings.ruleId': 'Regel-ID', 'settings.category': 'Kategorie', 'settings.score': 'Score',
    'settings.summary': 'Zusammenfassung', 'settings.pattern': 'RE2-Pattern', 'settings.addRule': 'Regel verschlüsselt speichern',
    'table.networkCidr': 'Netz/CIDR', 'table.kernelProtection': 'Kernel-Schutz',
    'system.heading': 'System', 'system.description': 'Gesundheit der privilegierten und unprivilegierten Sicherheitsdomänen.',
    'system.node': 'Node', 'system.dataPlane': 'Data Plane', 'system.xdr': 'XDR Sensor', 'system.policy': 'Policy',
    'system.behavior': 'Behavior Store', 'system.feeds': 'Feed Matrix', 'system.notSynced': 'Noch nicht synchronisiert',
    'system.domains': 'Getrennte Vertrauenszonen', 'system.kernel': 'Kernel', 'system.kernelDetail': 'Rust eBPF/XDP',
    'system.broker': 'Privileged Broker', 'system.brokerDetail': 'pidfd + Evidence-Recheck',
    'system.control': 'Control Plane', 'system.controlDetail': 'Go Standardbibliothek',
    'system.dashboard': 'Dashboard', 'system.dashboardDetail': 'Same-Origin, CSP, Session-Authentifizierung',
    'auth.eyebrow': 'OPERATOR ACCESS', 'auth.title': 'Dashboard-Key', 'auth.description': 'Der Operator-Key bleibt ausschließlich im flüchtigen Speicher dieses Browser-Tabs und wird beim Neuladen verworfen.',
    'auth.token': 'Bearer Token', 'auth.save': 'Sitzung autorisieren', 'dialog.close': 'Schließen',
    'support.title': 'VisionGaiaTechnology unterstützen', 'support.description': 'GeDefense wird unabhängig entwickelt. Unterstützung finanziert souveräne Open-Source-Sicherheit, Tests und Infrastruktur.',
    'support.method': 'Methode', 'support.address': 'Adresse', 'support.copy': 'Kopieren', 'support.copied': 'Adresse kopiert.',
    'support.paypal': 'PayPal öffnen', 'support.note': 'Krypto-Adressen vor jeder Überweisung selbst prüfen. USDT ausschließlich über ERC-20.',
    'footer.powered': `GeDefense ${VERSION} powered by VisionGaiaTechnology`,
    'noscript': 'Das GeDefense Command Center benötigt lokales JavaScript.',
    'dynamic.noManagement': 'Noch kein Managementnetz eingetragen. Enforce bleibt sicher blockiert.',
    'dynamic.noCustomRules': 'Keine eigenen Operator-Regeln konfiguriert.',
    'dynamic.failSafeVerified': 'Kernel-Leerzustand kryptografisch authentifiziert bestätigt.',
    'dynamic.failSafeUnverified': 'Kernelzustand nicht bestätigt – Out-of-Band-Prüfung erforderlich.',
    'dynamic.synced': 'SYNCHRONISIERT', 'dynamic.pending': 'AUSSTEHEND', 'dynamic.remove': 'Entfernen',
    'dynamic.managementRemoved': 'Managementnetz entfernt.', 'dynamic.revision': 'REVISION {value}',
    'dynamic.online': 'ONLINE', 'dynamic.offline': 'OFFLINE', 'dynamic.controlOnly': 'CONTROL ONLY',
    'dynamic.controlSafe': 'Control-only safe mode', 'dynamic.rustOffline': 'Rust Core offline',
    'dynamic.kernelShield': 'KERNEL SHIELD ACTIVE', 'dynamic.observeFabric': 'OBSERVE FABRIC',
    'dynamic.authVgt': 'Authentifiziertes VGT3 · {mode}', 'dynamic.allowlist': 'Allowlist {state}',
    'dynamic.nominal': 'SYSTEM NOMINAL', 'dynamic.degraded': 'DEGRADED', 'dynamic.disabled': 'DISABLED', 'dynamic.enableAction': 'Aktivieren', 'dynamic.disableAction': 'Deaktivieren',
    'dynamic.locked': 'LOCKED', 'dynamic.operatorLocked': 'OPERATOR LOCKED', 'dynamic.apiOffline': 'API OFFLINE',
    'dynamic.incidents': '{value} Incidents', 'dynamic.drops': '{value} Drops', 'dynamic.warm': '{value} warm',
    'dynamic.macVerified': 'MAC VERIFIED', 'dynamic.integrityFailure': 'INTEGRITY FAILURE',
    'dynamic.signatureVerified': 'SIGNATURE VERIFIED', 'dynamic.signatureFailure': 'SIGNATURE FAILURE',
    'dynamic.quarantined': 'QUARANTINED', 'dynamic.verified': 'VERIFIED', 'dynamic.failed': 'FAILED',
    'dynamic.hmacChain': 'AES-GCM + HMAC-Kette + Head-Checkpoint', 'dynamic.safeMode': 'Sicherer Control-only-Modus',
    'dynamic.protectedObjects': '{value} geschützte Objekte', 'dynamic.noSigner': 'kein Signer',
    'dynamic.generation': 'Generation {value}', 'dynamic.profilesWarm': '{profiles} Profile · {warm} warm',
    'dynamic.since': 'seit {time}', 'dynamic.ready': 'READY', 'dynamic.blocked': 'BLOCKED',
    'dynamic.noEvents': 'Noch keine Security-Ereignisse.', 'dynamic.noRules': 'Keine aktiven Blockregeln.',
    'dynamic.kernel': 'KERNEL', 'dynamic.observe': 'OBSERVE', 'dynamic.noIncidents': 'Noch keine XDR-Incidents.',
    'dynamic.acknowledge': 'Bestätigen', 'dynamic.noForensics': 'Keine forensischen Records.',
    'dynamic.noProfiles': 'Noch keine geladenen Verhaltensprofile.', 'dynamic.allGates': 'Alle aktuellen Freigabegates erfüllt.',
    'toast.ruleRemoved': 'Blockregel entfernt.', 'toast.incidentAck': 'Incident bestätigt.',
    'toast.operatorRequired': 'Operator-Key erforderlich.', 'toast.operationFailed': 'Operation fehlgeschlagen',
    'toast.sessionUpdated': 'Operator-Sitzung aktualisiert.', 'toast.policyActivated': 'Neue Netzwerk-Policy aktiviert.',
    'toast.feedStarted': 'Threat-Feed-Synchronisierung gestartet.', 'toast.profilesLoaded': 'Verhaltensprofile geladen.',
    'toast.forensicsCreated': 'Forensik-Export erstellt.', 'toast.phaseChanged': 'Beta-Phase wurde signiert und aktiviert.',
    'toast.emergencyActive': 'Emergency Stop aktiv. Alle aktiven Reaktionen sind gesperrt.',
    'toast.emergencyCleared': 'Emergency Stop aufgehoben. GeDefense bleibt in Observe.',
    'toast.settingsActivated': 'Runtime-Einstellungen aktiviert.', 'toast.allowlistSynced': 'Managementnetz im Rust-Core synchronisiert.',
    'toast.customRuleSaved': 'Eigene Regel validiert, verschlüsselt und aktiviert.', 'toast.customRuleRemoved': 'Eigene Regel entfernt.',
    'message.policySet': 'Policy wurde signiert und aktiviert.', 'message.policyFailed': 'Policy konnte nicht gesetzt werden.',
    'message.settingsSaved': 'Einstellungen wurden AES-256-GCM-verschlüsselt, HMAC-authentifiziert gespeichert und live übernommen.',
    'message.settingsFailed': 'Einstellungen konnten nicht gespeichert werden.'
  },
  en: {},
  ru: {}
};

Object.assign(messages.en, {
  ...messages.de,
  'skip.content':'Skip to content','nav.label':'Main navigation','nav.overview':'Overview','nav.network':'Network','nav.forensics':'Forensics','nav.release':'Beta Release','nav.settings':'Settings','nav.system':'System',
  'top.operator':'Operator key','top.support':'Support VGT','top.language':'Language',
  'view.overview.title':'Overview','view.network.title':'Network','view.forensics.title':'Forensics','view.settings.title':'Settings',
  'overview.heading':'Defense that understands the host as one system.','overview.description':'Rust XDP, signed policy snapshots and Linux XDR correlate network, processes, integrity and behavior — locally, transparently and without cloud dependency.',
  'metric.rules':'Active rules','metric.anomalies':'Anomalies','metric.ipc':'IPC verification','metric.sensorInit':'Sensor initialization','metric.signedCidrs':'signed CIDR policies','metric.adaptive':'adaptive deviations',
  'network.throughput':'Real-time throughput','network.chartLabel':'Network throughput','network.interface':'Interface','stream.title':'Recent events',
  'xdr.description':'Process, network, origin, integrity and behavior signals are evaluated as independent categories.','xdr.processes':'Monitored processes','xdr.processDetail':'current PID identities','xdr.flows':'External flows','xdr.flowDetail':'process-correlated','xdr.evaluations':'Evaluations','xdr.pipeline':'bounded worker pipeline','xdr.queue':'Queue','xdr.profiles':'Profiles','xdr.loadProfiles':'Load profiles','xdr.incidents':'Correlated incidents','xdr.behavior':'Behavior profiles',
  'table.time':'Time','table.process':'Process','table.signals':'Signals','table.decision':'Decision','table.result':'Result','table.avgConnections':'Avg. connections','table.avgTargets':'Avg. targets','table.knownPorts':'Known ports','table.lastSignal':'Last signal',
  'network.heading':'Network defense','network.description':'CIDR rules are normalized, time-limited and persisted as a signed policy snapshot.','network.newRule':'Create rule','network.target':'Target IP or CIDR','network.reason':'Reason','network.reasonPlaceholder':'Anomalous scan behavior','network.ttl':'Validity','network.15m':'15 minutes','network.1h':'1 hour','network.6h':'6 hours','network.24h':'24 hours','network.activate':'Activate policy','network.sync':'Synchronize threat feeds','network.rules':'Block rules','network.feedVectors':'feed vectors','table.target':'Target','table.source':'Source','table.reason':'Reason','table.expiry':'Expiry','table.status':'Status',
  'policy.description':'Every persistent rule generation is deterministically serialized, encrypted with AES-256-GCM and signed with Ed25519.','policy.signerDetail':'local Ed25519 trust anchor','policy.generationDetail':'monotonic policy state','policy.lastUpdate':'Last update','policy.updateDetail':'UTC-signed snapshot','policy.lifecycle':'Policy lifecycle','policy.apiValidation':'API validation','policy.strictJson':'strict JSON + replay guard','policy.mutation':'State mutation','policy.normalized':'normalized CIDR rule','policy.signature':'Ed25519 signature','policy.deterministic':'deterministic generation','policy.ipc':'authenticated VGT3 IPC',
  'forensics.heading':'Forensics','forensics.description':'Incidents are redacted, AES-256-GCM encrypted, HMAC-chained and checked against an atomic head checkpoint.','forensics.export':'Create export','forensics.chain':'Incident chain','forensics.initializing':'Initializing','forensics.records':'authenticated records','forensics.responses':'Responses','forensics.broker':'Broker decisions','forensics.history':'Incident history','table.summary':'Summary',
  'release.description':'Active response is enabled only in stages. Observe, Canary and Enforce have separate health, soak and rollback conditions.','release.startPhase':'Initial phase','release.gateCheck':'Gate check','release.failures':'consecutive failures','release.change':'Change phase','release.target':'Target phase','release.observe':'Return to Observe','release.reason':'Release reason','release.reasonPlaceholder':'Canary after completed observation phase','release.confirmation':'Explicit confirmation','release.submit':'Verify gate and transition','release.confirmationHint':'Confirmations: PROMOTE:CANARY, PROMOTE:ENFORCE or RETURN:OBSERVE.','release.emergencyDescription':'Persists a local stop anchor, returns network and XDR to Observe and blocks promotion until manually cleared.','release.emergencyReasonPlaceholder':'Unexpected response behavior detected','release.emergencySubmit':'Block active response now','release.clearReason':'Clearance reason','release.clearReasonPlaceholder':'Cause reviewed; system remains in Observe','release.clearSubmit':'Clear Emergency Stop','release.conditions':'Release conditions',
  'release.kernelState':'Kernel fail-safe','release.kernelStateDetail':'The empty XDP state must be confirmed',
  'settings.description':'Modules and response thresholds are changed live, AES-256-GCM encrypted, HMAC-authenticated and applied without restart.','settings.components':'Active components','settings.xdrDetail':'Processes, integrity and response pipeline','settings.network':'Network correlation','settings.networkDetail':'Map external flows to processes','settings.behaviorDetail':'Adaptive MAC-protected process profiles','settings.feedsDetail':'Stage public prefixes locally for correlation','settings.autoFeeds':'Automatic feed sync','settings.autoFeedsDetail':'Synchronization at the configured interval','settings.autoDegradeDetail':'Fall back to Observe on core, policy or sensor faults','settings.tuning':'Intervals and thresholds','settings.processScan':'Process scan (ms)','settings.networkScan':'Network scan (s)','settings.save':'Save encrypted settings','settings.allowlist':'Management allowlist','settings.required':'Required before Enforce','settings.ipCidr':'IP or CIDR','settings.add':'Add','table.networkCidr':'Network/CIDR','table.kernelProtection':'Kernel protection',
  'settings.ruleModules':'Wire rule modules','settings.observeOnly':'Changeable only in Observe/Degraded','settings.moduleCommand':'Built-in RE2 command detection','settings.moduleOrigin':'memfd, deleted and temporary executables','settings.moduleLineage':'Parent-child process correlation','settings.moduleMasquerading':'Process name against executable path','settings.moduleThreat':'Remote IP against staged prefixes','settings.moduleBaseline':'Local process and network baseline','settings.customRules':'Custom RE2 rules','settings.alertOnly':'Signal and score only; never direct kill authorization','settings.ruleId':'Rule ID','settings.category':'Category','settings.score':'Score','settings.summary':'Summary','settings.pattern':'RE2 pattern','settings.addRule':'Save encrypted rule',
  'system.description':'Health of privileged and unprivileged security domains.','system.dataPlane':'Data plane','system.notSynced':'Not synchronized yet','system.domains':'Separated trust domains','system.kernelDetail':'Rust eBPF/XDP','system.brokerDetail':'pidfd + evidence recheck','system.controlDetail':'Go standard library','system.dashboardDetail':'Same-origin, CSP, session authentication',
  'auth.title':'Dashboard key','auth.description':'The operator key remains only in this browser tab’s session storage.','auth.token':'Bearer token','auth.save':'Authorize session',
  'support.title':'Support VisionGaiaTechnology','support.description':'GeDefense is developed independently. Support funds sovereign open-source security, testing and infrastructure.','support.method':'Method','support.address':'Address','support.copy':'Copy','support.copied':'Address copied.','support.paypal':'Open PayPal','support.note':'Verify crypto addresses before every transfer. Use USDT only via ERC-20.','noscript':'The GeDefense Command Center requires local JavaScript.',
  'dynamic.noManagement':'No management network configured. Enforce remains safely blocked.','dynamic.synced':'SYNCHRONIZED','dynamic.pending':'PENDING','dynamic.remove':'Remove','dynamic.managementRemoved':'Management network removed.','dynamic.controlSafe':'Control-only safe mode','dynamic.rustOffline':'Rust Core offline','dynamic.authVgt':'Authenticated VGT3 · {mode}','dynamic.incidents':'{value} incidents','dynamic.drops':'{value} drops','dynamic.warm':'{value} warm','dynamic.hmacChain':'AES-GCM + HMAC chain + head checkpoint','dynamic.safeMode':'Safe control-only mode','dynamic.protectedObjects':'{value} protected objects','dynamic.noSigner':'no signer','dynamic.generation':'generation {value}','dynamic.profilesWarm':'{profiles} profiles · {warm} warm','dynamic.since':'since {time}','dynamic.noEvents':'No security events yet.','dynamic.noRules':'No active block rules.','dynamic.noIncidents':'No XDR incidents yet.','dynamic.acknowledge':'Acknowledge','dynamic.noForensics':'No forensic records.','dynamic.noProfiles':'No behavior profiles loaded yet.','dynamic.allGates':'All current release gates are satisfied.',
  'dynamic.noCustomRules':'No custom operator rules configured.',
  'dynamic.failSafeVerified':'Authenticated kernel empty-state confirmed.','dynamic.failSafeUnverified':'Kernel state unconfirmed; out-of-band verification required.',
  'toast.ruleRemoved':'Block rule removed.','toast.incidentAck':'Incident acknowledged.','toast.operatorRequired':'Operator key required.','toast.operationFailed':'Operation failed','toast.sessionUpdated':'Operator session updated.','toast.policyActivated':'New network policy activated.','toast.feedStarted':'Threat-feed synchronization started.','toast.profilesLoaded':'Behavior profiles loaded.','toast.forensicsCreated':'Forensics export created.','toast.phaseChanged':'Beta phase signed and activated.','toast.emergencyActive':'Emergency Stop active. All active responses are blocked.','toast.emergencyCleared':'Emergency Stop cleared. GeDefense remains in Observe.','toast.settingsActivated':'Runtime settings activated.','toast.allowlistSynced':'Management network synchronized with Rust Core.','message.policySet':'Policy was signed and activated.','message.policyFailed':'Policy could not be created.','message.settingsSaved':'Settings were AES-256-GCM encrypted, HMAC-authenticated, saved and applied live.','message.settingsFailed':'Settings could not be saved.'
  ,'toast.customRuleSaved':'Custom rule validated, encrypted and activated.','toast.customRuleRemoved':'Custom rule removed.'
});

Object.assign(messages.ru, {
  ...messages.de,
  'skip.content':'Перейти к содержимому','nav.label':'Главная навигация','nav.overview':'Обзор','nav.network':'Сеть','nav.forensics':'Форензика','nav.release':'Бета-релиз','nav.settings':'Настройки','nav.system':'Система',
  'top.operator':'Ключ оператора','top.support':'Поддержать VGT','top.language':'Язык',
  'view.overview.title':'Обзор','view.network.title':'Сеть','view.forensics.title':'Форензика','view.settings.title':'Настройки','view.system.title':'Система',
  'overview.heading':'Защита, которая воспринимает хост как единую систему.','overview.description':'Rust XDP, подписанные снимки политик и Linux XDR связывают сеть, процессы, целостность и поведение — локально, прозрачно и без зависимости от облака.',
  'metric.rules':'Активные правила','metric.anomalies':'Аномалии','metric.ipc':'Проверка IPC','metric.sensorInit':'Инициализация сенсора','metric.signedCidrs':'подписанные CIDR-политики','metric.adaptive':'адаптивные отклонения',
  'network.throughput':'Трафик в реальном времени','network.chartLabel':'Сетевая пропускная способность','network.interface':'Интерфейс','stream.title':'Последние события',
  'xdr.description':'Сигналы процессов, сети, происхождения, целостности и поведения оцениваются как независимые категории.','xdr.processes':'Контролируемые процессы','xdr.processDetail':'текущие PID-идентичности','xdr.flows':'Внешние потоки','xdr.flowDetail':'связаны с процессами','xdr.evaluations':'Оценки','xdr.pipeline':'ограниченный worker-конвейер','xdr.queue':'Очередь','xdr.profiles':'Профили','xdr.loadProfiles':'Загрузить профили','xdr.incidents':'Коррелированные инциденты','xdr.behavior':'Поведенческие профили',
  'table.time':'Время','table.process':'Процесс','table.signals':'Сигналы','table.decision':'Решение','table.result':'Результат','table.avgConnections':'Ср. соединений','table.avgTargets':'Ср. целей','table.knownPorts':'Известные порты','table.lastSignal':'Последний сигнал',
  'network.heading':'Сетевая защита','network.description':'CIDR-правила нормализуются, ограничиваются по времени и сохраняются как подписанный снимок политики.','network.newRule':'Создать правило','network.target':'IP или CIDR цели','network.reason':'Причина','network.reasonPlaceholder':'Аномальное сканирование','network.ttl':'Срок действия','network.15m':'15 минут','network.1h':'1 час','network.6h':'6 часов','network.24h':'24 часа','network.activate':'Активировать политику','network.sync':'Синхронизировать Threat Feeds','network.rules':'Правила блокировки','network.feedVectors':'векторов фида','table.target':'Цель','table.source':'Источник','table.reason':'Причина','table.expiry':'Истекает','table.status':'Статус',
  'policy.description':'Каждое поколение правил детерминированно сериализуется, шифруется AES-256-GCM и подписывается Ed25519.','policy.signerDetail':'локальный якорь доверия Ed25519','policy.generationDetail':'монотонное состояние политики','policy.lastUpdate':'Последнее обновление','policy.updateDetail':'UTC-подписанный снимок','policy.lifecycle':'Жизненный цикл политики','policy.apiValidation':'Проверка API','policy.strictJson':'строгий JSON + защита от replay','policy.mutation':'Изменение состояния','policy.normalized':'нормализованное CIDR-правило','policy.signature':'Подпись Ed25519','policy.deterministic':'детерминированное поколение','policy.ipc':'аутентифицированный VGT3 IPC',
  'forensics.heading':'Форензика','forensics.description':'Инциденты редактируются, шифруются AES-256-GCM, связываются HMAC-цепочкой и проверяются по атомарному checkpoint.','forensics.export':'Создать экспорт','forensics.chain':'Цепочка инцидентов','forensics.initializing':'Инициализация','forensics.records':'аутентифицированные записи','forensics.responses':'Реакции','forensics.broker':'Решения брокера','forensics.history':'История инцидентов','table.summary':'Описание',
  'release.description':'Активная реакция включается только поэтапно. Observe, Canary и Enforce имеют отдельные условия здоровья, выдержки и отката.','release.startPhase':'Начальная фаза','release.gateCheck':'Проверка gate','release.failures':'последовательных ошибок','release.change':'Сменить фазу','release.target':'Целевая фаза','release.observe':'Вернуться в Observe','release.reason':'Причина разрешения','release.reasonPlaceholder':'Canary после завершённой фазы наблюдения','release.confirmation':'Явное подтверждение','release.submit':'Проверить gate и переключить','release.confirmationHint':'Подтверждения: PROMOTE:CANARY, PROMOTE:ENFORCE или RETURN:OBSERVE.','release.emergencyDescription':'Создаёт локальный стоп-якорь, переводит сеть и XDR в Observe и блокирует повышение до ручного снятия.','release.emergencyReasonPlaceholder':'Обнаружено неожиданное поведение реакции','release.emergencySubmit':'Немедленно заблокировать активную реакцию','release.clearReason':'Причина снятия','release.clearReasonPlaceholder':'Причина проверена; система остаётся в Observe','release.clearSubmit':'Снять Emergency Stop','release.conditions':'Условия допуска',
  'release.kernelState':'Kernel fail-safe','release.kernelStateDetail':'Пустое состояние XDP должно быть подтверждено',
  'settings.description':'Модули и пороги реакции изменяются на лету, шифруются AES-256-GCM, аутентифицируются HMAC и применяются без перезапуска.','settings.components':'Активные компоненты','settings.xdrDetail':'Процессы, целостность и pipeline реакции','settings.network':'Сетевая корреляция','settings.networkDetail':'Связывать внешние потоки с процессами','settings.behaviorDetail':'Адаптивные MAC-защищённые профили процессов','settings.feedsDetail':'Локально подготавливать публичные префиксы','settings.autoFeeds':'Автосинхронизация фидов','settings.autoFeedsDetail':'Синхронизация по заданному интервалу','settings.autoDegradeDetail':'Возврат в Observe при ошибке Core, политики или сенсора','settings.tuning':'Интервалы и пороги','settings.processScan':'Скан процессов (мс)','settings.networkScan':'Скан сети (с)','settings.save':'Сохранить зашифрованные настройки','settings.allowlist':'Management-Allowlist','settings.required':'Обязательно перед Enforce','settings.ipCidr':'IP или CIDR','settings.add':'Добавить','table.networkCidr':'Сеть/CIDR','table.kernelProtection':'Защита ядра',
  'settings.ruleModules':'Связать модули правил','settings.observeOnly':'Изменяется только в Observe/Degraded','settings.moduleCommand':'Встроенный RE2-анализ команд','settings.moduleOrigin':'memfd, удалённые и временные executable','settings.moduleLineage':'Корреляция родительских и дочерних процессов','settings.moduleMasquerading':'Имя процесса против пути executable','settings.moduleThreat':'Remote IP против подготовленных префиксов','settings.moduleBaseline':'Локальная baseline процессов и сети','settings.customRules':'Пользовательские RE2-правила','settings.alertOnly':'Только сигнал и score; без прямого разрешения kill','settings.ruleId':'ID правила','settings.category':'Категория','settings.score':'Score','settings.summary':'Описание','settings.pattern':'RE2-pattern','settings.addRule':'Сохранить зашифрованное правило',
  'system.description':'Состояние привилегированных и непривилегированных доменов безопасности.','system.dataPlane':'Data Plane','system.notSynced':'Ещё не синхронизировано','system.domains':'Разделённые зоны доверия','system.kernelDetail':'Rust eBPF/XDP','system.brokerDetail':'pidfd + повторная проверка доказательств','system.controlDetail':'Стандартная библиотека Go','system.dashboardDetail':'Same-Origin, CSP, сессионная аутентификация',
  'auth.title':'Ключ Dashboard','auth.description':'Ключ оператора хранится только в оперативной памяти этой вкладки и удаляется при перезагрузке.','auth.token':'Bearer Token','auth.save':'Авторизовать сессию',
  'support.title':'Поддержать VisionGaiaTechnology','support.description':'GeDefense развивается независимо. Поддержка финансирует суверенную open-source безопасность, тестирование и инфраструктуру.','support.method':'Метод','support.address':'Адрес','support.copy':'Копировать','support.copied':'Адрес скопирован.','support.paypal':'Открыть PayPal','support.note':'Проверяйте криптоадрес перед каждым переводом. USDT — только ERC-20.','noscript':'GeDefense Command Center требует локальный JavaScript.',
  'dynamic.noManagement':'Management-сеть не задана. Enforce остаётся безопасно заблокирован.','dynamic.synced':'СИНХРОНИЗИРОВАНО','dynamic.pending':'ОЖИДАЕТ','dynamic.remove':'Удалить','dynamic.managementRemoved':'Management-сеть удалена.','dynamic.controlSafe':'Безопасный Control-only режим','dynamic.rustOffline':'Rust Core отключён','dynamic.authVgt':'Аутентифицированный VGT3 · {mode}','dynamic.incidents':'Инцидентов: {value}','dynamic.drops':'Потерь: {value}','dynamic.warm':'Прогрето: {value}','dynamic.hmacChain':'AES-GCM + HMAC-цепочка + checkpoint','dynamic.safeMode':'Безопасный Control-only режим','dynamic.protectedObjects':'Защищённых объектов: {value}','dynamic.noSigner':'нет signer','dynamic.generation':'поколение {value}','dynamic.profilesWarm':'Профилей: {profiles} · прогрето: {warm}','dynamic.since':'с {time}','dynamic.noEvents':'Событий безопасности пока нет.','dynamic.noRules':'Активных правил блокировки нет.','dynamic.noIncidents':'XDR-инцидентов пока нет.','dynamic.acknowledge':'Подтвердить','dynamic.noForensics':'Форензик-записей нет.','dynamic.noProfiles':'Поведенческие профили ещё не загружены.','dynamic.allGates':'Все текущие условия допуска выполнены.',
  'dynamic.noCustomRules':'Пользовательские правила оператора не настроены.',
  'dynamic.failSafeVerified':'Аутентифицированное пустое состояние kernel подтверждено.','dynamic.failSafeUnverified':'Состояние kernel не подтверждено; требуется out-of-band проверка.',
  'toast.ruleRemoved':'Правило блокировки удалено.','toast.incidentAck':'Инцидент подтверждён.','toast.operatorRequired':'Требуется ключ оператора.','toast.operationFailed':'Операция не выполнена','toast.sessionUpdated':'Сессия оператора обновлена.','toast.policyActivated':'Новая сетевая политика активирована.','toast.feedStarted':'Синхронизация Threat Feed запущена.','toast.profilesLoaded':'Поведенческие профили загружены.','toast.forensicsCreated':'Форензик-экспорт создан.','toast.phaseChanged':'Бета-фаза подписана и активирована.','toast.emergencyActive':'Emergency Stop активен. Все активные реакции заблокированы.','toast.emergencyCleared':'Emergency Stop снят. GeDefense остаётся в Observe.','toast.settingsActivated':'Runtime-настройки активированы.','toast.allowlistSynced':'Management-сеть синхронизирована с Rust Core.','message.policySet':'Политика подписана и активирована.','message.policyFailed':'Не удалось создать политику.','message.settingsSaved':'Настройки зашифрованы AES-256-GCM, аутентифицированы HMAC, сохранены и применены.','message.settingsFailed':'Не удалось сохранить настройки.'
  ,'toast.customRuleSaved':'Пользовательское правило проверено, зашифровано и активировано.','toast.customRuleRemoved':'Пользовательское правило удалено.'
});


// Explicit coverage for every static or dynamic key used by the Command Center.
// Keeping these entries explicit prevents a newly selected language from silently
// falling back to German for technical status labels.
Object.assign(messages.en, {
  'auth.eyebrow':'OPERATOR ACCESS','brand.powered':'powered by VisionGaiaTechnology','dialog.close':'Close',
  'dynamic.allowlist':'Allowlist {state}','dynamic.apiOffline':'API OFFLINE','dynamic.blocked':'BLOCKED','dynamic.controlOnly':'CONTROL ONLY',
  'dynamic.degraded':'DEGRADED','dynamic.disabled':'DISABLED','dynamic.enableAction':'Enable','dynamic.disableAction':'Disable','dynamic.failed':'FAILED','dynamic.integrityFailure':'INTEGRITY FAILURE',
  'dynamic.kernel':'KERNEL','dynamic.kernelShield':'KERNEL SHIELD ACTIVE','dynamic.locked':'LOCKED','dynamic.macVerified':'MAC VERIFIED',
  'dynamic.nominal':'SYSTEM NOMINAL','dynamic.observe':'OBSERVE','dynamic.observeFabric':'OBSERVE FABRIC','dynamic.offline':'OFFLINE',
  'dynamic.online':'ONLINE','dynamic.operatorLocked':'OPERATOR LOCKED','dynamic.quarantined':'QUARANTINED','dynamic.ready':'READY',
  'dynamic.revision':'REVISION {value}','dynamic.signatureFailure':'SIGNATURE FAILURE','dynamic.signatureVerified':'SIGNATURE VERIFIED','dynamic.verified':'VERIFIED',
  'footer.powered':`GeDefense ${VERSION} powered by VisionGaiaTechnology`,'forensics.incidents':'Incidents',
  'metric.kernel':'Kernel Core','metric.uptime':'Uptime','metric.xdr':'XDR Engine','nav.policy':'Policy Trust','nav.xdr':'GeDefense XDR',
  'network.pulse':'NETWORK PULSE','overview.kicker':`GEDEFENSE ${VERSION} // FULL STACK BETA`,
  'policy.core':'Rust Core','policy.generation':'Generation','policy.signer':'Signer',
  'release.canary':'Canary / Contain','release.emergency':'Emergency Stop','release.enforce':'Enforce','release.heartbeat':'Core heartbeat',
  'release.phase':'Phase','release.readiness':'Readiness','settings.alert':'Alert score','settings.autoDegrade':'Auto-degrade',
  'settings.behavior':'Behavior learning','settings.contain':'Contain score','settings.feeds':'Threat feeds','settings.heading':'Settings',
  'settings.kill':'Kill score','settings.xdr':'XDR sensor','system.behavior':'Behavior store','system.broker':'Privileged broker',
  'system.control':'Control plane','system.dashboard':'Dashboard','system.feeds':'Feed matrix','system.heading':'System',
  'system.kernel':'Kernel','system.node':'Node','system.policy':'Policy','system.xdr':'XDR sensor',
  'table.action':'Action','table.executable':'Executable','table.id':'ID','table.samples':'Samples','table.score':'Score','table.severity':'Severity'
});

Object.assign(messages.ru, {
  'auth.eyebrow':'ДОСТУП ОПЕРАТОРА','brand.powered':'на базе VisionGaiaTechnology','dialog.close':'Закрыть',
  'dynamic.allowlist':'Список доступа: {state}','dynamic.apiOffline':'API НЕДОСТУПЕН','dynamic.blocked':'ЗАБЛОКИРОВАНО','dynamic.controlOnly':'ТОЛЬКО УПРАВЛЕНИЕ',
  'dynamic.degraded':'ДЕГРАДИРОВАНО','dynamic.disabled':'ОТКЛЮЧЕНО','dynamic.enableAction':'Включить','dynamic.disableAction':'Отключить','dynamic.failed':'ОШИБКА','dynamic.integrityFailure':'ОШИБКА ЦЕЛОСТНОСТИ',
  'dynamic.kernel':'ЯДРО','dynamic.kernelShield':'ЗАЩИТА ЯДРА АКТИВНА','dynamic.locked':'ЗАБЛОКИРОВАНО','dynamic.macVerified':'MAC ПОДТВЕРЖДЁН',
  'dynamic.nominal':'СИСТЕМА В НОРМЕ','dynamic.observe':'НАБЛЮДЕНИЕ','dynamic.observeFabric':'КОНТУР НАБЛЮДЕНИЯ','dynamic.offline':'ОФЛАЙН',
  'dynamic.online':'ОНЛАЙН','dynamic.operatorLocked':'ОПЕРАТОР ЗАБЛОКИРОВАН','dynamic.quarantined':'В КАРАНТИНЕ','dynamic.ready':'ГОТОВО',
  'dynamic.revision':'РЕВИЗИЯ {value}','dynamic.signatureFailure':'ОШИБКА ПОДПИСИ','dynamic.signatureVerified':'ПОДПИСЬ ПОДТВЕРЖДЕНА','dynamic.verified':'ПОДТВЕРЖДЕНО',
  'footer.powered':`GeDefense ${VERSION} на базе VisionGaiaTechnology`,'forensics.incidents':'Инциденты',
  'metric.kernel':'Ядро','metric.uptime':'Время работы','metric.xdr':'Движок XDR','nav.policy':'Доверие политики','nav.xdr':'GeDefense XDR',
  'network.pulse':'СЕТЕВОЙ ПУЛЬС','overview.kicker':`GEDEFENSE ${VERSION} // ПОЛНАЯ БЕТА`,
  'policy.core':'Rust Core','policy.generation':'Поколение','policy.signer':'Подписант',
  'release.canary':'Canary / Сдерживание','release.emergency':'Аварийная остановка','release.enforce':'Принудительная защита','release.heartbeat':'Пульс ядра',
  'release.phase':'Фаза','release.readiness':'Готовность','settings.alert':'Порог предупреждения','settings.autoDegrade':'Автодеградация',
  'settings.behavior':'Обучение поведения','settings.contain':'Порог сдерживания','settings.feeds':'Фиды угроз','settings.heading':'Настройки',
  'settings.kill':'Порог завершения','settings.xdr':'Сенсор XDR','system.behavior':'Хранилище поведения','system.broker':'Привилегированный брокер',
  'system.control':'Плоскость управления','system.dashboard':'Панель управления','system.feeds':'Матрица фидов','system.heading':'Система',
  'system.kernel':'Ядро','system.node':'Узел','system.policy':'Политика','system.xdr':'Сенсор XDR',
  'table.action':'Действие','table.executable':'Исполняемый файл','table.id':'ID','table.samples':'Образцы','table.score':'Оценка','table.severity':'Критичность'
});

Object.assign(messages.de, {
  'hardening.heading':'Systemhärtung',
  'hardening.description':'Profile werden zuerst gegen den Live-Kernel vorgeprüft und nur mit transaktionsgebundener Bestätigung angewendet.',
  'hardening.profile':'Profil','hardening.reason':'Begründung','hardening.preview':'Live-Zustand vorprüfen',
  'hardening.selected':'Ausgewählte Transaktion','hardening.confirmation':'Exakte Bestätigung',
  'hardening.execute':'Transaktion ausführen','hardening.apply':'Geprüfte Änderung anwenden',
  'hardening.reverse':'Änderung verifiziert rückgängig machen','hardening.selectApply':'Anwenden auswählen',
  'hardening.selectReverse':'Rücknahme auswählen','hardening.noTransactions':'Noch keine Sicherheitstransaktionen.',
  'hardening.planUnavailable':'Der Plan bleibt nach der Anwendung im verschlüsselten Transaktionsspeicher.',
  'hardening.summary':'Hardening-Profil {profile}','hardening.previewReady':'Live-Preview wurde verschlüsselt gespeichert.',
  'hardening.applied':'Hardening wurde angewendet und gegen den Kernel verifiziert.',
  'hardening.reversed':'Hardening wurde rückgängig gemacht und verifiziert.','table.type':'Typ'
});

Object.assign(messages.en, {
  'hardening.heading':'System hardening',
  'hardening.description':'Profiles are previewed against the live kernel and applied only with transaction-bound confirmation.',
  'hardening.profile':'Profile','hardening.reason':'Reason','hardening.preview':'Preview live state',
  'hardening.selected':'Selected transaction','hardening.confirmation':'Exact confirmation',
  'hardening.execute':'Execute transaction','hardening.apply':'Apply verified change',
  'hardening.reverse':'Reverse and verify change','hardening.selectApply':'Select apply',
  'hardening.selectReverse':'Select reverse','hardening.noTransactions':'No security transactions yet.',
  'hardening.planUnavailable':'The plan remains in encrypted transaction storage after application.',
  'hardening.summary':'Hardening profile {profile}','hardening.previewReady':'The live preview was stored encrypted.',
  'hardening.applied':'Hardening was applied and verified against the kernel.',
  'hardening.reversed':'Hardening was reversed and verified.','table.type':'Type'
});

Object.assign(messages.ru, {
  'hardening.heading':'Усиление защиты системы',
  'hardening.description':'Профили предварительно сверяются с работающим ядром и применяются только с подтверждением, привязанным к транзакции.',
  'hardening.profile':'Профиль','hardening.reason':'Причина','hardening.preview':'Проверить текущее состояние',
  'hardening.selected':'Выбранная транзакция','hardening.confirmation':'Точное подтверждение',
  'hardening.execute':'Выполнить транзакцию','hardening.apply':'Применить проверенное изменение',
  'hardening.reverse':'Отменить и проверить изменение','hardening.selectApply':'Выбрать применение',
  'hardening.selectReverse':'Выбрать отмену','hardening.noTransactions':'Транзакций безопасности пока нет.',
  'hardening.planUnavailable':'После применения план хранится в зашифрованном журнале транзакций.',
  'hardening.summary':'Профиль усиления {profile}','hardening.previewReady':'Предварительный просмотр сохранён в зашифрованном виде.',
  'hardening.applied':'Усиление применено и проверено по состоянию ядра.',
  'hardening.reversed':'Усиление отменено и проверено.','table.type':'Тип'
});

Object.assign(messages.de, {
  'quarantine.heading':'Dateiquarantäne',
  'quarantine.description':'Dateien werden vor der Mutation gegen ihre unveränderliche Identität geprüft, atomar erfasst und verschlüsselt gespeichert.',
  'quarantine.path':'Absoluter Dateipfad','quarantine.reason':'Begründung',
  'quarantine.preview':'Identität prüfen','quarantine.size':'Größe',
  'quarantine.empty':'Keine aktiven Quarantäneobjekte.',
  'quarantine.previewReady':'Die Quarantäne-Vorschau wurde unveränderlich gespeichert.',
  'quarantine.transactionUnavailable':'Die Quarantäne-Transaktion ist nicht mehr verfügbar.'
});

Object.assign(messages.en, {
  'quarantine.heading':'File quarantine',
  'quarantine.description':'Files are checked against immutable identity, captured atomically, and stored encrypted before mutation.',
  'quarantine.path':'Absolute file path','quarantine.reason':'Reason',
  'quarantine.preview':'Verify identity','quarantine.size':'Size',
  'quarantine.empty':'No active quarantine objects.',
  'quarantine.previewReady':'The quarantine preview was committed immutably.',
  'quarantine.transactionUnavailable':'The quarantine transaction is no longer available.'
});

Object.assign(messages.ru, {
  'quarantine.heading':'Карантин файлов',
  'quarantine.description':'Перед изменением файл проверяется по неизменяемой идентичности, атомарно захватывается и сохраняется в зашифрованном виде.',
  'quarantine.path':'Абсолютный путь к файлу','quarantine.reason':'Причина',
  'quarantine.preview':'Проверить идентичность','quarantine.size':'Размер',
  'quarantine.empty':'Активных объектов карантина нет.',
  'quarantine.previewReady':'Предпросмотр карантина сохранён с неизменяемой привязкой.',
  'quarantine.transactionUnavailable':'Транзакция карантина больше недоступна.'
});

Object.assign(messages.de, {
  'cases.heading':'Security Cases','cases.selected':'Ausgewählter Fall',
  'cases.resolution':'Auflösung','cases.commit':'Status beweisbar speichern',
  'cases.occurrences':'Vorkommen','cases.empty':'Noch keine korrelierten Security Cases.',
  'cases.select':'Auswählen','cases.selectionRequired':'Zuerst einen Security Case auswählen.',
  'cases.saved':'Der Case-Status wurde verschlüsselt und beweisbar gespeichert.'
});
Object.assign(messages.en, {
  'cases.heading':'Security cases','cases.selected':'Selected case',
  'cases.resolution':'Resolution','cases.commit':'Commit status with evidence',
  'cases.occurrences':'Occurrences','cases.empty':'No correlated security cases yet.',
  'cases.select':'Select','cases.selectionRequired':'Select a security case first.',
  'cases.saved':'The case status was stored encrypted with durable evidence.'
});
Object.assign(messages.ru, {
  'cases.heading':'Дела безопасности','cases.selected':'Выбранное дело',
  'cases.resolution':'Решение','cases.commit':'Сохранить статус с доказательством',
  'cases.occurrences':'Срабатывания','cases.empty':'Коррелированных дел безопасности пока нет.',
  'cases.select':'Выбрать','cases.selectionRequired':'Сначала выберите дело безопасности.',
  'cases.saved':'Статус дела сохранён в зашифрованном виде с доказательством.'
});

Object.assign(messages.de, {
  'cells.heading':'Gaia Cells','cells.description':'GeDefense bindet Aktionen an UUID, Lifecycle-Generation und Kernel-cgroup-ID. Labels werden ausschließlich als untrusted Anzeige behandelt.',
  'cells.reason':'Begründung für Isolation','cells.label':'Label','cells.class':'Klasse','cells.network':'Netzwerk',
  'cells.empty':'Keine Gaia Cells gemeldet.','cells.runtimeMissing':'Die Gaia-Cells-Runtime ist in GaiaOS noch nicht installiert.',
  'cells.freeze':'Einfrieren','cells.revokeNetwork':'Netz entziehen',
  'cells.reasonRequired':'Eine Begründung mit mindestens drei Zeichen ist erforderlich.',
  'cells.previewReady':'Die Cell-Aktion wurde an ihre Kernelidentität gebunden und als Vorschau gespeichert.'
});
Object.assign(messages.en, {
  'cells.heading':'Gaia Cells','cells.description':'GeDefense binds actions to UUID, lifecycle generation, and kernel cgroup ID. Labels are treated only as untrusted display data.',
  'cells.reason':'Isolation reason','cells.label':'Label','cells.class':'Class','cells.network':'Network',
  'cells.empty':'No Gaia Cells reported.','cells.runtimeMissing':'The Gaia Cells runtime is not installed in GaiaOS yet.',
  'cells.freeze':'Freeze','cells.revokeNetwork':'Revoke network',
  'cells.reasonRequired':'A reason of at least three characters is required.',
  'cells.previewReady':'The Cell action was bound to its kernel identity and stored as a preview.'
});
Object.assign(messages.ru, {
  'cells.heading':'Gaia Cells','cells.description':'GeDefense привязывает действия к UUID, поколению жизненного цикла и kernel cgroup ID. Метки используются только как недоверенные отображаемые данные.',
  'cells.reason':'Причина изоляции','cells.label':'Метка','cells.class':'Класс','cells.network':'Сеть',
  'cells.empty':'Gaia Cells не обнаружены.','cells.runtimeMissing':'Среда выполнения Gaia Cells ещё не установлена в GaiaOS.',
  'cells.freeze':'Заморозить','cells.revokeNetwork':'Отключить сеть',
  'cells.reasonRequired':'Требуется причина длиной не менее трёх символов.',
  'cells.previewReady':'Действие Cell привязано к идентичности ядра и сохранено как предпросмотр.'
});

let current = 'de';

function detectLanguage() {
  const query = new URLSearchParams(location.search).get('lang');
  if (SUPPORTED.has(query)) return query;
  try {
    const saved = localStorage.getItem('gedefense-language');
    if (SUPPORTED.has(saved)) return saved;
  } catch (_) { /* storage may be disabled */ }
  const browser = String(navigator.language || 'de').toLowerCase().split('-')[0];
  return SUPPORTED.has(browser) ? browser : 'de';
}

function interpolate(value, vars) {
  return String(value).replace(/\{([a-zA-Z0-9_]+)\}/g, (_, key) => String(vars[key] ?? `{${key}}`));
}

export function t(key, vars = {}) {
  const table = messages[current] || messages.de;
  return interpolate(table[key] ?? messages.de[key] ?? key, vars);
}

export function language() { return current; }
export function locale() { return LOCALES[current] || LOCALES.de; }

export function applyTranslations(root = document) {
  document.documentElement.lang = current;
  document.title = t('app.title');
  root.querySelectorAll('[data-i18n]').forEach(node => { node.textContent = t(node.dataset.i18n); });
  root.querySelectorAll('[data-i18n-placeholder]').forEach(node => { node.setAttribute('placeholder', t(node.dataset.i18nPlaceholder)); });
  root.querySelectorAll('[data-i18n-aria]').forEach(node => { node.setAttribute('aria-label', t(node.dataset.i18nAria)); });
  root.querySelectorAll('[data-i18n-title]').forEach(node => { node.setAttribute('title', t(node.dataset.i18nTitle)); });
  const selector = document.getElementById('languageSelect');
  if (selector) selector.value = current;
}

export function setLanguage(next, { updateURL = true } = {}) {
  current = SUPPORTED.has(next) ? next : 'de';
  try { localStorage.setItem('gedefense-language', current); } catch (_) { /* ignored */ }
  document.cookie = `vgt_gedefense_lang=${current}; Path=/; Max-Age=31536000; SameSite=Strict; Secure`;
  if (updateURL) {
    const url = new URL(location.href);
    url.searchParams.set('lang', current);
    history.replaceState(null, '', `${url.pathname}${url.search}${url.hash}`);
  }
  applyTranslations();
  document.dispatchEvent(new CustomEvent('gedefense:language', { detail: { language: current, locale: locale() } }));
}

export function initializeI18n() {
  current = detectLanguage();
  setLanguage(current, { updateURL: false });
  return current;
}
