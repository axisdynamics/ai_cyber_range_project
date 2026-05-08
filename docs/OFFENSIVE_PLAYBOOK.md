# Offensive Playbook — AI Cyber Range

> *"Institucionalizar el ataque autorizado antes del ataque real,
>  usando IA para acelerar descubrimiento, validación y remediación
>  bajo reglas propias."*

---

## Filosofía

El Cyber Range no simula ataques para demostrar capacidad técnica.
Simula ataques para **encontrar los gaps de detección antes que el atacante**.

Cada escenario sigue tres preguntas:
1. ¿Podría un atacante ejecutar esta técnica contra este activo?
2. ¿Lo detectaríamos?
3. Si no: ¿qué regla, control o configuración necesitamos?

---

## Perimeter de engagement

### Activos autorizados

| Asset ID | Tipo | Criticidad |
|----------|------|-----------|
| `iam_role_demo` | Gestión de identidad | 5 (máxima) |
| `secrets_store_demo` | Almacén de secretos | 5 |
| `api_gateway_demo` | Perímetro de API | 4 |
| `pipeline_demo` | CI/CD pipeline | 4 |
| `cloud_storage_demo` | Almacenamiento cloud | 3 |
| `local_c_lab_service` | Servicio C compilado | 3 |
| `fixtures.synthetic_logs` | Fixture de logs | 2 |
| `fixtures.asset_graph` | Fixture de activos | 2 |

### Técnicas autorizadas

| ID | Nombre | Tactic | Superficie C |
|----|--------|--------|-------------|
| T1190 | Exploit Public-Facing Application | Initial Access | `add`, `echo`, `auth`, `alloc` |
| T1078 | Valid Accounts | Initial Access / Cred. Access | `auth` |
| T1059 | Command Scripting Interpreter | Execution | `exec` |
| T1053 | Scheduled Task/Job | Persistence | `persist` |
| T1548 | Abuse Elevation Control | Privilege Escalation | `privesc` |
| T1562 | Impair Defenses | Defense Evasion | detector gap check |
| T1003 | OS Credential Dumping | Credential Access | `collect` |
| T1082 | System Information Discovery | Discovery | `env` |
| T1021 | Remote Services | Lateral Movement | `lateral` |
| T1005 | Data from Local System | Collection | `collect` |
| T1041 | Exfiltration Over C2 | Exfiltration | `exfil` |
| T1499 | Endpoint DoS | Impact | `dos` |

### Técnicas bloqueadas (hardcoded en governance)

- **T1485** — Data Destruction
- **T1561** — Disk Wipe
- **T1529** — System Shutdown/Reboot

---

## Kill chain estándar (depth=6)

Cada hipótesis de ataque se expande en una cadena de 6 tácticas siguiendo
el orden MITRE ATT&CK. El `AttackChainSimulator` parte de la técnica inicial
y propaga hacia las tácticas siguientes.

```
Initial Access (T1190, T1078)
    ↓
Execution (T1059, T1053)
    ↓
Privilege Escalation (T1548)
    ↓
Defense Evasion (T1562)
    ↓
Credential Access (T1003)
    ↓
Lateral Movement (T1021) → Collection (T1005) → Exfiltration (T1041)
                                                → Impact (T1499)
```

---

## Protocolo de ejecución por técnica

### T1190 — Exploit Public-Facing Application

**Objetivo**: validar controles de input validation en el C service.

```bash
./c_service/build/lab_service add "$(python3 -c "print('A'*300)")"
# Esperado: WARN: input_validation_warning  (RC=3)

./c_service/build/lab_service echo "%s%n%x"
# Esperado: WARN: format_specifiers_detected  (RC=3)

./c_service/build/lab_service alloc 2000000
# Esperado: WARN: alloc_too_large  (RC=3)
```

**Gap esperado**: si el binario no emite `input_validation_warning`, el scoring
aplica penalización máxima.

---

### T1078 — Valid Accounts

**Objetivo**: detectar uso de credenciales válidas sin MFA.

```bash
./c_service/build/lab_service auth admin SYNTHETIC_VALID_TOKEN_1234
# Esperado: AUTH_OK + SYNTHETIC_VALID_TOKEN_1234 en stdout
# IoC IOC-001 debe dispararse en el IoCMatcher
```

**Regla de detección necesaria:**
```
SIEM: alert when auth_ok without 2FA_confirmed in same session
UEBA: baseline de horario + geolocalización para service accounts
```

---

### T1548 — Abuse Elevation Control Mechanism

**Objetivo**: encontrar paths de escalación en el activo.

```bash
./c_service/build/lab_service privesc
# Esperado: SYNTHETIC_PRIVILEGE_TEST + lista de binarios SUID
# IoC IOC-006 debe dispararse
```

**Regla de detección necesaria:**
```
EDR: alert on setuid() syscall from non-root process
PAM: log all elevation events to immutable storage
```

---

### T1059 — Command Scripting Interpreter

**Objetivo**: inyección de comandos en entradas no sanitizadas.

```bash
./c_service/build/lab_service exec "echo ok; id"
# Esperado: EXEC_BLOCKED + injection_detected  (RC=3)

./c_service/build/lab_service exec "echo hello"
# Esperado: EXEC_SIMULATED  (RC=0) — baseline limpio
```

**Regla de detección necesaria (SIGMA):**
```yaml
title: Shell Metacharacters in Service Input
detection:
  keywords: ['; id', '| bash', '$(', '`']
  field: process.args
```

---

### T1041 — Exfiltration Over C2 Channel

**Objetivo**: detectar canales de exfiltración DNS y HTTP.

```bash
./c_service/build/lab_service exfil "sensitive_data_payload"
# Esperado: SYNTHETIC_EXFIL_EVENT_NO_REAL_DATA + DNS marker
# IoC IOC-002, IOC-003, IOC-004 deben dispararse
```

**Controles necesarios:**
```
Egress filtering: allowlist-only outbound
DNS monitoring: alert on *.attacker.invalid, *.invalid TLDs
DLP: alert on outbound transfer >1MB to unknown destination
```

---

### T1021 — Remote Services (Lateral Movement)

**Objetivo**: validar segmentación entre activos.

```bash
# Target válido (fixture)
./c_service/build/lab_service lateral api_gateway_demo
# Esperado: LATERAL_MOVE + SYNTHETIC_PIVOT_REQUEST  (RC=0)

# Target externo (bloqueado por soberanía)
./c_service/build/lab_service lateral 10.0.0.1
# Esperado: SOVEREIGNTY_VIOLATION  (RC=3)
```

**Regla de detección necesaria:**
```
Network: alert on SSH/RDP from workstation to internal service
East-west: baseline inter-service communication, alert on new flows
```

---

## Evasion testing

El `EvasionTester` prueba cada control activo contra la técnica:

```
Para cada técnica T:
  Para cada control C registrado para T:
    Evasion test: ¿puede ejecutarse T sin que C lo detecte?
    Si sí → control_evaded=True → penalización en score
    Si no → control_effective=True → bonus en score

Resultado: evasion_rate = evaded / total_controls_tested
Resultado actual: 62.9% (53/84 controles evadidos)
```

Un gap de 62.9% significa que casi 2 de cada 3 controles pueden ser evadidos.
El objetivo es llegar a <40% antes del próximo trimestre.

---

## Criterios de cierre de escenario

Un escenario puede marcarse como `done` SOLO si:

1. ✅ Finding tiene `finding_id` no vacío
2. ✅ `artifacts/evidence/EVD-*.json` existe en disco
3. ✅ `hash_sha256` tiene 64 caracteres hex
4. ✅ `chain_of_custody` tiene al menos 1 entrada
5. ✅ Asset está dentro del `engagement_perimeter`
6. ✅ Técnica no está en la lista bloqueada
7. ✅ `blue_team_agent` emitió APPROVED en `progress/review_<id>.md`

Cualquier fallo → `REJECTED` automático → nunca entra al backlog de remediación.

---

*Powered by [AxisDynamics](https://axisdynamics.cl) · MIT License*
