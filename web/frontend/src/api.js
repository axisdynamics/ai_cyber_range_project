// Shared demo data — shown when API is unreachable
const _F = [
  {id:'FND-SCN-iam_role_demo-T1078',asset:'iam_role_demo',technique_id:'T1078',severity:'critical',detection_status:'gap',score:100,reproducible:true,poc_id:'POC-001',summary:'Credencial válida expuesta'},
  {id:'FND-SCN-iam_role_demo-T1548',asset:'iam_role_demo',technique_id:'T1548',severity:'critical',detection_status:'gap',score:100,reproducible:true,poc_id:'POC-002',summary:'Escalación de privilegios'},
  {id:'FND-SCN-secrets_store_demo-T1003',asset:'secrets_store_demo',technique_id:'T1003',severity:'critical',detection_status:'gap',score:100,reproducible:true,poc_id:'POC-003',summary:'Dump de credenciales'},
  {id:'FND-SCN-api_gateway_demo-T1041',asset:'api_gateway_demo',technique_id:'T1041',severity:'critical',detection_status:'gap',score:95,reproducible:true,poc_id:'POC-004',summary:'Exfiltración DNS no detectada'},
  {id:'FND-SCN-api_gateway_demo-T1059',asset:'api_gateway_demo',technique_id:'T1059',severity:'high',detection_status:'gap',score:87,reproducible:true,poc_id:'POC-005',summary:'Command injection'},
  {id:'FND-SCN-pipeline_demo-T1021',asset:'pipeline_demo',technique_id:'T1021',severity:'high',detection_status:'gap',score:87,reproducible:true,poc_id:'POC-006',summary:'Movimiento lateral'},
  {id:'FND-SCN-local_c_lab_service-T1190',asset:'local_c_lab_service',technique_id:'T1190',severity:'high',detection_status:'detected',score:62,reproducible:true,poc_id:'POC-007',summary:'Buffer overflow detectado'},
  {id:'FND-SCN-cloud_storage_demo-T1005',asset:'cloud_storage_demo',technique_id:'T1005',severity:'medium',detection_status:'gap',score:70,reproducible:true,poc_id:null,summary:'Datos sin clasificar accesibles'},
]
const _A = [
  {id:'ALT-001',source:'rule_engine',severity:'critical',confidence:.90,title:'[Rule] Shell Metacharacter Injection',description:'RULE-002 · metacaracter ";" detectado',tactic:'Execution',technique_ids:['T1059'],asset_id:'api_gateway_demo',rule_or_ioc_id:'RULE-002',requires_llm_review:false,detected_at:'2026-05-08T16:40:52Z'},
  {id:'ALT-002',source:'sigma_correlator',severity:'critical',confidence:.95,title:'[Sigma] Kill Chain: T1078 → T1003',description:'Secuencia credential access completada en ventana de 5 min',tactic:'Kill Chain',technique_ids:['T1078','T1003'],asset_id:'multi-asset',rule_or_ioc_id:'COR-002',requires_llm_review:false,detected_at:'2026-05-08T16:40:53Z'},
  {id:'ALT-003',source:'ioc_matcher',severity:'critical',confidence:1.0,title:'[IoC] SYNTHETIC_EXFIL_EVENT detectado',description:'IOC-002 encontrado en stdout · técnica T1041',tactic:'Exfiltration',technique_ids:['T1041'],asset_id:'api_gateway_demo',rule_or_ioc_id:'IOC-002',requires_llm_review:false,detected_at:'2026-05-08T16:40:54Z'},
  {id:'ALT-004',source:'rule_engine',severity:'critical',confidence:.80,title:'[Rule] Privilege Escalation Simulation',description:'RULE-005 · SYNTHETIC_PRIVILEGE_TEST detectado',tactic:'Privilege Escalation',technique_ids:['T1548'],asset_id:'iam_role_demo',rule_or_ioc_id:'RULE-005',requires_llm_review:false,detected_at:'2026-05-08T16:40:55Z'},
  {id:'ALT-005',source:'anomaly_detector',severity:'high',confidence:.78,title:'[Anomaly] detection_gap_rate (Z=2.8σ)',description:'Tasa de evasión 65.8% supera baseline por 2.8σ',tactic:'Statistical Anomaly',technique_ids:[],asset_id:'all',rule_or_ioc_id:'METRIC-gap_rate',requires_llm_review:false,detected_at:'2026-05-08T16:40:56Z'},
]
const _T = [
  {id:'REM-001',title:'[CRITICAL] Harden iam_role_demo contra T1078',priority:1,owner_team:'security',sla_days:1,status:'open',controls_to_apply:['Enforcer MFA en cuentas interactivas','Rotar credenciales comprometidas','Implementar UEBA'],detection_rules_needed:['PRIORITY: ZERO cobertura en T1078','Crear caso SIEM para esta variante']},
  {id:'REM-002',title:'[CRITICAL] Harden iam_role_demo contra T1548',priority:1,owner_team:'security',sla_days:1,status:'open',controls_to_apply:['Auditar reglas sudo','Habilitar logging PAM','JIT access'],detection_rules_needed:['EDR: alerta en cambio de UID no autorizado','PRIORITY: ZERO cobertura en T1548']},
  {id:'REM-003',title:'[HIGH] Harden api_gateway_demo contra T1059',priority:2,owner_team:'platform',sla_days:7,status:'open',controls_to_apply:['Allowlist de scripts (AppLocker/seccomp)','Reemplazar shell=True','Audit logging de comandos'],detection_rules_needed:['SIEM: Sigma rule para metacaracteres shell']},
  {id:'REM-004',title:'[HIGH] Harden pipeline_demo contra T1021',priority:2,owner_team:'platform',sla_days:7,status:'open',controls_to_apply:['Micro-segmentación de red','Restringir SSH lateral','Monitoreo east-west'],detection_rules_needed:['Network: alerta en SSH workstation→servicio']},
  {id:'REM-005',title:'[MEDIUM] Harden cloud_storage_demo contra T1005',priority:3,owner_team:'engineering',sla_days:30,status:'open',controls_to_apply:['ACLs en directorios de datos','Auditoría de acceso a ficheros','Políticas DLP'],detection_rules_needed:['Audit: alerta en lectura masiva de ficheros','DLP: alerta en acceso a datos clasificados']},
]
const _E = [
  {id:'EVD-A1B2C3D4',asset_id:'iam_role_demo',technique_id:'T1078',evidence_type:'stdout',hash_sha256:'a1b2c3d4e5f6789012345678901234567890123456789012345678901234abcd',chain_of_custody:['collected by RedTeamAgent 2026-05-08T16:40:52Z','validated by blue_team_agent 2026-05-08T16:40:58Z'],collector:'RedTeamAgent',collected_at:'2026-05-08T16:40:52Z',content:'AUTH_OK: SYNTHETIC_VALID_TOKEN_1234 user=admin technique=T1078'},
  {id:'EVD-B2C3D4E5',asset_id:'api_gateway_demo',technique_id:'T1041',evidence_type:'stdout',hash_sha256:'b2c3d4e5f678901234567890123456789012345678901234567890abcdef12',chain_of_custody:['collected by RedTeamAgent 2026-05-08T16:40:53Z'],collector:'RedTeamAgent',collected_at:'2026-05-08T16:40:53Z',content:'SYNTHETIC_EXFIL_EVENT_NO_REAL_DATA channel=dns payload_len=17'},
  {id:'EVD-C3D4E5F6',asset_id:'pipeline_demo',technique_id:'T1548',evidence_type:'stdout',hash_sha256:'c3d4e5f6789012345678901234567890123456789012345678901234abcdef',chain_of_custody:['collected by RedTeamAgent 2026-05-08T16:40:54Z'],collector:'RedTeamAgent',collected_at:'2026-05-08T16:40:54Z',content:'SYNTHETIC_PRIVILEGE_TEST: escalation_path_simulation technique=T1548'},
]

export const DEMO = {
  status:  {status:'idle',run_id:'RUN-DEMO-001'},
  summary: {findings_count:35,critical_count:8,high_count:13,medium_count:11,low_count:3,coverage_pct:97.2,detection_gap_pct:65.8,hypotheses_generated:36,chains_simulated:36,evasion_tests_run:84,pocs_built:36,run_id:'RUN-DEMO-001',scenario_count:39,open_tickets:35,sla_breach_count:8,top_findings:_F.slice(0,6)},
  findings: {count:_F.length,total:35,findings:_F},
  detections: {total_events_processed:113,rule_matches:7,correlation_alerts:4,ioc_matches:6,anomaly_alerts:2,llm_enrichments:0,novel_events_count:3,llm_analysis_summary:'Modo demo — 3 eventos novedosos. Revisar escalación en activos IAM.',engine_stats:{rule_engine_rules:12,sigma_rules:7,ioc_count:12,tracked_metrics:5,llm_available:false,mythos_available:false,mythos_experts:9,mythos_last_loops:0,mythos_last_converged:false,mythos_spectral_profile:[],new_rules_from_llm:0},all_alerts:_A,new_rules_suggested:[]},
  metrics: {coverage_pct:97.2,detection_gap_pct:65.8,techniques_tested:12,assets_tested:8,pocs_with_evidence:36,evasion_tests:84,score_distribution:[{range:'90-100',count:5},{range:'70-89',count:10},{range:'50-69',count:13},{range:'0-49',count:7}],severity_breakdown:{critical:8,high:13,medium:11,low:3},detection_by_status:{gap:23,detected:12},findings_by_tactic:{'Initial Access':8,'Execution':4,'Credential Access':6,'Privilege Escalation':4,'Defense Evasion':3,'Lateral Movement':4,'Exfiltration':4,'Impact':2}},
  chains: {chains_simulated:36,top_findings:_F.slice(0,6),engagement_id:'ENG-001'},
  remediation: {total:_T.length,by_priority:{critical:_T.filter(t=>t.sla_days<=1),high:_T.filter(t=>t.sla_days>1&&t.sla_days<=7),medium:_T.filter(t=>t.sla_days>7&&t.sla_days<=30),low:[]},tickets:_T,summary:{open:_T.length,by_owner:{security:2,platform:2,engineering:1}}},
  evidence: {summary:{total_records:78,by_type:{stdout:39,log:39},assets_covered:8,techniques_covered:12},records:_E,count:_E.length},
}

const API = {
  get: async (path) => {
    try {
      const r = await fetch(`/api/${path}`)
      if (!r.ok) throw new Error(r.statusText)
      return r.json()
    } catch {
      const base = path.split('?')[0]
      return DEMO[base] ?? DEMO[path] ?? null
    }
  },
  post: async (path, body) => {
    try {
      const r = await fetch(`/api/${path}`, {
        method: 'POST',
        headers: body ? {'Content-Type':'application/json'} : {},
        body: body ? JSON.stringify(body) : undefined,
      })
      return r.json()
    } catch { return null }
  }
}

export default API
