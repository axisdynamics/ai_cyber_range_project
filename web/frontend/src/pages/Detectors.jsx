import { useState, useEffect, useCallback } from 'react'
import API, { DEMO } from '../api.js'
import { Badge, Conf, SectionHeader, Loading } from '../shared.jsx'

const SOURCE_LABELS = {rule_engine:'RULE',sigma_correlator:'SIGMA',ioc_matcher:'IOC',anomaly_detector:'ANOMALY',llm:'LLM'}
const RULE_NAMES = ['Oversized Input / Buffer Overflow','Shell Metacharacter Injection','Synthetic Credential Token','Telemetry Gap Event','Privilege Escalation Simulation','Data Exfiltration Marker','Lateral Movement Simulation','Scheduled Task Persistence','Sensitive Data File Access','High-Criticality Asset Under Attack','DoS / Resource Exhaustion','Discovery / Enumeration Activity']
const IOC_VALUES = ['SYNTHETIC_VALID_TOKEN_1234','SYNTHETIC_EXFIL_EVENT_NO_REAL_DATA','*.attacker.invalid','exfil.invalid','SYNTHETIC_PIVOT_REQUEST','SYNTHETIC_PRIVILEGE_TEST','SYNTHETIC_IMPACT_MARKER','SYNTHETIC_LOAD_SPIKE','SYNTHETIC_CRON_ENTRY','input_validation_warning','/etc/shadow','mimikatz']

export default function Detectors() {
  const [data,    setData]    = useState(DEMO.detections)
  const [loading, setLoading] = useState(false)
  const [tab,     setTab]     = useState('alerts')

  const load = useCallback(() => {
    setLoading(true)
    API.get('detections').then(d => { setData(d || DEMO.detections); setLoading(false) })
  }, [])

  useEffect(() => { load() }, [load])

  const stats   = data?.engine_stats ?? {}
  const alerts  = data?.all_alerts ?? []
  const newRules = data?.new_rules_suggested ?? []
  const llmText  = data?.llm_analysis_summary ?? ''

  const engineCards = [
    {num:stats.rule_engine_rules??0,  label:'Reglas Activas',  color:'var(--cyan)'},
    {num:stats.sigma_rules??0,         label:'Reglas Sigma',    color:'var(--purple)'},
    {num:stats.ioc_count??0,           label:'IoCs Cargados',   color:'var(--orange)'},
    {num:data?.rule_matches??0,        label:'Rule Matches',    color:'var(--cyan)'},
    {num:data?.correlation_alerts??0,  label:'Correlaciones',   color:'var(--purple)'},
    {num:data?.ioc_matches??0,         label:'IoC Hits',        color:'var(--orange)'},
    {num:data?.anomaly_alerts??0,      label:'Anomalías',       color:'var(--yellow)'},
    {num:data?.llm_enrichments??0,     label:'LLM Enriched',    color:'var(--green)'},
  ]

  return (
    <div className="page">
      <SectionHeader title="Detection Engine"
        sub={`${data?.total_events_processed??0} eventos · ${alerts.length} alertas`}>
        <button className="run-btn" onClick={load} disabled={loading}>
          {loading ? 'ANALIZANDO…' : '↺ RE-ANALIZAR'}
        </button>
      </SectionHeader>

      <div className="engine-grid">
        {engineCards.map(e => (
          <div key={e.label} className="engine-card">
            <div className="engine-num" style={{color:e.color}}>{e.num}</div>
            <div className="engine-label">{e.label}</div>
          </div>
        ))}
      </div>

      {llmText && (
        <div className="llm-box">
          <div className="llm-title">
            🤖 {stats.mythos_available ? 'RDT Enrichment Active' : 'LLM Analysis'}
            {stats.mythos_last_loops > 0 && (
              <span style={{marginLeft:8,fontFamily:'var(--font-mono)',fontSize:9,color:'var(--dim)'}}>
                loops={stats.mythos_last_loops}
              </span>
            )}
          </div>
          <div className="llm-text">{llmText}</div>
          {newRules.length > 0 && (
            <div style={{display:'flex',flexWrap:'wrap',gap:4,marginTop:8}}>
              <span style={{fontFamily:'var(--font-mono)',fontSize:9,color:'var(--dim)'}}>NUEVAS REGLAS:</span>
              {newRules.map((r,i) => <span key={i} className="tag">{r.name||r.id}</span>)}
            </div>
          )}
        </div>
      )}

      <div className="tab-row">
        {[['alerts',`Alertas (${alerts.length})`],['rules','Reglas'],['iocs','IoCs']].map(([id,label]) => (
          <div key={id} className={`tab${tab===id?' active':''}`} onClick={()=>setTab(id)}>{label}</div>
        ))}
      </div>
      <div style={{height:20}}/>

      {tab === 'alerts' && (
        loading ? <Loading label="Ejecutando detectores" />
        : <div className="feed">
            {alerts.map(a => (
              <div key={a.id} className={`alert-item ${a.severity}`}>
                <span className={`alert-source ${a.source}`}>{SOURCE_LABELS[a.source]??a.source}</span>
                <div className="alert-body">
                  <div className="alert-title">{a.title}</div>
                  <div className="alert-desc">{a.description}</div>
                  <div className="alert-meta">
                    <Badge val={a.severity}/>
                    {(a.technique_ids??[]).slice(0,3).map(t=><span key={t} className="meta-tag">{t}</span>)}
                    <span className="meta-tag">conf: {((a.confidence??0)*100).toFixed(0)}%</span>
                    <Conf v={a.confidence??0}/>
                    {a.asset_id&&a.asset_id!=='unknown'&&<span className="meta-tag">↪ {a.asset_id}</span>}
                  </div>
                  {a.llm_hypothesis && (
                    <div style={{fontFamily:'var(--font-mono)',fontSize:10,color:'var(--green)',marginTop:6,padding:'4px 8px',background:'rgba(48,209,88,0.05)',borderRadius:3}}>
                      {a.llm_hypothesis}
                    </div>
                  )}
                </div>
                <span style={{fontFamily:'var(--font-mono)',fontSize:9,color:'var(--dim)',whiteSpace:'nowrap',marginTop:1}}>
                  {(a.detected_at??'').substring(11,19)}
                </span>
              </div>
            ))}
          </div>
      )}

      {tab === 'rules' && (
        <div className="browser-grid">
          {RULE_NAMES.map((name,i) => (
            <div key={i} className="browser-card">
              <div style={{color:'var(--cyan)',fontSize:9,letterSpacing:1,fontFamily:'var(--font-mono)'}}>RULE-{String(i+1).padStart(3,'0')}</div>
              <div style={{color:'var(--text)',fontSize:12,marginTop:4,fontFamily:'var(--font-display)',fontWeight:600}}>{name}</div>
              <div style={{color:'var(--dim)',fontSize:9,marginTop:4,fontFamily:'var(--font-mono)'}}>determinístico · regex</div>
            </div>
          ))}
          {newRules.map((r,i) => (
            <div key={`llm-${i}`} className="browser-card" style={{borderColor:'rgba(48,209,88,0.25)'}}>
              <div style={{color:'var(--green)',fontSize:9,letterSpacing:1,fontFamily:'var(--font-mono)'}}>{r.id??`RULE-LLM-${i}`}</div>
              <div style={{color:'var(--text)',fontSize:12,marginTop:4,fontFamily:'var(--font-display)',fontWeight:600}}>{r.name??'LLM Rule'}</div>
              <div style={{color:'var(--green)',fontSize:9,marginTop:4,fontFamily:'var(--font-mono)'}}>generada por RDT</div>
            </div>
          ))}
        </div>
      )}

      {tab === 'iocs' && (
        <div className="browser-grid">
          {IOC_VALUES.map((ioc,i) => (
            <div key={i} className="browser-card">
              <div style={{color:'var(--orange)',fontSize:9,letterSpacing:1,fontFamily:'var(--font-mono)'}}>IOC-{String(i+1).padStart(3,'0')}</div>
              <div style={{color:'var(--text)',fontSize:10,marginTop:4,wordBreak:'break-all',fontFamily:'var(--font-mono)'}}>{ioc}</div>
              <div style={{color:'var(--dim)',fontSize:9,marginTop:4,fontFamily:'var(--font-mono)'}}>lab_internal · determinístico</div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
