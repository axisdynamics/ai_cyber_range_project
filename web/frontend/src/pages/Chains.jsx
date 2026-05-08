import { useState, useEffect } from 'react'
import API, { DEMO } from '../api.js'
import { Badge, SectionHeader } from '../shared.jsx'

const TACTICS = ['Reconnaissance','Initial Access','Execution','Persistence','Privilege Escalation','Defense Evasion','Credential Access','Discovery','Lateral Movement','Collection','Exfiltration','Impact']
const TECH_TACTIC = {T1190:'Initial Access',T1078:'Initial Access',T1059:'Execution',T1053:'Persistence',T1548:'Privilege Escalation',T1562:'Defense Evasion',T1003:'Credential Access',T1082:'Discovery',T1005:'Collection',T1021:'Lateral Movement',T1041:'Exfiltration',T1499:'Impact'}
const CHAIN_STEPS = ['Initial Access','Execution','Persistence','Defense Evasion','Credential Access','Impact']

export default function Chains({ summary }) {
  const [data,     setData]     = useState(DEMO.chains)
  const [expanded, setExpanded] = useState(null)

  useEffect(() => {
    API.get('chains').then(d => setData(d || DEMO.chains))
  }, [])

  const src = data || summary || DEMO.chains
  const chains = src.chains_simulated ?? 0
  const topFindings = src.top_findings ?? []
  const coveredTactics = new Set(topFindings.map(f => TECH_TACTIC[f.technique_id]).filter(Boolean))

  return (
    <div className="page">
      <SectionHeader title="Kill Chains" sub={`${chains} cadenas simuladas · profundidad máxima 6`}/>

      <div className="chart-panel" style={{marginBottom:20}}>
        <div className="chart-title">ATT&CK Tactic Coverage</div>
        <div style={{display:'flex',gap:6,flexWrap:'wrap',padding:'4px 0'}}>
          {TACTICS.map(t => {
            const covered = coveredTactics.has(t)
            return (
              <div key={t} style={{padding:'6px 12px',borderRadius:4,fontSize:10,fontFamily:'var(--font-mono)',letterSpacing:.5,background:covered?'rgba(0,212,255,0.1)':'var(--surface2)',border:`1px solid ${covered?'var(--cyan)':'var(--border)'}`,color:covered?'var(--cyan)':'var(--dim)'}}>
                {t}
              </div>
            )
          })}
        </div>
      </div>

      {topFindings.length === 0
        ? <div className="empty">Sin kill chains. Ejecuta un scan primero.</div>
        : <div style={{display:'grid',gridTemplateColumns:'repeat(auto-fill,minmax(340px,1fr))',gap:12}}>
            {topFindings.slice(0,8).map((f,i) => {
              const open = expanded === i
              return (
                <div key={f.id}
                  style={{background:'var(--surface)',border:'1px solid var(--border)',borderRadius:6,padding:14,cursor:'pointer',transition:'border-color .15s'}}
                  onClick={() => setExpanded(open ? null : i)}
                  onMouseEnter={e=>e.currentTarget.style.borderColor='var(--border-hi)'}
                  onMouseLeave={e=>e.currentTarget.style.borderColor='var(--border)'}>
                  <div style={{display:'flex',justifyContent:'space-between',alignItems:'flex-start',marginBottom:10}}>
                    <div>
                      <div style={{fontFamily:'var(--font-mono)',fontSize:9,color:'var(--dim)'}}>CHAIN #{i+1}</div>
                      <div style={{fontFamily:'var(--font-display)',fontWeight:700,fontSize:14,marginTop:2}}>{f.technique_id} on {f.asset}</div>
                    </div>
                    <Badge val={f.severity}/>
                  </div>
                  <div style={{borderLeft:'2px solid var(--border)',paddingLeft:12}}>
                    {(open ? CHAIN_STEPS : CHAIN_STEPS.slice(0,3)).map((step,si) => (
                      <div key={si} style={{display:'flex',alignItems:'center',gap:8,marginBottom:6,position:'relative'}}>
                        <div style={{width:8,height:8,borderRadius:'50%',position:'absolute',left:-17,background:si===0?'var(--cyan)':'var(--border)',border:'1px solid var(--cyan)'}}/>
                        <span style={{fontFamily:'var(--font-mono)',fontSize:9,letterSpacing:.5,color:si===0?'var(--cyan)':'var(--dim)'}}>{step}</span>
                        {si===0 && <span style={{fontFamily:'var(--font-mono)',fontSize:9,color:'var(--text)'}}>{f.technique_id}</span>}
                      </div>
                    ))}
                    {!open && <div style={{fontFamily:'var(--font-mono)',fontSize:9,color:'var(--dim)',marginTop:4}}>+ {CHAIN_STEPS.length-3} pasos más ▾</div>}
                  </div>
                  <div style={{marginTop:10,paddingTop:8,borderTop:'1px solid var(--border)',display:'flex',gap:8,alignItems:'center',flexWrap:'wrap'}}>
                    <span className="meta-tag">score: {f.score}</span>
                    <Badge val={f.detection_status}/>
                    {f.poc_id && <span style={{fontFamily:'var(--font-mono)',fontSize:9,color:'var(--green)'}}>✓ PoC</span>}
                  </div>
                  {open && (
                    <div style={{marginTop:12,padding:'10px',background:'var(--surface3)',borderRadius:4,fontFamily:'var(--font-mono)',fontSize:10,color:'var(--muted)',lineHeight:1.6}}>
                      <div><strong style={{color:'var(--cyan)'}}>Asset:</strong> {f.asset}</div>
                      <div><strong style={{color:'var(--cyan)'}}>Técnica:</strong> {f.technique_id} — {TECH_TACTIC[f.technique_id]??'—'}</div>
                      <div style={{marginTop:6,color:'var(--dim)'}}>{f.summary}</div>
                    </div>
                  )}
                </div>
              )
            })}
          </div>
      }
    </div>
  )
}
