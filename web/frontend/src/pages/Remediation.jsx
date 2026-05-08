import { useState, useEffect } from 'react'
import API, { DEMO } from '../api.js'
import { Badge, SectionHeader } from '../shared.jsx'

const PRIORITY_CONFIG = [
  {key:'critical',label:'🔴 Crítico — SLA 1 día',  accent:'var(--red)'},
  {key:'high',    label:'🟠 Alto — SLA 7 días',     accent:'var(--orange)'},
  {key:'medium',  label:'🟡 Medio — SLA 30 días',   accent:'var(--yellow)'},
  {key:'low',     label:'🟢 Bajo — SLA 90 días',    accent:'var(--green)'},
]

function RemCard({ ticket, accent }) {
  const [open, setOpen] = useState(false)
  const title = (ticket.title ?? ticket.id).replace(/^\[.*?\]\s*/,'')
  return (
    <div className="rem-card" style={{borderTop:`2px solid ${accent}`,cursor:'pointer'}} onClick={()=>setOpen(o=>!o)}>
      <div className="rem-card-title">{title}</div>
      <div className="rem-card-meta">
        <span className={`owner-badge ${ticket.owner_team??'security'}`}>{ticket.owner_team}</span>
        <span className="sla-tag">SLA: {ticket.sla_days}d</span>
        <Badge val={ticket.status??'open'} label={ticket.status??'open'}/>
      </div>
      {open && <>
        {ticket.controls_to_apply?.length > 0 && <>
          <div style={{fontFamily:'var(--font-mono)',fontSize:9,color:'var(--dim)',letterSpacing:1,marginBottom:4}}>CONTROLES:</div>
          <ul className="rem-card-list">{ticket.controls_to_apply.map((c,i)=><li key={i}>{c}</li>)}</ul>
        </>}
        {ticket.detection_rules_needed?.length > 0 && <>
          <div style={{fontFamily:'var(--font-mono)',fontSize:9,color:'var(--dim)',letterSpacing:1,margin:'8px 0 4px'}}>REGLAS NECESARIAS:</div>
          <ul className="rem-card-list">
            {ticket.detection_rules_needed.map((r,i)=>(
              <li key={i} style={{color:r.startsWith('PRIORITY')?'var(--red)':'var(--dim)'}}>{r}</li>
            ))}
          </ul>
        </>}
      </>}
      <div style={{marginTop:6,fontFamily:'var(--font-mono)',fontSize:9,color:'var(--dim)'}}>
        {open?'▲ colapsar':'▼ ver controles'}
      </div>
    </div>
  )
}

export default function Remediation() {
  const [data, setData] = useState(DEMO.remediation)

  useEffect(() => {
    API.get('remediation').then(d => setData(d || DEMO.remediation))
  }, [])

  const {by_priority:bp={}, summary:s={}} = data ?? DEMO.remediation

  return (
    <div className="page">
      <SectionHeader
        title="Backlog de Remediación"
        sub={`${s.open??0} tickets abiertos · ${Object.entries(s.by_owner??{}).map(([k,v])=>`${k}(${v})`).join(' · ')}`}
      />
      {PRIORITY_CONFIG.map(({key,label,accent}) => {
        const tickets = bp[key] ?? []
        if (!tickets.length) return null
        return (
          <div key={key} className="rem-section">
            <div className="rem-section-title" style={{color:accent}}>{label} — {tickets.length} tickets</div>
            <div className="rem-cards">
              {tickets.map(t => <RemCard key={t.id} ticket={t} accent={accent}/>)}
            </div>
          </div>
        )
      })}
    </div>
  )
}
