import { useState, useEffect } from 'react'
import API, { DEMO } from '../api.js'
import { SectionHeader } from '../shared.jsx'

function EvdRecord({ rec }) {
  const [open, setOpen] = useState(false)
  return (
    <div className="evd-item" onClick={()=>setOpen(o=>!o)}>
      <div style={{display:'flex',alignItems:'center',gap:10,marginBottom:6,flexWrap:'wrap'}}>
        <span className="evd-id">{rec.id}</span>
        <span className="evd-type">{rec.evidence_type}</span>
        <span style={{fontFamily:'var(--font-mono)',fontSize:9,color:'var(--dim)'}}>asset: {rec.asset_id}</span>
        <span style={{fontFamily:'var(--font-mono)',fontSize:9,color:'var(--dim)'}}>tech: {rec.technique_id}</span>
        <span style={{marginLeft:'auto',fontFamily:'var(--font-mono)',fontSize:9,color:'var(--dim)'}}>
          SHA: {rec.hash_sha256?.substring(0,12)??'—'}…
        </span>
      </div>
      <div style={{fontFamily:'var(--font-mono)',fontSize:9,color:'var(--dim)'}}>
        collector: {rec.collector} · {rec.collected_at?.substring(0,19).replace('T',' ')??''}
      </div>
      {open && (
        <div className="evd-detail">
          {rec.chain_of_custody?.map((c,i)=><div key={i} style={{color:'var(--green)',marginBottom:2}}>▸ {c}</div>)}
          <div style={{marginTop:8,borderTop:'1px solid var(--border)',paddingTop:8}}>
            {typeof rec.content==='string' ? rec.content.substring(0,600)
              : JSON.stringify(rec.content,null,2)?.substring(0,600)}
          </div>
        </div>
      )}
    </div>
  )
}

export default function Evidence() {
  const [data,       setData]       = useState(DEMO.evidence)
  const [typeFilter, setTypeFilter] = useState('')

  useEffect(() => {
    const p = typeFilter ? `?evidence_type=${typeFilter}` : ''
    API.get(`evidence${p}&limit=40`).then(d => setData(d || DEMO.evidence))
  }, [typeFilter])

  const summary  = data?.summary  ?? {}
  const records  = data?.records  ?? []
  const byType   = summary.by_type ?? {}

  return (
    <div className="page">
      <SectionHeader
        title="Evidence Engine"
        sub={`${summary.total_records??0} registros · SHA-256 + chain of custody`}
      >
        <select className="filter-select" value={typeFilter} onChange={e=>setTypeFilter(e.target.value)}>
          <option value="">All Types</option>
          {['stdout','log','poc','chain_step','evasion'].map(t=><option key={t} value={t}>{t}</option>)}
        </select>
      </SectionHeader>

      <div className="cards-grid" style={{gridTemplateColumns:'repeat(auto-fill,minmax(140px,1fr))',marginBottom:20}}>
        {Object.entries(byType).map(([k,v]) => (
          <div key={k} className="metric-card" style={{'--card-accent':'var(--cyan)'}}>
            <div className="card-label">{k}</div>
            <div className="card-value" style={{fontSize:28}}>{v}</div>
          </div>
        ))}
        {summary.assets_covered!=null && (
          <div className="metric-card" style={{'--card-accent':'var(--green)'}}>
            <div className="card-label">Assets</div>
            <div className="card-value" style={{fontSize:28}}>{summary.assets_covered}</div>
          </div>
        )}
        {summary.techniques_covered!=null && (
          <div className="metric-card" style={{'--card-accent':'var(--purple)'}}>
            <div className="card-label">Técnicas</div>
            <div className="card-value" style={{fontSize:28}}>{summary.techniques_covered}</div>
          </div>
        )}
      </div>

      {records.length === 0
        ? <div className="empty">Sin registros de evidencia.</div>
        : records.map(r => <EvdRecord key={r.id} rec={r}/>)
      }
    </div>
  )
}
