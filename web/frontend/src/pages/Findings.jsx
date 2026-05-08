import { useState, useEffect } from 'react'
import API, { DEMO } from '../api.js'
import { Badge, ScoreBar, SectionHeader } from '../shared.jsx'

const COLS = [
  {key:'id',               label:'ID'},
  {key:'asset',            label:'Activo'},
  {key:'technique_id',     label:'ATT&CK'},
  {key:'severity',         label:'Severidad'},
  {key:'detection_status', label:'Detección'},
  {key:'poc_id',           label:'PoC'},
  {key:'score',            label:'Score'},
]

export default function Findings() {
  const [data,  setData]  = useState(DEMO.findings)
  const [sev,   setSev]   = useState('')
  const [det,   setDet]   = useState('')
  const [asset, setAsset] = useState('')
  const [sort,  setSort]  = useState({key:'score',dir:-1})

  useEffect(() => {
    const p = new URLSearchParams()
    if (sev)   p.set('severity', sev)
    if (det)   p.set('detection_status', det)
    if (asset) p.set('asset', asset)
    p.set('limit','100')
    API.get(`findings?${p}`).then(d => setData(d || DEMO.findings))
  }, [sev, det, asset])

  const toggle = k => setSort(s => ({key:k, dir:s.key===k ? s.dir*-1 : -1}))
  const arrow  = k => sort.key===k ? (sort.dir>0?'▲':'▼') : ''

  const rows = (data?.findings ?? []).slice().sort((a,b) => {
    const av=a[sort.key]??'', bv=b[sort.key]??''
    return typeof av==='number' ? (av-bv)*sort.dir : String(av).localeCompare(String(bv))*sort.dir
  })

  return (
    <div className="page">
      <SectionHeader title="Hallazgos" sub={`${data?.total??rows.length} total · ${rows.length} mostrando`}/>
      <div className="table-wrap">
        <div className="table-header">
          <span className="table-title">Findings</span>
          <div className="filters">
            <select className="filter-select" value={sev} onChange={e=>setSev(e.target.value)}>
              <option value="">All Severity</option>
              {['critical','high','medium','low'].map(s=><option key={s}>{s}</option>)}
            </select>
            <select className="filter-select" value={det} onChange={e=>setDet(e.target.value)}>
              <option value="">All Detection</option>
              {['gap','detected','partial'].map(s=><option key={s}>{s}</option>)}
            </select>
            <select className="filter-select" value={asset} onChange={e=>setAsset(e.target.value)}>
              <option value="">All Assets</option>
              {['iam_role_demo','api_gateway_demo','pipeline_demo','secrets_store_demo','cloud_storage_demo','local_c_lab_service'].map(a=><option key={a} value={a}>{a}</option>)}
            </select>
          </div>
        </div>
        {rows.length === 0
          ? <div className="empty">Sin hallazgos con los filtros actuales.</div>
          : <table>
              <thead><tr>{COLS.map(c=><th key={c.key} onClick={()=>toggle(c.key)}>{c.label} {arrow(c.key)}</th>)}</tr></thead>
              <tbody>{rows.map(f=>(
                <tr key={f.id}>
                  <td><span className="td-id">{f.id.replace('FND-SCN-','')}</span></td>
                  <td style={{fontSize:10}}>{f.asset}</td>
                  <td style={{color:'var(--cyan)',fontFamily:'var(--font-mono)',fontSize:10}}>{f.technique_id}</td>
                  <td><Badge val={f.severity}/></td>
                  <td><Badge val={f.detection_status}/></td>
                  <td>{f.poc_id?<span style={{color:'var(--green)'}}>✓</span>:<span className="td-muted">—</span>}</td>
                  <td><ScoreBar score={f.score}/></td>
                </tr>
              ))}</tbody>
            </table>
        }
      </div>
    </div>
  )
}
