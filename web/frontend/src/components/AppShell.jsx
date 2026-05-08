import React, { useState, useEffect } from 'react'
import API from '../api.js'

const Overview    = React.lazy(() => import('../pages/Overview.jsx'))
const Findings    = React.lazy(() => import('../pages/Findings.jsx'))
const Detectors   = React.lazy(() => import('../pages/Detectors.jsx'))
const Chains      = React.lazy(() => import('../pages/Chains.jsx'))
const Remediation = React.lazy(() => import('../pages/Remediation.jsx'))
const Evidence    = React.lazy(() => import('../pages/Evidence.jsx'))

const PAGES = [
  { id:'overview',    icon:'◈', label:'Overview',    group:'Análisis' },
  { id:'findings',    icon:'◉', label:'Findings',    group:'Análisis' },
  { id:'detectors',   icon:'⚡', label:'Detectores',  group:'Detección' },
  { id:'chains',      icon:'⛓', label:'Kill Chains', group:'Detección' },
  { id:'remediation', icon:'🛠', label:'Remediación', group:'Remediación' },
  { id:'evidence',    icon:'📁', label:'Evidencia',   group:'Remediación' },
]

const s = {
  sidebar: { width:'var(--sidebar,220px)', minWidth:'var(--sidebar,220px)', background:'var(--surface)',
    borderRight:'1px solid var(--border)', display:'flex', flexDirection:'column',
    position:'sticky', top:0, height:'100vh', overflowY:'auto' },
  logo:    { padding:'16px 16px 8px', borderBottom:'1px solid var(--border)', marginBottom:8 },
  navItem: (active) => ({
    display:'flex', alignItems:'center', gap:10, padding:'9px 16px',
    fontFamily:'var(--font-display)', fontSize:14, fontWeight:500,
    color: active ? 'var(--cyan)' : 'var(--muted)', cursor:'pointer',
    borderLeft: active ? '2px solid var(--cyan)' : '2px solid transparent',
    background: active ? 'rgba(0,212,255,0.06)' : 'transparent',
    letterSpacing:'.5px', transition:'all .15s',
  }),
  group: { padding:'8px 16px 4px', fontFamily:'var(--font-mono)', fontSize:9,
    letterSpacing:2, color:'var(--dim)', textTransform:'uppercase' },
  footer: { marginTop:'auto', padding:'12px 16px', borderTop:'1px solid var(--border)',
    fontFamily:'var(--font-mono)', fontSize:9, color:'var(--dim)' },
  header: { background:'var(--surface)', borderBottom:'1px solid var(--border)',
    padding:'0 24px', height:56, display:'flex', alignItems:'center', gap:16,
    position:'sticky', top:0, zIndex:100 },
  statusPill: (scanning) => ({
    display:'flex', alignItems:'center', gap:6, padding:'4px 10px', borderRadius:20,
    fontFamily:'var(--font-mono)', fontSize:10, letterSpacing:1, border:'1px solid',
    color: scanning ? 'var(--yellow)' : 'var(--green)',
    borderColor: scanning ? 'var(--yellow)' : 'var(--green)',
    background: scanning ? 'var(--yellow-dim)' : 'var(--green-dim)',
  }),
  pulse: { width:7, height:7, borderRadius:'50%', background:'currentColor',
    animation:'pulse 1.5s infinite' },
}

export default function AppShell() {
  const [page,     setPage]     = useState('overview')
  const [summary,  setSummary]  = useState(null)
  const [status,   setStatus]   = useState(null)
  const [metrics,  setMetrics]  = useState(null)
  const [scanning, setScanning] = useState(false)

  useEffect(() => {
    Promise.all([API.get('summary'), API.get('status'), API.get('metrics')])
      .then(([s, st, m]) => { setSummary(s); setStatus(st); setMetrics(m) })
      .catch(() => {})

    const id = setInterval(() => {
      API.get('status').then(st => {
        setStatus(st)
        if (st?.status === 'idle' && scanning) {
          setScanning(false)
          API.get('summary').then(setSummary)
        }
      }).catch(() => {})
    }, 5000)
    return () => clearInterval(id)
  }, [scanning])

  const runScan = async () => {
    setScanning(true)
    await API.post('run').catch(() => {})
  }

  let prevGroup = ''
  return (
    <div className="app">
      <style>{`@keyframes pulse{0%,100%{opacity:1}50%{opacity:.3}}`}</style>

      {/* Sidebar */}
      <nav style={s.sidebar}>
        <div style={s.logo}>
          <div style={{ fontFamily:'var(--font-display)', fontSize:17, fontWeight:700,
            color:'var(--cyan)', letterSpacing:1 }}>AI CYBER RANGE</div>
          <div style={{ fontFamily:'var(--font-mono)', fontSize:9, color:'var(--muted)',
            letterSpacing:2, marginTop:2 }}>OFENSIVA CONTROLADA · IA</div>
        </div>
        {PAGES.map(p => {
          const showGroup = p.group !== prevGroup
          prevGroup = p.group
          return (
            <React.Fragment key={p.id}>
              {showGroup && <div style={s.group}>{p.group}</div>}
              <div style={s.navItem(page===p.id)} onClick={() => setPage(p.id)}>
                <span style={{ fontSize:14, width:18, textAlign:'center' }}>{p.icon}</span>
                {p.label}
              </div>
            </React.Fragment>
          )
        })}
        <div style={s.footer}>
          <div style={{ color:'var(--cyan)', marginBottom:2 }}>
            <a href="https://axisdynamics.cl" target="_blank" rel="noopener"
              style={{ color:'var(--cyan)', textDecoration:'none' }}>
              AxisDynamics
            </a>
          </div>
          <div>MITRE ATT&amp;CK · v2.0</div>
          <div style={{ marginTop:2, color:'var(--dim)' }}>MIT License</div>
        </div>
      </nav>

      {/* Main */}
      <div className="main-col">
        <header style={s.header}>
          <div style={{ fontFamily:'var(--font-display)', fontSize:16, fontWeight:700,
            letterSpacing:1, flex:1 }}>
            {PAGES.find(p => p.id===page)?.label}
          </div>
          <div style={s.statusPill(scanning)}>
            <div style={{ ...s.pulse, animationDuration: scanning ? '.7s' : '1.5s' }}/>
            {scanning ? 'SCANNING…' : 'IDLE'}
          </div>
          <span style={{ fontFamily:'var(--font-mono)', fontSize:10, color:'var(--muted)' }}>
            {status?.last_scan_at?.substring(0,19).replace('T',' ') ?? '—'}
          </span>
          <button className="run-btn" onClick={runScan} disabled={scanning}>
            {scanning ? 'RUNNING…' : '▶ RUN SCAN'}
          </button>
        </header>

        <React.Suspense fallback={
          <div style={{ padding:60, textAlign:'center', fontFamily:'var(--font-mono)',
            fontSize:12, color:'var(--muted)' }}>Loading…</div>
        }>
          {page==='overview'    && <Overview    summary={summary} metrics={metrics} />}
          {page==='findings'    && <Findings />}
          {page==='detectors'   && <Detectors />}
          {page==='chains'      && <Chains     summary={summary} />}
          {page==='remediation' && <Remediation />}
          {page==='evidence'    && <Evidence />}
        </React.Suspense>
      </div>
    </div>
  )
}
