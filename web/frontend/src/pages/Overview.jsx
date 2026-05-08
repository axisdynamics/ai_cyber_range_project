import React from 'react'
import { BarChart, Bar, PieChart, Pie, Cell, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend } from 'recharts'

const SEV_COLORS = { critical:'#ff2d55', high:'#ff6b35', medium:'#ffd60a', low:'#30d158' }

export default function Overview({ summary, metrics }) {
  if (!summary) return <div style={{padding:60,textAlign:'center',fontFamily:'Share Tech Mono',fontSize:12,color:'var(--muted)'}}>Cargando resumen…</div>

  const { critical_count:c=0, high_count:h=0, medium_count:m=0, low_count:l=0 } = summary
  const sevData = [
    { name:'Critical', value:c, color:'#ff2d55' },
    { name:'High',     value:h, color:'#ff6b35' },
    { name:'Medium',   value:m, color:'#ffd60a' },
    { name:'Low',      value:l, color:'#30d158' },
  ]
  const scoreData = (metrics?.score_distribution || []).map(b => ({ ...b, name: b.range }))
  const tacticData = Object.entries(metrics?.findings_by_tactic || {})
    .map(([name, count]) => ({ name, count }))
    .sort((a, b) => b.count - a.count).slice(0, 7)

  const cards = [
    { label:'Total Findings',  value: summary.findings_count,     sub:`${summary.scenario_count||'—'} scenarios`, accent:'var(--cyan)' },
    { label:'Critical',        value: c,                          sub:'SLA: 1 día',         accent:'var(--red)' },
    { label:'High',            value: h,                          sub:'SLA: 7 días',         accent:'var(--orange)' },
    { label:'ATT&CK Coverage', value:`${summary.coverage_pct}%`, sub:`${summary.hypotheses_generated} hipótesis`, accent:'var(--green)' },
    { label:'Detection Gap',   value:`${summary.detection_gap_pct}%`, sub:`${summary.evasion_tests_run} tests`, accent:'var(--yellow)' },
    { label:'PoCs Built',      value: summary.pocs_built,         sub:'reproducibles',       accent:'var(--purple)' },
    { label:'Kill Chains',     value: summary.chains_simulated,   sub:'multi-step',          accent:'var(--cyan)' },
    { label:'Open Tickets',    value: summary.open_tickets||0,    sub:`${summary.sla_breach_count||0} SLA breach`, accent: summary.sla_breach_count > 0 ? 'var(--red)' : 'var(--muted)' },
  ]

  return (
    <div className="page">
      <div style={{ marginBottom:16 }}>
        <div style={{ fontFamily:'var(--font-display)', fontSize:18, fontWeight:700, letterSpacing:1 }}>Resumen Ejecutivo</div>
        <div style={{ fontFamily:'var(--font-mono)', fontSize:10, color:'var(--muted)', marginTop:2 }}>
          RUN: {summary.run_id} · {summary.finished_at?.substring(0,19).replace('T',' ') || '—'}
        </div>
      </div>
      <div style={{ display:'grid', gridTemplateColumns:'repeat(auto-fill,minmax(200px,1fr))', gap:12, marginBottom:24 }}>
        {cards.map(card => (
          <div key={card.label} style={{ background:'var(--surface)', border:'1px solid var(--border)', borderRadius:6, padding:16, position:'relative', overflow:'hidden' }}>
            <div style={{ position:'absolute', top:0, left:0, right:0, height:2, background:card.accent }}/>
            <div style={{ fontFamily:'var(--font-mono)', fontSize:9, letterSpacing:2, color:'var(--muted)', textTransform:'uppercase', marginBottom:8 }}>{card.label}</div>
            <div style={{ fontFamily:'var(--font-display)', fontSize:36, fontWeight:700, color:card.accent, lineHeight:1 }}>{card.value}</div>
            <div style={{ fontFamily:'var(--font-mono)', fontSize:10, color:'var(--muted)', marginTop:4 }}>{card.sub}</div>
          </div>
        ))}
      </div>
      <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:16, marginBottom:24 }}>
        <div style={{ background:'var(--surface)', border:'1px solid var(--border)', borderRadius:6, padding:16 }}>
          <div style={{ fontFamily:'var(--font-display)', fontSize:13, fontWeight:600, letterSpacing:1, color:'var(--muted)', textTransform:'uppercase', marginBottom:16 }}>▶ Hallazgos por Severidad</div>
          <ResponsiveContainer width="100%" height={200}>
            <PieChart>
              <Pie data={sevData} cx="50%" cy="50%" innerRadius={55} outerRadius={80} paddingAngle={3} dataKey="value">
                {sevData.map((e,i) => <Cell key={i} fill={e.color} opacity={0.85}/>)}
              </Pie>
              <Tooltip contentStyle={{ background:'#0d1117', border:'1px solid #1a2535', fontFamily:'Share Tech Mono', fontSize:11 }}/>
              <Legend iconType="circle" iconSize={8} wrapperStyle={{ fontFamily:'Share Tech Mono', fontSize:10 }}/>
            </PieChart>
          </ResponsiveContainer>
        </div>
        <div style={{ background:'var(--surface)', border:'1px solid var(--border)', borderRadius:6, padding:16 }}>
          <div style={{ fontFamily:'var(--font-display)', fontSize:13, fontWeight:600, letterSpacing:1, color:'var(--muted)', textTransform:'uppercase', marginBottom:16 }}>▶ Distribución Risk Score</div>
          <ResponsiveContainer width="100%" height={200}>
            <BarChart data={scoreData}>
              <CartesianGrid strokeDasharray="2 2" stroke="#1a2535"/>
              <XAxis dataKey="name" tick={{ fontFamily:'Share Tech Mono', fontSize:10, fill:'#6272a4' }} axisLine={false}/>
              <YAxis tick={{ fontFamily:'Share Tech Mono', fontSize:10, fill:'#6272a4' }} axisLine={false} tickLine={false}/>
              <Tooltip contentStyle={{ background:'#0d1117', border:'1px solid #1a2535', fontFamily:'Share Tech Mono', fontSize:11 }}/>
              <Bar dataKey="count" radius={[3,3,0,0]}>
                {scoreData.map((_,i) => <Cell key={i} fill={['#ff2d55','#ff6b35','#ffd60a','#30d158'][i]||'#00d4ff'}/>)}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
        <div style={{ background:'var(--surface)', border:'1px solid var(--border)', borderRadius:6, padding:16, gridColumn:'span 2' }}>
          <div style={{ fontFamily:'var(--font-display)', fontSize:13, fontWeight:600, letterSpacing:1, color:'var(--muted)', textTransform:'uppercase', marginBottom:16 }}>▶ Hallazgos por Táctica ATT&CK</div>
          <ResponsiveContainer width="100%" height={180}>
            <BarChart data={tacticData} layout="vertical">
              <CartesianGrid strokeDasharray="2 2" stroke="#1a2535" horizontal={false}/>
              <XAxis type="number" tick={{ fontFamily:'Share Tech Mono', fontSize:10, fill:'#6272a4' }} axisLine={false}/>
              <YAxis dataKey="name" type="category" width={150} tick={{ fontFamily:'Share Tech Mono', fontSize:10, fill:'#6272a4' }} axisLine={false} tickLine={false}/>
              <Tooltip contentStyle={{ background:'#0d1117', border:'1px solid #1a2535', fontFamily:'Share Tech Mono', fontSize:11 }}/>
              <Bar dataKey="count" fill="#00d4ff" opacity={0.8} radius={[0,3,3,0]}/>
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>
    </div>
  )
}
