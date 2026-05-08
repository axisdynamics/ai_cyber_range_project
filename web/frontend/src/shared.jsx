// src/shared.jsx — shared components and constants

export const SEV_COLORS = {
  critical: '#ff2d55', high: '#ff6b35', medium: '#ffd60a', low: '#30d158',
  gap: '#ff2d55', detected: '#30d158', partial: '#ffd60a',
}

export const SOURCE_LABELS = {
  rule_engine: 'RULE', sigma_correlator: 'SIGMA',
  ioc_matcher: 'IOC', anomaly_detector: 'ANOMALY', llm: 'LLM',
}

export function Badge({ val, label }) {
  return <span className={`badge ${val}`}>{label || val}</span>
}

export function Conf({ v = 0 }) {
  const thresholds = [0.2, 0.4, 0.6, 0.8, 1.0]
  return (
    <div className="conf-bar">
      {thresholds.map((t, i) => (
        <div key={i} className="conf-pip"
          style={{ background: v >= t ? 'var(--cyan)' : 'var(--border)' }} />
      ))}
    </div>
  )
}

export function ScoreBar({ score }) {
  return (
    <div className="score-bar-wrap">
      <div className="score-bar" style={{ width: Math.min(score, 100) * 0.8 }} />
      <span className="score-num">{score}</span>
    </div>
  )
}

export function SectionHeader({ title, sub, children }) {
  return (
    <div className="section-header">
      <div>
        <div className="section-title">{title}</div>
        {sub && <div className="section-sub">{sub}</div>}
      </div>
      {children}
    </div>
  )
}

export function Loading({ label = 'Cargando' }) {
  return <div className="loading">{label}…</div>
}

export function Empty({ label = 'Sin datos' }) {
  return <div className="empty">{label}</div>
}
