export default function Panel({ title, extra, className = '', children }) {
  return (
    <section className={`panel ${className}`}>
      <div className="panel-head">
        <h2>{title}</h2>
        {extra && <div className="panel-extra">{extra}</div>}
      </div>
      {children}
    </section>
  )
}

export const Waiting = ({ text = 'Waiting for data…' }) => <div className="waiting">{text}</div>

export const Sev = ({ level }) => <span className={`sev sev-${level}`}>{level ?? '—'}</span>
