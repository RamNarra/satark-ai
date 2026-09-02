'use client'

import { useRef, useState } from 'react'

type Reply = { title: string; body: string; evidence: string[] }

const API_BASE = process.env.NEXT_PUBLIC_API_BASE_URL?.replace(/\/$/, '') ?? ''

export default function Home() {
  const [text, setText] = useState('')
  const [reply, setReply] = useState<Reply | null>(null)
  const [busy, setBusy] = useState(false)
  const fileRef = useRef<HTMLInputElement>(null)

  async function analyze() {
    const value = text.trim()
    if (!value || busy) return
    setBusy(true)
    setReply(null)
    try {
      const response = await fetch(`${API_BASE}/api/analyze`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text: value, deep_analysis: false, fast_first: true, generate_report: false, trigger_mcp_actions: false }),
      })
      if (!response.ok) throw new Error(`HTTP ${response.status}`)
      const data = await response.json()
      setReply({
        title: data.risk_level ? `Assessment: ${String(data.risk_level).toUpperCase()}` : 'I found something worth checking',
        body: data.summary || data.message || JSON.stringify(data, null, 2),
        evidence: Array.isArray(data.evidence) ? data.evidence.slice(0, 6) : [],
      })
    } catch {
      setReply({
        title: 'SATARK is ready, but the analysis service is not connected yet',
        body: 'The interface is intentionally decoupled from the backend. Set NEXT_PUBLIC_API_BASE_URL when the v2 incident-reconstruction API is deployed.',
        evidence: ['conversation preserved', 'backend adapter ready'],
      })
    } finally {
      setBusy(false)
    }
  }

  function onKeyDown(e: React.KeyboardEvent<HTMLTextAreaElement>) {
    if ((e.metaKey || e.ctrlKey) && e.key === 'Enter') analyze()
  }

  return (
    <main className="shell">
      <header className="top">
        <div className="brand">SATARK</div>
        <div className="status">private incident workspace</div>
      </header>

      <section className="center">
        <div className="hero">
          <div className="kicker">Cybercrime first response</div>
          <h1>Tell me what happened.</h1>
          <p className="sub">Paste the message, upload the evidence, or describe the mess exactly as it happened. SATARK reconstructs the incident before telling you what to do.</p>
        </div>

        <div className="composer">
          <textarea value={text} onChange={e => setText(e.target.value)} onKeyDown={onKeyDown} placeholder={'“I got this SMS, clicked the link, then someone called me…”'} aria-label="Describe the incident" />
          <input ref={fileRef} hidden type="file" multiple accept="image/*,audio/*,video/*,.pdf,.apk,.txt" />
          <div className="tools">
            <button className="attach" onClick={() => fileRef.current?.click()}>＋ Add evidence</button>
            <button className="send" onClick={analyze} disabled={!text.trim() || busy}>{busy ? 'Thinking…' : 'Analyze'}</button>
          </div>
        </div>
        <div className="hint">You do not need to organize the story first. Start messy.</div>

        {reply && (
          <article className="response">
            <strong>{reply.title}</strong>
            <p>{reply.body}</p>
            {reply.evidence.length > 0 && <div className="evidence">{reply.evidence.map((item, i) => <span className="chip" key={i}>{String(item)}</span>)}</div>}
          </article>
        )}
      </section>

      <footer className="footer">SATARK · evidence first · decisions grounded in what can be shown</footer>
    </main>
  )
}
