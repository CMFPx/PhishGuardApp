import { useState } from 'react'
import { supabase } from '../supabaseClient.js'

const EXAMPLES = [
  {
    label: 'Bank text',
    text: 'Kiwibank: Did you just try to make a payment of $1,249.00? Cancel it now at https://kiwibank-cancel.com/verify and enter the code we send you.',
  },
  {
    label: 'Prize email',
    text: "Congratulations! You've won a $500 voucher. Claim your prize now at prize-center.club before it expires today.",
  },
  {
    label: 'Hidden link',
    text: 'Your statement is ready. Log in at https://www.westpac.co.nz@westpac-statements.cc/login to view it.',
  },
  {
    label: 'Genuine receipt',
    text: 'Thanks for being on Premium. Your receipt for $15.99 is at spotify.com/account. Paid with the card ending 4821.',
  },
]

export default function AnalyzeForm({ onStart, onResult, onError, busy }) {
  const [text, setText] = useState('')

  async function handleSubmit(e) {
    e.preventDefault()
    if (!text.trim() || busy) return
    onStart()

    // Sends the text to the 'analyze' Edge Function in Supabase, which runs the detection rules.
    const { data, error } = await supabase.functions.invoke('analyze', { body: { text } })

    if (error) onError(error.message)
    else onResult(data)
  }

  return (
    <form className="analyze-form" onSubmit={handleSubmit}>
      <label htmlFor="message-input" className="field-label">
        Paste the message or link
      </label>
      <textarea
        id="message-input"
        placeholder="Paste the email text, the text message or a web address here"
        value={text}
        onChange={(e) => setText(e.target.value)}
        rows={8}
      />

      <div className="example-row">
        <span className="example-label">Not sure what to paste? Try one:</span>
        {EXAMPLES.map((ex) => (
          <button key={ex.label} type="button" className="example-chip" onClick={() => setText(ex.text)}>
            {ex.label}
          </button>
        ))}
      </div>

      <div className="form-actions">
        <button type="submit" className="primary" disabled={busy || !text.trim()}>
          {busy ? 'Checking...' : 'Check this message'}
        </button>
        {text && !busy && (
          <button type="button" className="text-button" onClick={() => setText('')}>
            Clear
          </button>
        )}
      </div>
      <p className="privacy-note">
        What you paste is sent to PhishGuard's checker to be scored. The message itself is not saved. Only the score, the risk level and the names of the warning signs are kept for the Analytics page.
      </p>
    </form>
  )
}
