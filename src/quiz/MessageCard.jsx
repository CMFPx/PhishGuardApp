import { useState } from 'react'
import { CHANNEL_LABEL, parseSender, splitUrl } from './quizLogic.js'

function LinkReveal({ q, forceOpen }) {
  const [open, setOpen] = useState(false)
  if (!q.linkUrl) return null
  const shown = open || forceOpen
  const { before, host, after } = splitUrl(q.linkUrl)

  return (
    <div className="link-block">
      <button type="button" className="link-button" onClick={() => setOpen(true)} aria-describedby="link-destination">
        {q.linkText}
      </button>
      {!shown && (
        <button type="button" className="link-peek" onClick={() => setOpen(true)}>
          Check where this link goes
        </button>
      )}
      <p id="link-destination" className={`link-destination ${shown ? 'visible' : ''}`} aria-live="polite">
        {shown && (
          <>
            <span className="link-destination-label">The link goes to</span>
            <span className="link-url">
              {before}
              <strong>{host}</strong>
              {after}
            </span>
          </>
        )}
      </p>
    </div>
  )
}

export default function MessageCard({ q, revealed }) {
  const { name, address } = parseSender(q.sender)
  const channel = q.channel || 'email'

  if (channel === 'email') {
    return (
      <article className="message message-email" aria-label="Email to judge">
        <header className="email-head">
          <span className="avatar" aria-hidden="true">
            {(name || address).trim().charAt(0).toUpperCase()}
          </span>
          <div className="email-from">
            <p className="email-name">{name || address}</p>
            {name && <p className="email-address">{address}</p>}
          </div>
          <span className="channel-tag">{CHANNEL_LABEL.email}</span>
        </header>
        <h3 className="email-subject">{q.subject}</h3>
        <p className="message-body">{q.body}</p>
        <LinkReveal q={q} forceOpen={revealed} />
      </article>
    )
  }

  return (
    <article className={`message message-chat message-${channel}`} aria-label={`${CHANNEL_LABEL[channel]} to judge`}>
      <p className="chat-from">
        <span>{q.sender}</span>
        <span className="channel-tag">{CHANNEL_LABEL[channel]}</span>
      </p>
      <div className="bubble">
        <p className="message-body">{q.body}</p>
        <LinkReveal q={q} forceOpen={revealed} />
      </div>
    </article>
  )
}
