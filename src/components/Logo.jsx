// A shield with a fish hook inside it: a hook is what phishing uses, a shield is what this app is for.
export default function Logo({ size = 40 }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 48 48"
      role="img"
      aria-label="PhishGuard logo"
      focusable="false"
    >
      <path d="M24 3 42 9.5V23c0 11-7.5 18.5-18 22C13.5 41.5 6 34 6 23V9.5Z" fill="#4b2a6b" />
      <g fill="none" stroke="#ffc53d" strokeWidth="3.2" strokeLinecap="round" strokeLinejoin="round">
        <circle cx="24" cy="13.6" r="2.3" />
        <path d="M24 16.2V29.5c0 6-8.5 6-8.5 0" />
        <path d="m15.5 29.5 3-3" />
      </g>
    </svg>
  )
}
