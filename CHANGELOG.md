# RansomwareShield-SA changelog

## v3.1.0
Management Centre
- Super Admin: one-time password reset codes (RS-XXXX-XXXX-XXXX, 24 h), forced new password at next sign-in
- Super Admin: permanent user deletion with typed email confirmation (removes assessments, actions, scans; audit kept anonymised)
- Only Super Admin can grant/invite Administrator; Administrators cannot change other Administrators
- Six live KPIs, user filter, invitation status (incl. expired) and a live platform security feed
Security
- Sessions and remember-me cookies are bound to the password hash - every session is revoked on password change/reset
- Automatic, additive database migration for new user columns (no data loss)
- Threat Exposure blocks private/internal addresses (SSRF protection)
ShieldAI
- New ShieldAI emblem and animated launcher; chat with thinking stages, typed responses, follow-up suggestions and memory of the last turns
- Context-aware answers built from the user's live scores, weak controls, actions and exposure checks
- Optional generative mode: Azure OpenAI or any OpenAI-compatible API, sending aggregate context only
- Refuses offensive requests (malware, exploits, phishing kits)
- Interactive spotlight tour across the real interface
Results & report
- Animated readiness gauge badge with level colours and legend; radar chart with values restored
- Branded PDF: logo header, readiness seal, badge, executive summary, radar + scorecard, colour-coded findings, page footer
Threat Exposure
- Interactive scanner: SPF, DMARC, MTA-STS, TLS-RPT, DNSSEC, CAA, HTTPS, HSTS, optional HIBP and VirusTotal
- Green tick (healthy), amber (attention), red cross (critical); exposure score ring and risk level
Dashboard & About
- Rewritten dashboard with greeting, logo in hero, four posture KPIs, Function snapshot, trend, quick actions
- New About identity: who we are, mission, vision, capabilities, secure-by-design, what it is not, creators
