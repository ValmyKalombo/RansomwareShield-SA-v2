"""ShieldAI - RansomwareShield-SA security assistant.

Two engines:
  1. Generative mode: Azure OpenAI or any OpenAI-compatible API (when configured).
     Only aggregate, non-identifying context is sent (role, scores, weak-control codes).
  2. ShieldAI Core: built-in reasoning engine that composes answers from the
     user's live platform data and a curated ransomware knowledge base.
Both engines share the same guardrails.
"""
import json
import logging
import re

import requests

log = logging.getLogger("ransomwareshield.shieldai")

PLATFORM = {
    "identity": (
        "RansomwareShield-SA is a cybersecurity readiness platform built by Group 7 for the "
        "Project: Cyber Security module. It measures how prepared an organisation is to prevent, "
        "detect, respond to and recover from ransomware, using a 50-question assessment aligned to "
        "the six NIST CSF 2.0 Functions plus an AI-preparedness supplement. It turns answers into a "
        "weighted readiness score, a risk register, owned remediation actions, an external threat "
        "exposure check and a branded executive report."
    ),
    "not": (
        "It is not antivirus, EDR or a SIEM. It does not scan endpoints, remove malware or certify "
        "compliance. Scores are project-defined readiness guidance, not NIST certification."
    ),
}

TOUR_STEPS = [
    {"target": "brand", "title": "Your secured workspace",
     "text": "Everything in RansomwareShield-SA runs inside an authenticated, audited session. The green indicator confirms your session is protected."},
    {"target": "nav-dashboard", "title": "Dashboard",
     "text": "Your security posture at a glance: readiness score, open remediation, latest exposure check and assessment history."},
    {"target": "start-assessment", "title": "Run an assessment",
     "text": "Answer 50 questions across Govern, Identify, Protect, Detect, Respond, Recover and AI Preparedness. Drafts save automatically per section."},
    {"target": "nav-remediation", "title": "Remediation tracker",
     "text": "Every weak control becomes an action. Assign an owner, set a due date and track it to Remediated or Accepted Risk."},
    {"target": "nav-threat", "title": "Threat Exposure",
     "text": "Scan a public domain or email to check SPF, DMARC, MTA-STS, DNSSEC, HTTPS and breach exposure. Green is healthy, amber needs attention, red is critical."},
    {"target": "nav-security", "title": "Security Centre",
     "text": "Review the controls protecting this platform and your personal audit trail of sign-ins and actions."},
    {"target": "nav-management", "title": "Management Centre",
     "text": "Administrators invite users, assign roles and oversee platform activity. The Super Admin can also reset passwords and delete accounts."},
    {"target": "ai-fab", "title": "ShieldAI is always here",
     "text": "Open ShieldAI on any page to ask security questions, interpret your results or get a prioritised action plan."},
]

KNOWLEDGE = [
    (("mfa", "multi-factor", "multifactor", "2fa"),
     "**Multi-factor authentication** blocks the majority of credential-based intrusions, which are a leading ransomware entry point.\n"
     "- Enforce MFA first on privileged, remote-access (VPN/RDP) and email accounts\n"
     "- Prefer phishing-resistant methods (FIDO2 keys, passkeys, number-matching authenticator) over SMS\n"
     "- Remove legacy authentication protocols that bypass MFA\n"
     "- Review MFA exclusions monthly and treat every exclusion as an accepted risk"),
    (("backup", "3-2-1", "immutable", "restore"),
     "**Backups are your last line of defence against ransomware** - but only if attackers cannot reach them.\n"
     "- Follow 3-2-1-1-0: 3 copies, 2 media, 1 off-site, 1 offline or immutable, 0 restore errors\n"
     "- Separate backup credentials from domain admin accounts\n"
     "- Test restores of critical systems on a schedule and record the time taken against your RTO\n"
     "- Monitor for backup deletion or encryption attempts - attackers target them first"),
    (("phish", "email", "social engineering"),
     "**Phishing remains a primary ransomware delivery vector**, increasingly AI-generated and convincing.\n"
     "- Enforce SPF, DKIM and DMARC at `p=quarantine` or `p=reject` (check it in Threat Exposure)\n"
     "- Filter attachments and links, and sandbox unknown files\n"
     "- Train staff with realistic simulations and a one-click report button\n"
     "- Never approve unexpected MFA prompts or share one-time codes"),
    (("patch", "vulnerab", "update"),
     "**Unpatched internet-facing systems are a fast route to ransomware.**\n"
     "- Prioritise vulnerabilities listed as known-exploited, especially VPN, firewall and remote-access products\n"
     "- Set patch timelines by severity (for example critical external within days)\n"
     "- Maintain an accurate asset inventory - you cannot patch what you do not know exists\n"
     "- Track exceptions with compensating controls and an expiry date"),
    (("segment", "lateral"),
     "**Network segmentation limits how far ransomware can spread.**\n"
     "- Separate user, server, backup and management networks\n"
     "- Restrict SMB and RDP between workstations\n"
     "- Use privileged-access workstations for administration\n"
     "- Alert on unusual east-west traffic"),
    (("incident", "attack", "infected", "hit by", "what do i do", "encrypted"),
     "**If ransomware is suspected, act quickly and in this order:**\n"
     "1. Isolate affected systems from the network - do not power them off, memory may hold evidence\n"
     "2. Activate your incident-response plan and escalate to the incident lead\n"
     "3. Disable compromised accounts and reset privileged credentials from a clean device\n"
     "4. Preserve logs and evidence for forensics\n"
     "5. Engage legal, executives and, where required, regulators (in South Africa POPIA section 22 requires notifying the Information Regulator and affected persons of a compromise)\n"
     "6. Restore from verified clean backups only after the attacker's access is removed\n"
     "Do not negotiate or pay without executive, legal and law-enforcement guidance."),
    (("ransom", "pay"),
     "**Paying a ransom does not guarantee recovery** and may fund further attacks or create legal exposure.\n"
     "- Decide your ransom-payment policy before an incident, at board level\n"
     "- Involve legal counsel, insurers and law enforcement\n"
     "- Invest in tested recovery so payment is never your only option"),
    (("edr", "antivirus", "endpoint"),
     "**Endpoint detection and response (EDR)** watches behaviour such as mass file encryption, shadow-copy deletion and credential dumping.\n"
     "- Deploy across all servers and endpoints, including backup servers\n"
     "- Enable tamper protection so attackers cannot disable it\n"
     "- Ensure someone actually monitors and responds to alerts 24/7"),
    (("popia", "regulat", "compliance", "law"),
     "**Regulatory context (South Africa):**\n"
     "- POPIA requires appropriate security safeguards for personal information and notification of security compromises (section 22)\n"
     "- The Cybercrimes Act 19 of 2020 criminalises unlawful access and interference and imposes reporting duties on some providers\n"
     "- Financial institutions also face sector cyber-resilience requirements\n"
     "RansomwareShield-SA supports alignment evidence but does not certify compliance."),
    (("nist", "csf", "framework", "function"),
     "**NIST CSF 2.0 has six Functions**, all used by RansomwareShield-SA:\n"
     "- **Govern** - strategy, roles, risk appetite and oversight\n"
     "- **Identify** - assets, risks and dependencies\n"
     "- **Protect** - safeguards such as MFA, patching and backups\n"
     "- **Detect** - monitoring and detection of attacks\n"
     "- **Respond** - incident handling and communication\n"
     "- **Recover** - restoration and lessons learned"),
    (("spf", "dmarc", "dkim", "mta-sts", "dnssec"),
     "**Email domain protections reduce spoofing and phishing:**\n"
     "- **SPF** lists servers allowed to send for your domain - end it with `-all` or `~all`\n"
     "- **DKIM** cryptographically signs outgoing mail\n"
     "- **DMARC** tells receivers what to do with failures - move from `p=none` to `p=quarantine` then `p=reject`\n"
     "- **MTA-STS** forces encrypted mail delivery\n"
     "- **DNSSEC** protects DNS answers from tampering\n"
     "Run Threat Exposure to see your domain's status."),
    (("password", "passphrase"),
     "**Strong credential hygiene:**\n"
     "- Use long passphrases (12+ characters) and a password manager\n"
     "- Never reuse passwords across systems\n"
     "- Use unique, vaulted credentials for privileged accounts\n"
     "- Combine with MFA - a strong password alone is not enough"),
]

SYSTEM_PROMPT = (
    "You are ShieldAI, the expert security assistant inside RansomwareShield-SA, a ransomware readiness "
    "platform aligned to NIST CSF 2.0. Platform facts: " + PLATFORM["identity"] + " " + PLATFORM["not"] +
    " Platform areas: Dashboard, Assessments, Results (radar, badge, PDF), Remediation tracker, Threat Exposure "
    "(SPF/DMARC/MTA-STS/DNSSEC/HTTPS/breach checks), Security Centre, Management Centre (admins). "
    "Behave like a senior defensive security consultant: reason step by step internally, then answer clearly and "
    "concisely using short paragraphs and '-' bullet points, with **bold** for key terms. Ground answers in the "
    "user's context when provided. Rules: defensive guidance only - refuse to write malware, exploits or attack "
    "instructions; never claim certification or guarantee protection; never ask for passwords or secrets; say "
    "when something is outside the platform's scope; keep answers under 220 words unless asked for detail."
)


def _context_text(ctx):
    if not ctx:
        return "No assessment data available yet."
    parts = [f"User role: {ctx.get('role')}.", f"Current page: {ctx.get('page', 'unknown')}."]
    if ctx.get("score") is not None:
        parts.append(f"Latest readiness: {ctx['score']}% ({ctx['readiness']}).")
        parts.append("Function scores: " + ", ".join(f"{k} {v}%" for k, v in ctx["functions"].items() if v is not None) + ".")
    if ctx.get("weak"):
        parts.append("Weakest controls: " + "; ".join(f"{c} ({f}): {t}" for c, f, t in ctx["weak"][:6]) + ".")
    parts.append(f"Open remediation actions: {ctx.get('open_actions', 0)} ({ctx.get('critical', 0)} critical).")
    if ctx.get("exposure"):
        parts.append(f"Latest exposure check: {ctx['exposure']}.")
    return " ".join(parts)


# ---------------------------------------------------------------- generative mode
def _generative(cfg, question, history, ctx):
    messages = [{"role": "system", "content": SYSTEM_PROMPT},
                {"role": "system", "content": "User context (aggregate, non-identifying): " + _context_text(ctx)}]
    for turn in history[-6:]:
        role = "assistant" if turn.get("role") == "assistant" else "user"
        messages.append({"role": role, "content": str(turn.get("content", ""))[:1200]})
    messages.append({"role": "user", "content": question})
    body = {"messages": messages, "max_tokens": 600, "temperature": 0.3}
    try:
        if cfg.get("AZURE_OPENAI_ENDPOINT") and cfg.get("AZURE_OPENAI_KEY") and cfg.get("AZURE_OPENAI_DEPLOYMENT"):
            url = (f"{cfg['AZURE_OPENAI_ENDPOINT'].rstrip('/')}/openai/deployments/"
                   f"{cfg['AZURE_OPENAI_DEPLOYMENT']}/chat/completions?api-version=2024-10-21")
            headers = {"api-key": cfg["AZURE_OPENAI_KEY"], "Content-Type": "application/json"}
            engine = "ShieldAI + Azure OpenAI"
        elif cfg.get("AI_API_BASE") and cfg.get("AI_API_KEY") and cfg.get("AI_MODEL"):
            url = cfg["AI_API_BASE"].rstrip("/") + "/chat/completions"
            headers = {"Authorization": "Bearer " + cfg["AI_API_KEY"], "Content-Type": "application/json"}
            body["model"] = cfg["AI_MODEL"]
            engine = "ShieldAI + " + cfg["AI_MODEL"]
        else:
            return None
        r = requests.post(url, headers=headers, json=body, timeout=25)
        r.raise_for_status()
        text = r.json()["choices"][0]["message"]["content"].strip()
        return {"answer": text[:4000], "engine": engine}
    except Exception:
        log.warning("Generative model unavailable; falling back to ShieldAI Core")
        return None


# ---------------------------------------------------------------- ShieldAI Core
BLOCKED = ("write malware", "ransomware code", "encrypt files script", "keylogger", "exploit code",
           "bypass edr", "disable antivirus", "phishing email template", "steal password", "crack password")


def _plan(ctx):
    if not ctx or ctx.get("score") is None:
        return ("You have not completed an assessment yet, so I cannot prioritise your specific gaps.\n"
                "- Start an assessment from the Dashboard - it takes roughly 15 minutes\n"
                "- Answer honestly; N/A answers need an evidence note\n"
                "- I will then rank your weakest controls and build a 30/60/90-day plan")
    funcs = {k: v for k, v in ctx["functions"].items() if v is not None}
    weakest = sorted(funcs, key=funcs.get)[:2]
    lines = [f"Your latest readiness is **{ctx['score']}% ({ctx['readiness']})**. "
             f"The biggest gaps are in **{weakest[0]}** ({funcs[weakest[0]]}%)"
             + (f" and **{weakest[1]}** ({funcs[weakest[1]]}%)." if len(weakest) > 1 else ".")]
    if ctx.get("weak"):
        lines.append("\n**Next 30 days - critical controls:**")
        for code, fn, text in ctx["weak"][:3]:
            lines.append(f"- {code} ({fn}): {text}")
        if len(ctx["weak"]) > 3:
            lines.append("\n**Next 60 days:**")
            for code, fn, text in ctx["weak"][3:6]:
                lines.append(f"- {code} ({fn}): {text}")
    lines.append("\n**By 90 days:** re-assess, compare against this baseline and run a ransomware tabletop exercise "
                 f"focused on {weakest[0]}.")
    lines.append(f"\nYou currently have **{ctx.get('open_actions', 0)} open remediation actions** "
                 f"({ctx.get('critical', 0)} critical). Assign owners in the Remediation tracker.")
    return "\n".join(lines)


def _core(question, ctx):
    q = question.lower().strip()
    suggestions = ["What should I fix first?", "Give me a tour", "What do I do if we are hit by ransomware?"]
    if any(b in q for b in BLOCKED):
        return ("I can't help create malware, exploits or attack material. I can help you **defend** against those "
                "techniques - for example hardening endpoints, detecting encryption behaviour or training staff to spot phishing."), suggestions
    if re.search(r"\b(what is|about|explain)\b.*(ransomwareshield|this (tool|platform)|shield)", q) or q in ("what is this", "who are you"):
        return (PLATFORM["identity"] + "\n\n" + PLATFORM["not"] +
                "\n\nI'm **ShieldAI**, its built-in security assistant. I read your assessment results and help you "
                "interpret them, prioritise fixes and answer ransomware-defence questions."), ["Give me a tour", "How is my score calculated?", "What should I fix first?"]
    if "tour" in q or "show me around" in q or "how do i use" in q:
        return "TOUR", suggestions
    if any(w in q for w in ("fix first", "priorit", "improve", "plan", "what should i do", "recommend", "next step", "my result", "my score", "summar")):
        return _plan(ctx), ["Explain my weakest Function", "How do I assign remediation?", "Generate my PDF report"]
    if "weakest" in q and ctx and ctx.get("score") is not None:
        funcs = {k: v for k, v in ctx["functions"].items() if v is not None}
        fn = min(funcs, key=funcs.get)
        kb = dict((k[0], v) for k, v in KNOWLEDGE)
        return (f"Your weakest Function is **{fn}** at {funcs[fn]}%.\n\n" +
                {"Govern": "Govern covers leadership ownership, policy, risk appetite and board reporting. Without it, technical controls lack funding and accountability.",
                 "Identify": "Identify covers knowing your assets, data, dependencies and ransomware scenarios. You cannot protect what you have not identified.",
                 "Protect": kb["mfa"] + "\n\n" + kb["backup"],
                 "Detect": kb["edr"],
                 "Respond": kb["incident"],
                 "Recover": kb["backup"]}.get(fn, "")), suggestions
    if any(w in q for w in ("score", "calculat", "weight", "readiness level")):
        return ("**How the readiness score works:**\n"
                "- Each answer from 1-5 converts to 0-100% (1 = 0%, 5 = 100%); N/A is excluded\n"
                "- Each Function score is the average of its answers\n"
                "- The overall score weights Govern 20%, Protect 20%, and Identify, Detect, Respond, Recover 15% each\n"
                "- Levels: Critical <40, Weak 40-59, Developing 60-74, Good 75-89, Strong 90+\n"
                "- Answers of 1 or 2 create Critical or High remediation actions\n"
                "These thresholds are project-defined, not official NIST ratings."), suggestions
    if any(w in q for w in ("threat exposure", "exposure", "checker", "scan my domain", "check my domain")):
        return ("**Threat Exposure** checks a public domain or email from the outside:\n"
                "- Email spoofing defences: SPF, DMARC policy, MTA-STS and TLS reporting\n"
                "- DNS integrity: DNSSEC and CAA\n"
                "- Web: HTTPS availability and HSTS\n"
                "- Optional: breach exposure (Have I Been Pwned) and domain reputation (VirusTotal)\n"
                "Green tick = healthy, amber = needs attention, red cross = high risk. It shows exposure, not proof of an active infection."), suggestions
    if any(w in q for w in ("admin", "invite", "role", "delete user", "reset password", "management")):
        return ("**Management Centre** (Administrators and Super Admin):\n"
                "- Invite users with one-use links that expire in 48 hours\n"
                "- Assign Administrator, Organisation Manager or Assessor roles\n"
                "- Suspend or reactivate accounts\n"
                "- Super Admin only: reset passwords with a one-time code and delete accounts\n"
                "Every action is written to the audit log."), suggestions
    if any(w in q for w in ("remediation", "action", "owner", "due date")):
        return ("**Remediation tracker:** every answer of 1 or 2 becomes an action.\n"
                "- Critical actions get a 30-day target, High actions 60 days\n"
                "- Assign an owner and adjust the due date\n"
                "- Move status from Open to In Progress to Remediated, or Accepted Risk with justification\n"
                "- Overdue items are highlighted on the dashboard"), suggestions
    for keys, answer in KNOWLEDGE:
        if any(k in q for k in keys):
            return answer, suggestions
    return ("I'm a defensive security assistant focused on ransomware readiness. I can:\n"
            "- Explain what RansomwareShield-SA is and give you a guided tour\n"
            "- Interpret your score and build a prioritised 30/60/90-day plan\n"
            "- Advise on MFA, backups, phishing, patching, EDR, segmentation and incident response\n"
            "- Explain Threat Exposure results and the Management Centre\n"
            "Try asking: *What should I fix first?*"), suggestions


def answer(cfg, question, history, ctx):
    question = (question or "").strip()[:800]
    if not question:
        return {"answer": "Ask me anything about ransomware readiness or this platform.", "engine": "ShieldAI Core", "suggestions": []}
    core_text, suggestions = _core(question, ctx)
    if core_text == "TOUR":
        return {"answer": "Starting the guided tour now. I'll highlight each area of the platform - use **Next** to move through it.",
                "tour": True, "engine": "ShieldAI Core", "suggestions": suggestions}
    if not any(b in question.lower() for b in BLOCKED):
        gen = _generative(cfg, question, history or [], ctx)
        if gen:
            gen["suggestions"] = suggestions
            return gen
    return {"answer": core_text, "engine": "ShieldAI Core", "suggestions": suggestions}


def executive_summary(ctx):
    """Deterministic summary used in the PDF report."""
    if ctx.get("score") is None:
        return "No completed assessment data is available."
    funcs = {k: v for k, v in ctx["functions"].items() if v is not None}
    strongest = max(funcs, key=funcs.get)
    weakest = min(funcs, key=funcs.get)
    crit = ctx.get("critical_weak", 0)
    return (f"The organisation achieved a project-defined ransomware readiness score of {ctx['score']}% "
            f"({ctx['readiness']}). Its strongest capability is {strongest} ({funcs[strongest]}%), while "
            f"{weakest} ({funcs[weakest]}%) presents the greatest improvement opportunity. "
            f"{len(ctx.get('weak', []))} weak controls were identified, {crit} of which are critical. "
            f"Leadership should assign owners to critical actions within 30 days, address high-priority "
            f"gaps within 60 days and re-assess within 90 days to evidence improvement.")
