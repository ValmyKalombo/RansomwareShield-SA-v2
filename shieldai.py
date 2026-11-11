"""ShieldAI v2 - RansomwareShield-SA friendly cybersecurity assistant.

Drop-in replacement for shieldai.py (same public interface):
    answer(cfg, question, history, ctx) -> dict
    executive_summary(ctx) -> str
    redact(text) -> str
    TOUR_STEPS, PLATFORM

Two engines share the same persona and guardrails:
  1. Generative mode - Azure OpenAI or any OpenAI-compatible API (when configured).
     Secrets are redacted and only aggregate, non-identifying context is sent.
  2. ShieldAI Core - built-in engine: intent detection with typo tolerance,
     plain-language glossary, urgent incident playbooks, prevention guides,
     experience-level tailoring and platform-aware advice from live data.
"""
import difflib
import logging
import re

import requests

log = logging.getLogger("ransomwareshield.shieldai")

# =====================================================================  platform
PLATFORM = {
    "identity": (
        "RansomwareShield-SA is a cybersecurity readiness platform built by Group 7 for the Project: Cyber Security "
        "module. It measures how prepared an organisation is to prevent, detect, respond to and recover from "
        "ransomware, using a 50-question assessment aligned to the six NIST CSF 2.0 Functions plus an "
        "AI-preparedness supplement. It turns answers into a readiness score, a risk register, owned remediation "
        "actions, an external Threat Exposure check and a branded executive report."
    ),
    "not": (
        "It is not antivirus, EDR or a SIEM. It does not scan your devices, remove malware or certify compliance. "
        "Scores are project-defined readiness guidance, not NIST certification."
    ),
}

TOUR_STEPS = [
    {"target": "brand", "title": "Your secured workspace",
     "text": "Everything here runs inside a protected, audited session. The green indicator confirms your session is secure."},
    {"target": "nav-dashboard", "title": "Dashboard",
     "text": "Your security posture at a glance: readiness score, open fixes, latest exposure check and assessment history."},
    {"target": "start-assessment", "title": "Run an assessment",
     "text": "Answer 50 plain questions about how your organisation handles security. Each section saves as you go."},
    {"target": "nav-remediation", "title": "Remediation tracker",
     "text": "Every weak answer becomes a to-do item. Give it an owner and a due date, then track it until it's fixed."},
    {"target": "nav-threat", "title": "Threat Exposure",
     "text": "Check how a domain looks to attackers from the outside. Green means healthy, amber needs attention, red is high risk."},
    {"target": "nav-security", "title": "Security Centre",
     "text": "See the protections on this platform and a log of your own sign-ins and actions."},
    {"target": "nav-management", "title": "Management Centre",
     "text": "Administrators invite users, assign roles and monitor questionnaire progress and scores."},
    {"target": "ai-fab", "title": "ShieldAI is always here",
     "text": "Ask me anything about security in everyday language - from 'is this email a scam?' to 'what should we fix first?'"},
]

# =====================================================================  persona
PERSONA = """You are ShieldAI, the cybersecurity assistant inside RansomwareShield-SA.

Who you are: a friendly, trustworthy cybersecurity assistant - supportive and approachable like a knowledgeable friend, while staying professional, calm and honest. You help people understand security risks and take practical steps to protect their devices, accounts, networks and organisations.

How you help:
- Give clear, actionable advice in plain language. Match the user's experience level: for beginners avoid jargon, use everyday analogies and short steps; for technical users be precise and concise.
- Whenever you use a technical term, explain it in a few words the first time.
- If important details are missing, ask one to three focused questions - but still give the safest immediate advice first.
- For urgent incidents (hacked account, clicked a phishing link, ransomware, money sent to a scammer, lost device), start with the most important harm-reducing steps, numbered, then guide what to do next.
- Prioritise prevention, defence, privacy and recovery. Keep recommendations proportionate to the situation.
- Distinguish confirmed facts from possibilities ("this could mean...", "it is not confirmed that...").
- Never claim you scanned a device, verified a breach, contacted anyone or took any action. You can only read the RansomwareShield-SA results provided in context.
- Topics: phishing, account and password security, MFA, malware concerns, ransomware, backups, secure configuration, vulnerability remediation, incident response, privacy, security awareness, POPIA basics, and this platform's features.

Boundaries:
- Do not help with breaking into systems, stealing credentials or data, evading detection, writing or deploying malware, or harming others. If a request could enable harm, briefly explain the concern and offer a safe, defensive alternative.
- Never ask for passwords, one-time codes, private keys, card numbers or ID numbers. If the user shares one, tell them kindly not to and advise changing it.
- When a situation involves significant financial, legal or organisational risk, or is beyond what you can safely guide, recommend contacting the relevant provider (bank, email or platform provider, IT/security team) or a qualified security professional.

Style: warm and reassuring without minimising risk or making promises. Use short paragraphs, '-' bullets or numbered steps, and **bold** for key words. Keep answers under about 250 words unless asked for more. Always finish with a line starting "**Next step:**" giving one concise action, or invite the user to share non-sensitive details for tailored help."""

SYSTEM_PROMPT = (PERSONA + "\n\nPlatform facts: " + PLATFORM["identity"] + " " + PLATFORM["not"] +
                 " Areas: Dashboard, Assessments, Results (score gauge, radar, PDF report), Remediation tracker, "
                 "Threat Exposure (SPF, DMARC, MTA-STS, DNSSEC, CAA, HTTPS, HSTS, breach and reputation checks), "
                 "Security Centre, Management Centre (administrators).")

# =====================================================================  helpers
def _norm(text):
    return re.sub(r"\s+", " ", re.sub(r"[^a-z0-9@./+\- ]", " ", (text or "").lower())).strip()


SENSITIVE_PATTERNS = [
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(-----END [A-Z ]*PRIVATE KEY-----|$)", re.S), "[private key removed]"),
    (re.compile(r"(?i)\b(password|passwd|pwd|passcode|pin|otp|one[- ]time code|auth(entication)? code|verification code|2fa code|mfa code|secret|api[_ -]?key|token)\b(\s*(is|=|:|was)\s*)\S+"),
     r"\1\3[removed]"),
    (re.compile(r"\b(?:\d[ -]?){13,19}\b"), "[number removed]"),
    (re.compile(r"\b(sk|pk|ghp|xox[bpas])[-_][A-Za-z0-9_-]{16,}\b"), "[key removed]"),
    (re.compile(r"\b[A-Za-z0-9+/]{40,}={0,2}\b"), "[token removed]"),
]


def redact(text):
    """Remove passwords, codes, keys and long numbers before logging or sending anywhere."""
    out = text or ""
    for pattern, repl in SENSITIVE_PATTERNS:
        out = pattern.sub(repl, out)
    return out


def _has_sensitive(text):
    return redact(text) != (text or "")


def _fuzzy_in(word, tokens):
    if len(word) < 5:
        return word in tokens
    return bool(difflib.get_close_matches(word, tokens, n=1, cutoff=0.84))


def _score(qnorm, tokens, keywords):
    s = 0
    for k in keywords:
        if " " in k:
            if k in qnorm:
                s += 3
        elif k in tokens:
            s += 2
        elif _fuzzy_in(k, tokens):
            s += 1
    return s


def _level(question, history):
    text = " ".join([question] + [h.get("content", "") for h in (history or []) if h.get("role") == "user"][-3:]).lower()
    beginner = ["simple", "simply", "plain english", "plain language", "don't understand", "dont understand",
                "not technical", "non technical", "non-technical", "eli5", "explain like", "layman", "confused",
                "beginner", "new to this", "no idea", "what does that mean", "in english", "easy words", "lost"]
    expert = ["edr", "siem", "cve", "cvss", "lateral movement", "kerberos", "ntlm", "ioc", "yara", "sigma", "dkim",
              "p=reject", "tls 1.", "mitre", "att&ck", "ttp", "c2", "exfil", "sysmon", "gpo", "conditional access",
              "least privilege", "segmentation", "playbook", "rto", "rpo", "immutable", "xdr", "soar"]
    if any(b in text for b in beginner):
        return "beginner"
    if sum(1 for e in expert if e in text) >= 2:
        return "technical"
    return "everyday"


def _compose(parts, next_step):
    body = "\n\n".join(p.strip() for p in parts if p and p.strip())
    return f"{body}\n\n**Next step:** {next_step}"


# =====================================================================  glossary
# term: (aliases, plain explanation, everyday analogy, why it matters, what to do)
GLOSSARY = {
    "phishing": (["phishing", "phish", "phishing email"],
        "a fake message (email, SMS or chat) pretending to be someone you trust, to trick you into clicking a link, opening a file, paying, or giving away your password.",
        "It's like a stranger in a delivery uniform asking for your house keys.",
        "It's the most common way attacks - including ransomware - begin.",
        "Pause before clicking, check the sender's real address, and verify by contacting the company through a number or website you already know."),
    "smishing": (["smishing", "sms scam", "text scam"],
        "phishing sent by SMS or WhatsApp - for example a fake parcel-delivery or bank message with a link.",
        "Same trick as phishing, just arriving on your phone.", "People trust texts more than emails, so these work surprisingly often.",
        "Don't tap links in unexpected texts; open the official app or website yourself."),
    "vishing": (["vishing", "voice phishing", "scam call"],
        "phishing done over a phone call - someone pretending to be your bank, IT support or a supplier.",
        "A con artist using a confident voice instead of an email.", "Callers create urgency so you act before thinking.",
        "Hang up and call back on the official number from the company's website or your card."),
    "ransomware": (["ransomware"],
        "malicious software that locks (encrypts) your files or systems and demands payment to unlock them. Modern attackers often steal data first and threaten to publish it.",
        "A burglar who changes all the locks in your building and sells you the keys back.",
        "It can stop a whole organisation from operating for days or weeks.",
        "Keep tested offline backups, use MFA, patch quickly and train people to spot phishing."),
    "malware": (["malware", "virus", "malicious software"],
        "any software designed to harm, spy on or take control of a device - viruses, trojans, spyware and ransomware are all types.",
        "An uninvited guest hiding in your house.", "It can steal passwords, money or data, or open the door to bigger attacks.",
        "Keep devices updated, use reputable security software and only install apps from trusted sources."),
    "trojan": (["trojan"], "malware disguised as something harmless, like a free game, cracked software or a fake invoice.",
        "The Trojan horse - a gift with soldiers inside.", "You install it yourself, so it bypasses some defences.",
        "Avoid pirated software and unexpected attachments."),
    "spyware": (["spyware", "stalkerware"], "software that secretly watches what you do - messages, location or keystrokes.",
        "A hidden camera in your home.", "It quietly leaks private information.",
        "Check for unknown apps, update your device and, if you suspect stalkerware, get help before removing it if your safety may be at risk."),
    "keylogger": (["keylogger", "key logger"], "software or a device that records everything you type, including passwords.",
        "Someone reading over your shoulder - permanently.", "It can capture passwords even if they are strong.",
        "Use MFA so a stolen password alone isn't enough."),
    "mfa": (["mfa", "2fa", "multi factor", "multi-factor", "two factor", "two-factor", "2 step", "two step", "authenticator"],
        "a second proof that it's really you when signing in - like a code from an app, a tap on your phone or a security key - on top of your password.",
        "A door with two locks: even if someone copies one key, they still can't get in.",
        "It blocks most account takeovers that start with a stolen password.",
        "Turn it on for email, banking and work accounts first; prefer an authenticator app or passkey over SMS."),
    "password manager": (["password manager", "password vault", "bitwarden", "1password", "keepass"],
        "an app that creates and remembers strong, unique passwords for every account, so you only remember one master password.",
        "A secure safe for all your keys.", "Reusing passwords is how one leak becomes many hacked accounts.",
        "Install a reputable password manager and start with your email and banking passwords."),
    "passkey": (["passkey", "passkeys"], "a newer way to sign in using your phone or computer's fingerprint, face or PIN instead of a password. It can't be phished.",
        "Your face or fingerprint becomes the key, and it only fits the real website.", "It removes the password that attackers try to steal.",
        "Enable passkeys where offered, starting with Google, Microsoft or Apple accounts."),
    "encryption": (["encryption", "encrypt", "encrypted"], "scrambling information so only someone with the right key can read it.",
        "Writing a letter in a secret code only the recipient can read.", "If a laptop or file is stolen, encrypted data stays private.",
        "Turn on device encryption (BitLocker on Windows, FileVault on Mac) and use HTTPS websites."),
    "vpn": (["vpn", "virtual private network"], "an encrypted tunnel between your device and another network, often used for working remotely or on public Wi-Fi.",
        "A private, covered walkway through a crowded public area.", "It protects traffic on untrusted networks; it does not make you anonymous or stop malware.",
        "Use your organisation's VPN for work and keep it updated - unpatched VPNs are a common ransomware entry point."),
    "firewall": (["firewall"], "a filter that decides which network traffic may enter or leave a device or network.",
        "A security guard at the gate checking who comes in and out.", "It blocks many unwanted connections before they reach you.",
        "Keep your device's built-in firewall switched on and don't expose remote-access ports to the internet."),
    "antivirus": (["antivirus", "anti virus", "edr", "endpoint protection", "defender", "xdr"],
        "security software on a device. Antivirus catches known bad files; EDR (endpoint detection and response) also watches behaviour, like mass file encryption, and helps respond.",
        "Antivirus checks IDs at the door; EDR is a guard who also notices suspicious behaviour inside.",
        "It's often the first thing to spot ransomware in action.", "Make sure it's installed, updated and actually monitored on every device, including servers."),
    "patch": (["patch", "patching", "update", "updates", "software update"],
        "a fix released by a software maker, usually closing a security hole.", "Repairing a broken window before a burglar finds it.",
        "Attackers race to use known holes; unpatched systems are an easy way in.",
        "Turn on automatic updates, and patch internet-facing systems like VPNs and firewalls first."),
    "vulnerability": (["vulnerability", "vulnerabilities", "vuln", "weakness", "security hole"],
        "a weakness in software, settings or processes that an attacker could use.", "An unlocked window.",
        "Not every weakness is used by attackers, but known-exploited ones are urgent.", "Prioritise by how exposed the system is and whether the weakness is being actively exploited."),
    "cve": (["cve", "cvss"], "CVE is a public ID number for a known vulnerability (like CVE-2024-1234). CVSS is a 0-10 severity score for it.",
        "A recall number for a faulty car part, plus a rating of how dangerous it is.", "It lets everyone talk about the same flaw precisely.",
        "Look up whether the CVE affects your version and whether it's known to be exploited, then patch."),
    "zero day": (["zero day", "zero-day", "0day"], "a weakness that attackers know about before the maker has released a fix.",
        "A lock-picking trick the lock company hasn't discovered yet.", "No patch exists yet, so other layers of defence matter.",
        "Apply the vendor's temporary advice, limit exposure and watch for the patch."),
    "backup": (["backup", "backups", "back up", "3-2-1", "immutable backup", "offline backup"],
        "a separate copy of your data you can restore from. The safe rule is 3-2-1: three copies, on two types of storage, one kept offline or off-site - ideally one that can't be changed (immutable).",
        "A spare set of house keys kept at a trusted friend's house, not under your doormat.",
        "Good, tested backups are what let you recover from ransomware without paying.",
        "Check that at least one backup is offline or immutable, and test restoring a file this month."),
    "spf": (["spf"], "a public DNS record listing which servers are allowed to send email for your domain.",
        "A guest list at the door for your company's emails.", "Without it, criminals can more easily send email pretending to be you.",
        "Publish one SPF record ending in -all or ~all. Check it in Threat Exposure."),
    "dkim": (["dkim"], "a digital signature added to your outgoing emails so receivers can confirm they weren't altered and really came from you.",
        "A wax seal on a letter.", "It helps receivers trust your genuine emails and spot fakes.", "Enable DKIM signing in your email platform (e.g. Microsoft 365 or Google Workspace)."),
    "dmarc": (["dmarc"], "a DNS policy telling other email systems what to do with mail that fails SPF/DKIM checks - monitor, quarantine (spam) or reject.",
        "Instructions to the post office: 'if a letter claims to be from us but lacks our seal, throw it away.'",
        "It's one of the strongest protections against criminals impersonating your domain.",
        "Start with p=none to monitor, then move to p=quarantine and p=reject."),
    "mta-sts": (["mta-sts", "mta sts", "tls-rpt", "tlsrpt"], "a policy that forces other mail servers to use encryption when delivering email to you.",
        "Insisting couriers use a locked van.", "It stops email being quietly downgraded to unencrypted delivery.", "Publish an MTA-STS policy and a TLS-RPT record for reports."),
    "dnssec": (["dnssec"], "a way of signing DNS answers so nobody can forge where your domain points.",
        "A tamper-evident seal on the address book of the internet.", "It prevents some redirect and spoofing attacks.", "Enable DNSSEC at your domain registrar or DNS host."),
    "dns": (["dns"], "the internet's address book that turns names like example.co.za into server addresses.",
        "A phone directory for websites.", "If it's tampered with, people can be sent to fake sites.", "Use a reputable DNS host, lock your domain account with MFA and consider DNSSEC."),
    "https": (["https", "ssl", "tls", "certificate", "padlock", "hsts"],
        "HTTPS (using TLS, formerly SSL) encrypts the connection between your browser and a website. HSTS tells browsers to always use HTTPS for that site.",
        "A sealed envelope instead of a postcard.", "It stops people on the same network reading or changing what you send - but a padlock does NOT prove a site is honest.",
        "Only enter details on HTTPS sites, and still check the web address is the real one."),
    "social engineering": (["social engineering", "pretexting", "impersonation"],
        "manipulating people rather than computers - using urgency, authority, fear or kindness to get someone to reveal information or take an action.",
        "A con artist talking their way past reception.", "Technology can't fully block it; aware people can.",
        "Slow down when a request is urgent or unusual, and verify through a separate channel."),
    "bec": (["bec", "business email compromise", "invoice fraud", "payment fraud", "ceo fraud", "banking details changed"],
        "a scam where criminals impersonate a boss, supplier or client by email to get money paid into their account - often by 'updating' banking details.",
        "Someone forging your supplier's letterhead to redirect payments.", "It causes some of the largest financial losses of any cybercrime.",
        "Always confirm any change of banking details by phoning a number you already have on file."),
    "breach": (["breach", "data breach", "leak", "leaked", "pwned", "have i been pwned", "hibp"],
        "when information is accessed or exposed without permission - for example a website's customer database being stolen.",
        "Someone photocopying the files in your filing cabinet.", "Leaked passwords get reused against other accounts.",
        "Change the affected password and any account that reused it, and turn on MFA."),
    "credential stuffing": (["credential stuffing", "password spraying", "brute force", "brute-force"],
        "automated guessing of logins - either trying passwords leaked from other sites (stuffing) or trying common passwords across many accounts (spraying/brute force).",
        "Trying a stolen keyring on every door in the street.", "Reused and weak passwords make it work.",
        "Use unique passwords, MFA and account lockout."),
    "least privilege": (["least privilege", "admin rights", "privileged access", "administrator rights"],
        "giving each person or system only the access they actually need, and no more.",
        "Giving the cleaner a key to the office, not to the safe.", "If an account is hacked, the damage is limited.",
        "Remove everyday admin rights and use separate admin accounts only when needed."),
    "segmentation": (["segmentation", "network segmentation", "lateral movement"],
        "dividing a network into separate zones so a problem in one area can't easily spread to others.",
        "Fire doors in a building.", "It stops ransomware spreading from one PC to the whole organisation.",
        "Separate servers, backups and staff devices, and restrict file-sharing and remote-desktop between them."),
    "siem": (["siem", "soc", "security operations", "monitoring", "log monitoring"],
        "a SIEM collects security logs from many systems so a team (often called a SOC - security operations centre) can spot and respond to attacks.",
        "CCTV for your network, with someone actually watching the screens.", "Attacks are much less damaging when noticed early.",
        "Make sure key alerts reach a person who will act on them, including after hours."),
    "incident response": (["incident response", "ir plan", "response plan", "tabletop", "tabletop exercise"],
        "the plan for what to do - and who does it - when something goes wrong, such as ransomware. A tabletop exercise is a practice run discussed around a table.",
        "A fire drill for cyber attacks.", "Teams that have practised recover faster and make fewer costly mistakes.",
        "Write a one-page contact and decision list, then run a 60-minute tabletop exercise."),
    "nist csf": (["nist", "csf", "nist csf", "framework", "govern identify protect detect respond recover"],
        "the NIST Cybersecurity Framework 2.0 - a widely used guide that groups security into six areas: Govern, Identify, Protect, Detect, Respond and Recover.",
        "A checklist that covers the whole journey from planning to bouncing back.", "It's the structure RansomwareShield-SA uses to score readiness.",
        "Look at your weakest Function in your results and start there."),
    "popia": (["popia", "information regulator", "section 22", "privacy law"],
        "South Africa's Protection of Personal Information Act. It requires reasonable security for personal information and, under section 22, notifying the Information Regulator and affected people when it is compromised.",
        "The rules for looking after other people's personal details.", "Organisations can face regulatory action and reputational damage.",
        "Know who your Information Officer is and how a compromise gets reported. For legal certainty, consult a privacy or legal professional."),
    "zero trust": (["zero trust"], "an approach where no user or device is trusted automatically - every access request is checked each time.",
        "Checking ID at every door, not just the front gate.", "It limits damage when an account or device is compromised.", "Start with MFA everywhere, device health checks and least-privilege access."),
    "ddos": (["ddos", "denial of service"], "flooding a website or service with traffic until it can't serve real users.",
        "A crowd blocking a shop's entrance so customers can't get in.", "It causes downtime, sometimes as a distraction from other attacks.", "Use your hosting or DNS provider's DDoS protection."),
    "rto rpo": (["rto", "rpo", "recovery time objective", "recovery point objective"],
        "RTO is how quickly a system must be running again after an outage; RPO is how much recent data you can afford to lose (e.g. the last 4 hours).",
        "RTO: how long the shop can stay closed. RPO: how many hours of sales records you can afford to lose.",
        "They decide how often you back up and how fast you must restore.", "Agree RTO and RPO for your critical systems, then test that backups meet them."),
    "penetration test": (["penetration test", "pen test", "pentest", "ethical hacking", "vulnerability scan"],
        "an authorised, simulated attack to find weaknesses before criminals do. A vulnerability scan is an automated check for known weaknesses.",
        "Hiring a locksmith to test your locks, with your permission.", "It shows what an attacker could really do.", "Only test systems you own or have written permission to test."),
    "csrf": (["csrf", "xss", "sql injection", "injection"],
        "common website attack types: SQL injection tricks a site into running database commands, XSS injects malicious script into pages, and CSRF tricks a logged-in browser into performing actions.",
        "Slipping fake instructions into a form the website follows blindly.", "They can expose or change data.",
        "Use secure frameworks, validate input, encode output and use CSRF tokens - all of which RansomwareShield-SA applies."),
    "dark web": (["dark web", "darkweb", "deep web"], "hidden parts of the internet, often used to trade stolen data and logins.",
        "A black market in a back alley.", "Seeing your details there means they have been exposed, not necessarily used.", "Change affected passwords, enable MFA and watch your accounts and statements."),
    "sim swap": (["sim swap", "sim-swap", "port out"], "when a criminal convinces your mobile network to move your number to their SIM, so they receive your SMS codes and calls.",
        "Someone redirecting your mail to their house.", "It can let them reset bank and email accounts that use SMS codes.",
        "Add a PIN/password with your mobile network and prefer authenticator apps over SMS codes."),
}

GLOSSARY_INDEX = {}
for _term, _data in GLOSSARY.items():
    for _alias in _data[0]:
        GLOSSARY_INDEX[_alias] = _term


def _find_term(qnorm):
    best = None
    for alias in sorted(GLOSSARY_INDEX, key=len, reverse=True):
        if re.search(r"(^|[^a-z0-9])" + re.escape(alias) + r"([^a-z0-9]|$)", qnorm):
            best = GLOSSARY_INDEX[alias]
            break
    if best:
        return best
    tokens = qnorm.split()
    for t in tokens:
        if len(t) >= 5:
            m = difflib.get_close_matches(t, [a for a in GLOSSARY_INDEX if " " not in a], n=1, cutoff=0.86)
            if m:
                return GLOSSARY_INDEX[m[0]]
    return None


def _define(term, level):
    aliases, plain, analogy, why, action = GLOSSARY[term]
    name = aliases[0].upper() if len(aliases[0]) <= 5 else aliases[0].capitalize()
    if level == "technical":
        text = f"**{name}** - {plain[0].upper() + plain[1:]}\n\n**Why it matters:** {why}"
    else:
        text = (f"**{name}** in plain words: {plain[0].upper() + plain[1:]}\n\n**Think of it like this:** {analogy}\n\n"
                f"**Why it matters:** {why}")
    return text, action


# =====================================================================  urgent playbooks
URGENT = {
    "clicked": {
        "keys": ["clicked a link", "clicked the link", "clicked on", "opened an attachment", "opened the attachment",
                 "entered my password", "typed my password", "gave my password", "entered my details", "fake login",
                 "phishing link", "downloaded something", "opened a file"],
        "lead": "Don't worry - acting quickly makes a big difference, and you've done the right thing by asking.",
        "now": ["**Disconnect** the device from Wi-Fi or the network if you opened a file or installed something.",
                "**Change the password** of the account you entered (and any account using the same password) - do this from a different, trusted device if possible.",
                "**Turn on MFA** (a second sign-in step) for that account if it isn't already.",
                "**Tell your IT or security team** now if it's a work device or account - they'd much rather hear early."],
        "then": ["Check the account for unfamiliar sign-ins, forwarding rules or changed recovery details.",
                 "Run a full scan with your security software.", "Watch for follow-up messages pretending to 'help' - they're often part of the same scam."],
        "facts": "Clicking a link doesn't always mean something was installed - it depends on what happened next. Entering a password on a fake page does mean you should treat it as exposed.",
        "ask": ["Did you only click, or did you also enter a password or open/download a file?", "Is it a work or personal device/account?"],
        "next": "Change the exposed password now, then tell me which of the questions above applies so I can guide the next part.",
    },
    "hacked": {
        "keys": ["hacked", "been hacked", "got hacked", "compromised", "someone logged into", "can't log in", "cant log in",
                 "locked out", "password changed", "account taken", "strange emails sent", "sending spam", "unknown login",
                 "suspicious login", "sign in alert", "new device signed in"],
        "lead": "That's stressful - let's secure things step by step. Most accounts can be recovered when you act quickly.",
        "now": ["If you can still sign in: **change the password** to a new, unique one and **sign out all other sessions**.",
                "If you're locked out: use the provider's **official account-recovery page** (type the address yourself - don't use links in emails).",
                "**Turn on MFA** and check that your recovery email and phone number are still yours.",
                "If it's an **email account**, check for forwarding rules or filters you didn't create - attackers use these to keep watching."],
        "then": ["Warn contacts if messages were sent from your account, so they don't fall for them.",
                 "Change the password anywhere you reused the old one.", "For work accounts, tell your IT/security team immediately."],
        "facts": "A login alert or strange activity strongly suggests someone had your password, but it isn't proof of how - it may be a reused password, a phishing page or malware.",
        "ask": ["Which account is affected (e.g. email, banking, social media, work)?", "Can you still sign in?"],
        "next": "Secure the affected account using the first steps above, then tell me which account it is (no passwords) so I can give specific recovery steps.",
    },
    "ransomware": {
        "keys": ["ransom note", "files encrypted", "encrypted my files", "my files are locked", "can't open my files",
                 "cant open my files", "files renamed", "pay bitcoin", "ransomware attack", "we have ransomware",
                 "hit by ransomware", "ransomware infection", "demanding payment"],
        "lead": "This is serious, but a calm, structured response limits the damage. Here's what matters most right now.",
        "now": ["**Isolate affected devices** - unplug the network cable or turn off Wi-Fi. Don't switch them off (memory can hold evidence) unless your incident team says to.",
                "**Alert your incident-response lead or IT/security team** immediately and start your ransomware response plan.",
                "**Protect your backups** - disconnect them from the network so they can't be encrypted too.",
                "**Don't contact the attackers or pay** without executive, legal and law-enforcement advice."],
        "then": ["Reset privileged passwords from a clean device and disable compromised accounts.",
                 "Preserve logs and the ransom note for investigation.",
                 "Engage a qualified incident-response provider and your cyber insurer if you have one.",
                 "If personal information may be affected, involve legal/your Information Officer - POPIA section 22 may require notifying the Information Regulator and affected people.",
                 "Restore only from clean, verified backups after the attacker's access is removed."],
        "facts": "A ransom note confirms an attack, but how far it spread and whether data was stolen still needs investigation.",
        "ask": ["How many devices or systems are showing it?", "Do you have backups that are offline or separate from the network?"],
        "next": "Isolate the affected devices and call your incident lead now. This needs professional incident-response support.",
    },
    "money": {
        "keys": ["sent money", "paid a scammer", "transferred money", "scammed", "fraudulent payment", "paid the invoice",
                 "changed banking details", "banking details were changed", "banking details changed", "invoice", "scammer",
                 "fraud", "gave my card", "card details", "bank details", "unauthorised transaction",
                 "unauthorized transaction", "money missing"],
        "lead": "I'm sorry this happened - you're not alone, and speed really matters for getting money back.",
        "now": ["**Call your bank's fraud line immediately** using the number on your card or the official app - ask them to stop or recall the payment and block the card if needed.",
                "**Stop any further payments** to the same account or person.",
                "**Keep all evidence** - emails, messages, invoice, proof of payment."],
        "then": ["Report the crime to the police (in South Africa, at your local SAPS station) and keep the case number.",
                 "If it was a business payment, alert your finance team and the real supplier through a known phone number.",
                 "Change passwords for any account the scammer may have used to contact you."],
        "facts": "Recovery is never guaranteed, but banks have the best chance when contacted within hours.",
        "ask": ["Was it a card payment, EFT/bank transfer, or crypto?", "Roughly when did it happen?"],
        "next": "Call your bank's fraud line right now - everything else can wait until that's done.",
    },
    "lost": {
        "keys": ["lost my phone", "lost my laptop", "stolen phone", "stolen laptop", "phone was stolen", "laptop was stolen",
                 "lost device", "stolen device", "lost my device"],
        "lead": "Let's protect your accounts and data first.",
        "now": ["**Lock or locate the device** remotely (Find My for Apple, Find My Device for Android/Google or Microsoft).",
                "**Change passwords** for email and banking, and **sign the lost device out** of your accounts.",
                "**Contact your mobile network** to suspend the SIM, and your bank if banking apps were on it.",
                "If it's a work device, **tell IT immediately** so they can lock or wipe it."],
        "then": ["Wipe it remotely if you're unlikely to get it back.", "Report theft to the police for insurance purposes."],
        "facts": "If the device had a screen lock and encryption, your data is much safer - but act as if accounts may be exposed.",
        "ask": ["Was the device locked with a PIN, password or biometrics?"],
        "next": "Remotely lock the device and change your email password now.",
    },
    "sextortion": {
        "keys": ["recorded you", "webcam", "i have your password and", "hacked your camera", "video of you", "send bitcoin or",
                 "embarrassing video", "sextortion"],
        "lead": "These emails are frightening, but they are very common scams, and in most cases there is no video at all.",
        "now": ["**Don't reply and don't pay.**", "If the email shows an old password of yours, **change it everywhere** you used it - it likely came from an old data breach.",
                "**Turn on MFA** for your important accounts."],
        "then": ["Mark it as spam/phishing and delete it.", "If someone you know is genuinely threatening you with real images, report it to the police and the platform - you are not to blame."],
        "facts": "These messages are usually sent in bulk to thousands of people using leaked email/password lists. Including a real password does not prove they accessed your device.",
        "ask": [], "next": "Change any password the email mentioned, then delete the email.",
    },
    "remote": {
        "keys": ["remote access", "anydesk", "teamviewer", "gave them access", "let them on my computer", "tech support called",
                 "microsoft called", "support scam", "fake support"],
        "lead": "Thanks for telling me - let's cut off their access straight away.",
        "now": ["**Disconnect the device from the internet** now.", "**Uninstall the remote-access app** they asked you to install (e.g. AnyDesk/TeamViewer) if you don't normally use it.",
                "**From a different device, change passwords** for email and banking and **call your bank** if you logged into banking while they were connected."],
        "then": ["Run a full security scan, or have a trusted technician check the device.", "Real companies like Microsoft don't make unsolicited support calls."],
        "facts": "While connected, they could have viewed files or installed tools - so treat the device as possibly compromised until checked.",
        "ask": ["Did you log into banking or email while they were connected?"],
        "next": "Disconnect the device and change your email and banking passwords from another device.",
    },
}

# =====================================================================  prevention / how-to guides
GUIDES = {
    "spot_phishing": {
        "keys": ["is this a scam", "is this email real", "is this legit", "suspicious email", "suspicious message", "spot phishing",
                 "recognise phishing", "recognize phishing", "fake email", "scam email", "scam sms", "is it safe to click", "scam",
                 "phishy", "legit", "suspicious", "a scam",
                 "how do i know if", "should i click"],
        "intro": "Good instinct to check first. Here are the warning signs - **two or more together is a strong red flag**:",
        "points": ["**Urgency or threats** - 'act now', 'account suspended', 'final notice'.",
                   "**Sender address doesn't match** the company (look at the actual address, not just the name).",
                   "**Links that go somewhere unexpected** - hover over them (or long-press on mobile) to preview the address.",
                   "**Requests for passwords, codes, payment or banking changes.** Real organisations don't ask for codes.",
                   "**Unexpected attachments**, especially .zip, .html or files asking to 'enable macros'.",
                   "**Too good to be true** - prizes, refunds, investment returns."],
        "close": "When unsure, don't use anything in the message - open the official website or app yourself, or phone a number you already know.",
        "ask": "If you like, describe the message (sender, what it asks, any link domain - no personal codes) and I'll help you assess it.",
        "next": "Don't click anything yet - verify the request through the official website or a known phone number.",
    },
    "passwords": {
        "keys": ["strong password", "good password", "password tips", "secure my account", "protect my account", "account security",
                 "how do i protect my accounts", "getting hacked", "avoid getting hacked", "stay safe", "stay safe online",
                 "protect myself", "keep safe", "reuse password", "same password", "change my password", "password policy"],
        "intro": "Account security comes down to three habits:",
        "points": ["**Long and unique** - use a passphrase of 4+ random words (e.g. 'river-candle-orbit-jam'), and never reuse it on another site.",
                   "**A password manager** remembers them all for you, so unique passwords are easy.",
                   "**MFA on important accounts** - email first (it resets everything else), then banking, work and social media.",
                   "Keep your **recovery email and phone number** up to date.",
                   "Check whether your email appeared in known breaches (for example via Have I Been Pwned) and change any affected passwords."],
        "close": "Your email account is the 'master key' to most others, so protect it first.",
        "ask": "", "next": "Turn on MFA for your main email account today.",
    },
    "home_network": {
        "keys": ["wifi", "wi-fi", "router", "home network", "secure my network", "network security", "public wifi", "public wi-fi", "hotspot"],
        "intro": "Here's how to make your network safer:",
        "points": ["**Change the router's default admin password** and update its firmware (software).",
                   "**Use WPA3 or WPA2 encryption** with a strong Wi-Fi password; turn off WPS.",
                   "**Create a guest network** for visitors and smart devices.",
                   "**On public Wi-Fi**, avoid banking or work logins unless you use a VPN or your phone's hotspot; make sure sites use HTTPS."],
        "close": "For organisations: separate staff, server, guest and backup networks (segmentation) and don't expose remote desktop to the internet.",
        "ask": "", "next": "Log into your router and change its default admin password.",
    },
    "device": {
        "keys": ["secure my laptop", "secure my computer", "secure my phone", "protect my device", "device security", "is my phone hacked",
                 "is my computer hacked", "slow computer", "laptop", "computer", "pc", "weird", "strange", "acting up", "pop ups", "popups", "virus on my", "malware on my", "infected", "antivirus do i need"],
        "intro": "Let's check and strengthen the device. Possible signs of malware include sudden pop-ups, unknown apps, a much slower device, settings changing on their own, or security software being switched off - but these can also have ordinary causes.",
        "points": ["**Update** the operating system and apps.", "**Run a full scan** with reputable security software (Windows Security/Microsoft Defender is built into Windows).",
                   "**Remove apps or browser extensions** you don't recognise.", "**Use a screen lock** and turn on device encryption.",
                   "**Don't use an admin account** for everyday work."],
        "close": "If you see ransom messages, files you can't open, or your security software keeps getting disabled, treat it as urgent and contact your IT team or a professional.",
        "ask": "What signs are you noticing, and is it a work or personal device?", "next": "Install pending updates and run a full scan.",
    },
    "ransomware_prevent": {
        "keys": ["prevent ransomware", "protect against ransomware", "stop ransomware", "ransomware prevention", "defend against ransomware",
                 "ransomware protection", "avoid ransomware"],
        "intro": "Ransomware protection works best in layers - each one makes the next attack harder:",
        "points": ["**Backups:** 3-2-1 with one offline or immutable copy, and test restores regularly.",
                   "**MFA** on email, remote access (VPN) and admin accounts.",
                   "**Patch fast**, especially internet-facing systems like VPNs and firewalls.",
                   "**Endpoint protection/EDR** on every device and server, monitored by someone.",
                   "**Least privilege and segmentation** so one infected PC can't reach everything.",
                   "**Train staff** to spot and report phishing quickly.",
                   "**An incident-response plan** that has been practised."],
        "close": "Your RansomwareShield-SA assessment measures exactly these areas.", "ask": "",
        "next": "Ask me 'What should I fix first?' and I'll prioritise using your latest results.",
    },
    "vuln_remediation": {
        "keys": ["remediate", "remediation plan", "prioritise vulnerabilities", "prioritize vulnerabilities", "patch management", "vulnerability management",
                 "which vulnerabilities first", "fix vulnerabilities"],
        "intro": "A practical way to prioritise fixes:",
        "points": ["**1. Known-exploited first** - weaknesses attackers are actively using (check the CISA KEV list).",
                   "**2. Internet-facing systems** - VPNs, firewalls, email, remote access, web apps.",
                   "**3. Critical severity** on important systems.", "**4. Everything else** on a regular schedule.",
                   "If you can't patch yet, **reduce exposure** (restrict access, disable the feature) and record the exception with an end date."],
        "close": "Verify each fix by re-scanning or checking versions, and track it in the Remediation tracker.", "ask": "",
        "next": "List your internet-facing systems and check each is on the latest supported version.",
    },
    "awareness": {
        "keys": ["security awareness", "train staff", "training", "awareness programme", "awareness program", "educate employees", "phishing simulation"],
        "intro": "Effective awareness is short, frequent and positive:",
        "points": ["**Monthly 5-10 minute topics** rather than one long annual session.",
                   "**Realistic phishing simulations** followed by friendly, immediate guidance - never shaming.",
                   "**One clear way to report** suspicious messages (a report button or a known mailbox), and thank people who report.",
                   "**Cover AI-powered scams** - deepfake voices and very polished phishing.", "**Measure** report rates, not just click rates."],
        "close": "", "ask": "", "next": "Set up a single, easy 'report phishing' channel and announce it to staff.",
    },
    "privacy": {
        "keys": ["privacy", "protect my data", "personal information", "social media settings", "data protection", "tracking"],
        "intro": "Simple ways to protect your privacy:",
        "points": ["**Review privacy settings** on social media and limit who sees your posts, phone and birthday.",
                   "**Share less publicly** - pet names, schools and birthdays are common security-question answers.",
                   "**Check app permissions** (location, microphone, contacts) and remove what isn't needed.",
                   "**Use unique emails or aliases** for shopping and newsletters if you can."],
        "close": "For organisations handling personal information, POPIA requires reasonable security safeguards.", "ask": "",
        "next": "Review the privacy settings of the social media account you use most.",
    },
    "incident_plan": {
        "keys": ["incident response plan", "ir plan", "response plan", "what if we get attacked", "prepare for an attack", "tabletop exercise",
                 "business continuity", "disaster recovery"],
        "intro": "A good incident-response plan doesn't need to be long. It should answer:",
        "points": ["**Who decides?** An incident lead and backup, plus executive, legal and communications contacts.",
                   "**How do we contain?** Steps to isolate devices, disable accounts and protect backups.",
                   "**Who do we call?** IT/security provider, cyber insurer, bank, law enforcement, and (for POPIA) the Information Officer.",
                   "**How do we recover?** Restore order for critical systems, with agreed RTO/RPO targets.",
                   "**How do we learn?** A review after every incident or exercise."],
        "close": "Keep a printed copy - during ransomware your systems may be unavailable.", "ask": "",
        "next": "Schedule a 60-minute ransomware tabletop exercise with your key people.",
    },
}

HARMFUL = ["write malware", "create malware", "make malware", "ransomware code", "write ransomware", "build ransomware", "keylogger code",
           "make a keylogger", "write a keylogger", "exploit code", "write an exploit", "bypass edr", "bypass antivirus", "disable antivirus on",
           "evade detection", "avoid detection", "phishing template", "phishing kit", "phishing page", "fake login page",
           "steal password", "steal passwords", "steal credentials", "steal data", "crack password", "crack a password", "hack into",
           "hack someone", "hack my ex", "hack my girlfriend", "hack my boyfriend", "hack a wifi", "hack wifi", "hack an account",
           "break into", "ddos attack", "launch a ddos", "spy on my", "track someone's phone", "botnet", "reverse shell",
           "sql injection payload", "bypass login", "brute force a", "get into someone"]

GREETING = {"hi", "hello", "hey", "howzit", "hiya", "good morning", "good afternoon", "good evening", "sup"}
THANKS = ["thank", "thanks", "appreciate", "cheers", "great help", "that helped"]


# =====================================================================  platform answers
def _plan(ctx, level):
    if not ctx or ctx.get("score") is None:
        return _compose([
            "I can't prioritise your organisation's gaps yet, because no assessment has been completed on your account.",
            "- Start an assessment from the **Dashboard** (about 15 minutes).\n- Answer honestly - it's a self-check, not a test.\n"
            "- I'll then rank your weakest areas and build a 30/60/90-day plan."],
            "Select **New assessment** on your Dashboard.")
    funcs = {k: v for k, v in ctx["functions"].items() if v is not None}
    weakest = sorted(funcs, key=funcs.get)[:2]
    simple = {"Govern": "leadership and policies", "Identify": "knowing what you have and what could go wrong",
              "Protect": "safeguards like MFA, updates and backups", "Detect": "noticing attacks early",
              "Respond": "handling an incident", "Recover": "getting back up and running"}
    lead = (f"Your latest readiness is **{ctx['score']}% ({ctx['readiness']})**. Your biggest gaps are **{weakest[0]}** "
            f"({funcs[weakest[0]]}%)" + (f" and **{weakest[1]}** ({funcs[weakest[1]]}%)." if len(weakest) > 1 else "."))
    if level != "technical":
        lead += f"\n\nIn plain terms, {weakest[0]} is about {simple.get(weakest[0], weakest[0])}."
    parts = [lead]
    if ctx.get("weak"):
        parts.append("**First 30 days - most important:**\n" + "\n".join(f"- {c} ({f}): {t}" for c, f, t in ctx["weak"][:3]))
        if len(ctx["weak"]) > 3:
            parts.append("**Next 60 days:**\n" + "\n".join(f"- {c} ({f}): {t}" for c, f, t in ctx["weak"][3:6]))
    parts.append(f"**By 90 days:** re-assess and compare against this baseline, and run a short ransomware practice exercise focused on {weakest[0]}.")
    parts.append(f"You have **{ctx.get('open_actions', 0)} open remediation actions** ({ctx.get('critical', 0)} critical). "
                 "These are based on your self-assessment answers, not a technical scan.")
    return _compose(parts, "Open **Remediation**, and assign an owner to the first critical action.")


def _platform(q, ctx, level):
    if re.search(r"(what is|about|explain|tell me about|who are you|what does).*(ransom\w* ?shield|this (tool|platform|app|site|system)|shieldai|you)", q) \
            or q in ("what is this", "who are you", "what can you do", "help"):
        return _compose([
            PLATFORM["identity"], PLATFORM["not"],
            "I'm **ShieldAI**, the built-in security assistant. I can:\n- explain security in plain language\n"
            "- help you respond calmly if something goes wrong\n- interpret your results and build a plan\n- guide you around the platform"],
            "Try asking 'Give me a tour' or 'What should I fix first?'")
    if any(w in q for w in ["tour", "show me around", "how do i use", "where do i start", "how does this work"]):
        return "TOUR"
    if any(w in q for w in ["score calculat", "how is my score", "how are scores", "readiness level", "how scoring",
                            "what does my score mean", "score mean", "score work"]):
        return "SCORE"
    if any(w in q for w in ["fix first", "prioritise my", "prioritize my", "our priorities", "my priorities", "improve my score",
                            "what should we do", "what should i do next", "my result", "my score", "summarise my", "summarize my",
                            "summarise our", "action plan", "roadmap", "30/60/90"]):
        return _plan(ctx, level)
    if ("weakest" in q or "explain my" in q) and ctx and ctx.get("score") is not None:
        funcs = {k: v for k, v in ctx["functions"].items() if v is not None}
        fn = min(funcs, key=funcs.get)
        term = {"Protect": "backup", "Detect": "siem", "Respond": "incident response", "Recover": "backup",
                "Govern": "nist csf", "Identify": "vulnerability"}.get(fn, "nist csf")
        d, action = _define(term, level)
        return _compose([f"Your weakest area is **{fn}** at {funcs[fn]}%.", d], action)
    return None


def _score_text():
        return _compose([
            "**How your readiness score works**",
            "- Each answer (1 = strongly disagree, 5 = strongly agree) becomes 0-100%. 'Not applicable' answers are left out.\n"
            "- Each area (Function) gets an average.\n- Govern and Protect count 20% each; the others 15% each.\n"
            "- Levels: Critical below 40, Weak 40-59, Developing 60-74, Good 75-89, Strong 90+.\n"
            "- Answers of 1 or 2 automatically create remediation actions.",
            "It reflects your own answers, so it's a guide to priorities - not a certification or a guarantee."],
            "Open your latest Results to see which areas pulled the score down.")


def _platform_more(q, ctx, level):
    if any(w in q for w in ["threat exposure", "exposure check", "exposure scan", "check my domain", "scan my domain", "domain check", "external exposure"]):
        latest = f" Your most recent check showed **{ctx['exposure']}**." if ctx and ctx.get("exposure") else ""
        return _compose([
            "**Threat Exposure** looks at a public domain or email from the outside, like an attacker would." + latest,
            "- **Email spoofing protection:** SPF, DMARC, MTA-STS\n- **DNS integrity:** DNSSEC and CAA\n- **Website:** HTTPS and HSTS\n"
            "- **Optional:** breach exposure and domain reputation (when keys are configured)",
            "Green means healthy, amber needs attention, red means high risk. It shows exposure and hygiene - it **cannot** prove whether ransomware is on a device."],
            "Run a scan on your organisation's domain and ask me to explain any amber or red results.")
    if any(w in q for w in ["management centre", "management center", "invite", "add a user", "make admin", "delete user",
                            "reset password for", "reset a user", "monitor users", "admin panel"]):
        return _compose([
            "**Management Centre** (Administrators and Super Admin):",
            "- Invite users with one-time links that expire after 48 hours\n- Assign roles and suspend or reactivate accounts\n"
            "- Monitor who has started or completed the questionnaire and their scores, and export reports\n"
            "- **Super Admin only:** reset passwords with a one-time code and permanently delete accounts",
            "Every action is recorded in the audit log."],
            "Open Management Centre from the left menu (visible to administrators).")
    if any(w in q for w in ["remediation", "assign owner", "due date", "action tracker", "open actions"]):
        return _compose([
            "**The Remediation tracker** turns weak answers into a to-do list.",
            "- Critical items get a 30-day target and High items 60 days\n- Add an owner and adjust the date\n"
            "- Move each item to In Progress, then Remediated - or Accepted Risk with a reason"],
            "Open Remediation and assign owners to your critical items.")
    if any(w in q for w in ["pdf", "report download", "download report", "generate report", "export report"]):
        return _compose(["Open any completed assessment's **Results** page and select **Branded PDF report**. "
                         "It includes your score, readiness badge, radar chart, findings and recommended actions."],
                        "Open your latest Results and download the PDF.")
    return None


# =====================================================================  core engine
def _urgent(qn, tokens):
    best, best_score = None, 0
    for key, pb in URGENT.items():
        s = _score(qn, tokens, pb["keys"])
        if s > best_score:
            best, best_score = key, s
    return best if best_score >= 2 else None


def _guide(qn, tokens):
    best, best_score = None, 0
    for key, g in GUIDES.items():
        s = _score(qn, tokens, g["keys"])
        if s > best_score:
            best, best_score = key, s
    return best if best_score >= 2 else None


def _render_urgent(key, level):
    pb = URGENT[key]
    parts = [pb["lead"], "**Do this now:**\n" + "\n".join(f"{i}. {s}" for i, s in enumerate(pb["now"], 1))]
    if pb["then"]:
        parts.append("**Then:**\n" + "\n".join(f"- {s}" for s in pb["then"]))
    parts.append("**What we know:** " + pb["facts"])
    if level == "beginner" and key in ("clicked", "hacked", "lost"):
        parts.append("*MFA means a second sign-in check, like a code from an app on your phone.*")
    if pb["ask"]:
        parts.append("**To tailor the next steps (please don't share passwords or codes):**\n" + "\n".join(f"- {a}" for a in pb["ask"]))
    parts.append("If this involves significant money, sensitive data or a work system, involve your bank, IT/security team or a qualified "
                 "incident-response professional - I can guide you, but I can't see or check your devices.")
    return _compose(parts, pb["next"])


def _render_guide(key, level):
    g = GUIDES[key]
    parts = [g["intro"], "\n".join(f"- {p}" for p in g["points"])]
    if g["close"]:
        parts.append(g["close"])
    if g["ask"]:
        parts.append(g["ask"])
    if level == "beginner":
        terms = [t for t in ("mfa", "patch", "backup", "vpn", "encryption", "segmentation", "https") if any(a in " ".join(g["points"]).lower() for a in GLOSSARY[t][0][:2])]
        if terms:
            parts.append("**Quick terms:**\n" + "\n".join(f"- **{GLOSSARY[t][0][0].upper() if len(GLOSSARY[t][0][0]) <= 4 else GLOSSARY[t][0][0].capitalize()}**: {GLOSSARY[t][1].split('.')[0]}." for t in terms[:3]))
    return _compose(parts, g["next"])


def _core(question, history, ctx):
    level = _level(question, history)
    qn = _norm(question)
    tokens = qn.split()
    default_sugs = ["Is this email a scam?", "What should I fix first?", "Explain MFA simply"]

    # 1. Harmful requests - refuse and redirect
    if any(h in qn for h in HARMFUL):
        return _compose([
            "I can't help with that, because it could be used to break into systems, steal information or harm people.",
            "I'm happy to help on the **defensive** side instead - for example:\n- how to protect accounts against password theft\n"
            "- how to detect or block that kind of attack\n- how to run an **authorised** security test on systems you own"],
            "Tell me what you're trying to protect, and I'll suggest practical defences."), ["How do I protect against ransomware?", "How do I spot phishing?"], level

    # 2. Sensitive data shared
    warn = ""
    if _has_sensitive(question):
        warn = ("**Quick safety note:** it looks like your message may contain a password, code, key or card/ID number. "
                "Please don't share those here or with anyone - I never need them. If it was real, change it as soon as possible.")

    # 3. Small talk
    if qn in GREETING or (len(tokens) <= 3 and tokens and tokens[0] in GREETING):
        return _compose(["Hi! I'm ShieldAI, your friendly security assistant. Ask me anything - in your own words, no technical terms needed."],
                        "Ask a question, or try 'Is this email a scam?'"), default_sugs, level
    if any(t in qn for t in THANKS) and len(tokens) <= 8:
        return _compose(["You're welcome - asking questions is one of the best security habits there is."],
                        "Is there anything else you'd like to check or protect?"), default_sugs, level

    # 4. Urgent incidents first
    u = _urgent(qn, tokens)
    if u in ("hacked", "money") and re.search(r"\b(prevent|avoid|protect|stop|before|future|next time|getting hacked|how do i not)\b", qn) \
            and not re.search(r"\b(i was|i got|i've been|ive been|i have been|we were|we got|my .* (got|was|is) hacked|paid|sent|transferred)\b", qn):
        u = None
    if u:
        text = _render_urgent(u, level)
        return (warn + "\n\n" + text if warn else text), ["What else should I check?", "How do I prevent this next time?"], level

    if warn:
        return _compose([warn], "Change the shared secret, then ask your question again without it."), default_sugs, level

    # 5. Platform questions
    p = _platform(qn, ctx, level)
    if p == "SCORE":
        p = _score_text()
    elif p is None:
        p = _platform_more(qn, ctx, level)
    if p == "TOUR":
        return "TOUR", default_sugs, level
    if p:
        return p, ["Explain this more simply", "What should I fix first?", "Give me a tour"], level

    # 6. Definitions ("what is X", "explain X", "what does X mean")
    is_define = re.search(r"\b(what is|what's|whats|what are|what does|meaning of|define|explain|tell me about|what do you mean by|mean)\b", qn)
    term = _find_term(qn)
    if term and (is_define or len(tokens) <= 4):
        d, action = _define(term, level)
        follow = f"Explain {GLOSSARY[term][0][0]} more simply" if level != "beginner" else f"How do I protect myself from {GLOSSARY[term][0][0]}?"
        return _compose([d], action), [follow, "What should I fix first?"], level

    # 7. Prevention / how-to guides
    gk = _guide(qn, tokens)
    if gk:
        return _render_guide(gk, level), ["Explain that more simply", "What should I do first?"], level

    # 8. Any known term mentioned at all
    if term:
        d, action = _define(term, level)
        return _compose([d], action), ["How do I protect against this?", "Explain more simply"], level

    # 9. "explain more simply" follow-up
    if any(w in qn for w in ["simpl", "plain", "don't understand", "dont understand", "confused", "what do you mean"]) and history:
        last = next((h.get("content", "") for h in reversed(history) if h.get("role") == "assistant"), "")
        t = _find_term(_norm(last))
        if t:
            d, action = _define(t, "beginner")
            return _compose(["No problem - let me put it more simply.", d], action), default_sugs, "beginner"

    # 10. Out-of-scope vs unclear
    security_words = ["laptop", "computer", "phone", "weird", "strange", "suspicious", "secur", "hack", "cyber", "attack", "safe", "risk", "protect", "threat", "scam", "fraud", "virus",
                      "breach", "privacy", "password", "account", "device", "network", "email", "data"]
    if not any(w in qn for w in security_words):
        return _compose(["I'm focused on cybersecurity and this platform, so I may not be the best help for that question.",
                         "I can help with things like scam messages, account safety, protecting devices, ransomware, or understanding your results."],
                        "Ask me a security question in your own words."), default_sugs, level
    return _compose([
        "I want to make sure I give you the right advice. Could you tell me a little more (please no passwords or codes)?",
        "- **What happened or what are you trying to do?** (e.g. a strange email, protecting an account, understanding a result)\n"
        "- **Is it a personal or work device/account?**\n- **Is anything happening right now** that feels urgent?",
        "If something looks wrong right now - like a ransom message or money leaving an account - say so and I'll start with the urgent steps."],
        "Describe the situation in a sentence or two, in your own words."), default_sugs, level


# =====================================================================  generative mode
def _context_text(ctx, level):
    parts = [f"Detected user experience level: {level}."]
    if not ctx:
        return " ".join(parts + ["No platform data available."])
    parts += [f"User role: {ctx.get('role')}.", f"Current page: {ctx.get('page') or 'unknown'}."]
    if ctx.get("score") is not None:
        parts.append(f"Latest self-assessed readiness: {ctx['score']}% ({ctx['readiness']}).")
        parts.append("Function scores: " + ", ".join(f"{k} {v}%" for k, v in ctx["functions"].items() if v is not None) + ".")
    else:
        parts.append("No completed assessment yet.")
    if ctx.get("weak"):
        parts.append("Weakest controls: " + "; ".join(f"{c} ({f}): {t}" for c, f, t in ctx["weak"][:6]) + ".")
    parts.append(f"Open remediation actions: {ctx.get('open_actions', 0)} ({ctx.get('critical', 0)} critical).")
    if ctx.get("exposure"):
        parts.append(f"Latest Threat Exposure result: {ctx['exposure']}.")
    return " ".join(parts)


def _generative(cfg, question, history, ctx, level):
    messages = [{"role": "system", "content": SYSTEM_PROMPT},
                {"role": "system", "content": "Context (aggregate, non-identifying; these are self-assessment results, not scans): "
                                              + _context_text(ctx, level)}]
    for turn in (history or [])[-8:]:
        role = "assistant" if turn.get("role") == "assistant" else "user"
        messages.append({"role": role, "content": redact(str(turn.get("content", "")))[:1500]})
    messages.append({"role": "user", "content": redact(question)})
    body = {"messages": messages, "max_tokens": 700, "temperature": 0.3}
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
        r = requests.post(url, headers=headers, json=body, timeout=30)
        r.raise_for_status()
        text = (r.json()["choices"][0]["message"]["content"] or "").strip()
        if not text:
            return None
        if "next step" not in text.lower():
            text += "\n\n**Next step:** Tell me a little more (no passwords or codes) if you'd like more tailored guidance."
        return {"answer": text[:5000], "engine": engine}
    except Exception:
        log.warning("Generative model unavailable; using ShieldAI Core")
        return None


# =====================================================================  public API
def answer(cfg, question, history, ctx):
    question = (question or "").strip()[:1000]
    history = history if isinstance(history, list) else []
    if not question:
        return {"answer": "Ask me anything about staying safe online or about this platform - in your own words.",
                "engine": "ShieldAI Core", "suggestions": ["Is this email a scam?", "Give me a tour"], "level": "everyday"}
    core_text, suggestions, level = _core(question, history, ctx)
    if core_text == "TOUR":
        return {"answer": "Let's take a quick tour. I'll highlight each part of the platform and explain it in plain language - use **Next** to continue.",
                "tour": True, "engine": "ShieldAI Core", "suggestions": suggestions, "level": level}
    qn = _norm(question)
    deterministic = (any(h in qn for h in HARMFUL) or _has_sensitive(question)
                     or core_text.startswith("Hi! I'm ShieldAI"))
    if not deterministic:
        gen = _generative(cfg or {}, question, history, ctx, level)
        if gen:
            gen.update(suggestions=suggestions, level=level)
            return gen
    return {"answer": core_text, "engine": "ShieldAI Core", "suggestions": suggestions, "level": level}


def executive_summary(ctx):
    """Deterministic summary used in the PDF report."""
    if not ctx or ctx.get("score") is None:
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
