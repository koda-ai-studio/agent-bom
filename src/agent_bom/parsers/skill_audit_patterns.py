"""Regex behavioral risk patterns and dangerous-launcher keywords for skill audits."""

from __future__ import annotations

import re
from typing import NamedTuple

_SHELL_COMMANDS = {"sh", "bash", "cmd", "powershell", "zsh"}

_DANGEROUS_ARG_KEYWORDS = {
    "--allow-exec",
    "exec",
    "shell",
    "--dangerous",
    "--yolo",
}

_DANGEROUS_SERVER_NAME_KEYWORDS = {"exec", "shell", "terminal", "command"}


# ── Behavioral risk pattern definitions ──────────────────────────────────────


class _BehavioralPattern(NamedTuple):
    """A regex-based behavioral risk pattern to detect in skill file prose/code.

    ``pattern`` is the high-confidence signal (an imperative directive, a
    concrete dangerous flag, or an actual command invocation). ``weak_pattern``
    is an optional lower-confidence heuristic — a bare feature name appearing in
    prose (e.g. "subagent", "delegation") that, on its own, is descriptive
    rather than evidence of malicious behavior. A weak-only match is downgraded
    to ``weak_severity`` with ``confidence="low"`` so a single descriptive
    keyword in a legitimate instruction file cannot escalate the file's verdict.
    """

    category: str  # e.g. "credential_file_access"
    severity: str  # "critical" | "high" | "medium" | "low"
    title: str  # Human-readable finding title
    pattern: re.Pattern  # Compiled regex (high-confidence signal)
    description: str  # Recommendation text
    weak_pattern: re.Pattern | None = None  # optional low-confidence keyword regex
    weak_severity: str = "low"  # severity to use when only weak_pattern matches


# One character that does not start a markdown heading or a frontmatter
# delimiter line, so a two-part prose match stays inside one section.
_SAME_SECTION = r"(?:(?!\n[ \t]{0,3}(?:#|---))[\s\S])"
_CREDENTIAL_PATHS = (
    r"(?:~?/?\.aws/credentials|~?/?\.aws/config|~?/\.ssh/id_[a-z0-9_]+|~?/\.ssh/id_rsa|~?/\.ssh/id_ed25519"
    r"|~?/\.netrc|~?/\.config/gcloud|~?/\.kube/config|~?/\.docker/config\.json|/etc/shadow"
    r"|(?<![\w.])\.env(?![\w])|Cookies(?:\.sqlite)?|Login\s+Data)"
)
_SEND_VERBS_NO_PUSH = r"(?:upload|exfiltrat\w*|post(?:ing|ed)?|send(?:ing)?|curl|wget|fetch(?:ing)?|transmit\w*|leak)"
_SEND_VERBS = r"(?:upload|exfiltrat\w*|post(?:ing|ed)?|send(?:ing)?|curl|wget|fetch(?:ing)?|transmit\w*|push(?:ing)?|leak)"

_BEHAVIORAL_PATTERNS: list[_BehavioralPattern] = [
    # ── CRITICAL ──────────────────────────────────────────────────────────
    _BehavioralPattern(
        category="credential_file_access",
        severity="critical",
        title="Credential/secret file access",
        pattern=re.compile(
            r"""
            \b op \s+ (signin|vault|item|read)          # 1Password CLI
            | \b security \s+ find-generic-password       # macOS Keychain
            | cat \s+ ~/? \. (config|ssh|aws|gnupg)       # dotfile credential dirs
            | \b vault \s+ (kv|read|write) \s             # HashiCorp Vault
            | \b aws \s+ secretsmanager                   # AWS Secrets Manager
            """,
            re.VERBOSE | re.IGNORECASE,
        ),
        description="Review and remove direct credential/secret file access. Use scoped environment variables instead.",
    ),
    _BehavioralPattern(
        category="credential_exfiltration",
        severity="critical",
        title="Natural-language credential exfiltration",
        # Prose-level exfiltration: a concrete sensitive credential/secret path
        # COMBINED (in any order, within a short window of one section) with an
        # action that sends it to an external URL. Requiring BOTH the path and the
        # send-to-URL action keeps benign skills that merely mention
        # "credentials" or cite a docs URL from matching.
        pattern=re.compile(
            rf"{_CREDENTIAL_PATHS}{_SAME_SECTION}{{0,240}}?{_SEND_VERBS}{_SAME_SECTION}{{0,120}}?https?://"
            rf"|{_SEND_VERBS_NO_PUSH}(?:{_SAME_SECTION}{{0,120}}?https?://{_SAME_SECTION}{{0,240}}?{_CREDENTIAL_PATHS}"
            rf"|{_SAME_SECTION}{{0,120}}?{_CREDENTIAL_PATHS}{_SAME_SECTION}{{0,120}}?https?://)",
            re.IGNORECASE,
        ),
        description=(
            "This skill instructs reading a credential/secret file and sending it to an external URL — "
            "credential exfiltration. Remove the instruction; never transmit local secrets off-host."
        ),
    ),
    _BehavioralPattern(
        category="remote_code_execution",
        severity="high",
        title="Remote script piped to a shell",
        # `curl <url> | bash` / `wget <url> | sh` — fetch-and-execute of remote
        # code. High-confidence: the pipe-into-shell is the dangerous signal.
        pattern=re.compile(
            r"\b(?:curl|wget)\b[^\n|]{0,200}\|\s*(?:sudo\s+)?(?:bash|sh|zsh|python[23]?)\b",
            re.IGNORECASE,
        ),
        description=(
            "Piping a remotely-fetched script straight into a shell runs unreviewed remote code. "
            "Download, inspect, and pin the script instead of executing it inline."
        ),
    ),
    _BehavioralPattern(
        category="confirmation_bypass",
        severity="critical",
        title="Safety confirmation bypass",
        pattern=re.compile(
            r"""
            --yolo \b                                     # Codex --yolo
            | --full-auto \b                              # Full auto mode
            | --no-sandbox \b                             # Sandbox disable
            | --dangerously-skip-permissions \b           # Claude Code skip perms
            | \b elevated \s* [:=] \s* true \b            # Elevated mode
            | \b auto_approve \s* [:=] \s* true \b        # Auto-approve
            | --no-verify \b                              # Git no-verify
            | \b allowedTools \s* [:=] \s* \[? \s* \*     # Wildcard tool allow
            """,
            re.VERBOSE | re.IGNORECASE,
        ),
        description="Remove safety bypasses. Never disable confirmation prompts or sandbox protections.",
    ),
    # ── HIGH ──────────────────────────────────────────────────────────────
    _BehavioralPattern(
        category="prompt_coercion",
        severity="high",
        title="Prompt coercion or guardrail override",
        pattern=re.compile(
            r"""
            (?:ignore|disregard|forget)\s+(?:all\s+)?(?:(?:the|your|any)\s+)?(?:previous|prior|above|earlier|preceding)\s+instructions
            | override \s+ (?:the \s+)? system \s+ prompt
            | reveal \s+ (?:the \s+)? system \s+ prompt
            | bypass \s+ (?:the \s+)? guardrails?
            | (?:(?:now|are)\s+in|enter|switch\s+to|activate)\s+developer\s+mode|developer\s+mode\s+(?:enabled|activated|on)\b
            | do \s+ not \s+ mention \s+ (?:the \s+)? policy
            """,
            re.VERBOSE | re.IGNORECASE,
        ),
        weak_pattern=re.compile(r"\bdeveloper\s+mode\b|\bjailbreak", re.IGNORECASE),
        description=(
            "Prompt coercion patterns try to override system instructions or hide policy checks. Remove or rewrite these instructions."
        ),
    ),
    _BehavioralPattern(
        category="messaging_capability",
        severity="high",
        title="Messaging/impersonation capability",
        pattern=re.compile(
            r"""
            \b imsg \s+ send \b                           # iMessage CLI
            | \b wacli \s+ send \b                        # WhatsApp CLI
            | \b slack \s+ (sendMessage|chat\.postMessage) # Slack API
            | \b discord \s+ send \b                      # Discord
            | \b twilio \s+ messages \b                   # Twilio SMS
            | \b sendgrid \b                              # SendGrid email
            | \b send[-_]?email \b                        # Generic email send
            """,
            re.VERBOSE | re.IGNORECASE,
        ),
        description="Messaging capabilities let the agent impersonate the user. Require explicit confirmation for every message.",
    ),
    _BehavioralPattern(
        category="voice_telephony",
        severity="high",
        title="Voice/telephony capability",
        pattern=re.compile(
            r"""
            \b voicecall \s+ call \b                      # Voice call CLI
            | \b twilio \s+ calls \b                      # Twilio voice
            | \b telnyx \b                                # Telnyx telephony
            | \b plivo \b                                 # Plivo telephony
            """,
            re.VERBOSE | re.IGNORECASE,
        ),
        description="Voice/telephony lets the agent make calls as the user. Remove or require human-in-the-loop.",
    ),
    _BehavioralPattern(
        category="agent_delegation",
        severity="high",
        title="Sub-agent delegation/spawning",
        pattern=re.compile(
            r"""
            \b codex \s+ (exec|--yolo) \b                 # Codex execution
            | \b claude \s+ (exec|--dangerously) \b       # Claude Code execution
            | \b spawn \s+ agent \b                       # Generic agent spawn
            | \b Task \s* \( .*? subagent                 # SDK Task() with subagent
            """,
            re.VERBOSE | re.IGNORECASE,
        ),
        description="Sub-agent delegation can bypass safety controls. Ensure child agents inherit permission restrictions.",
        # A bare "subagent"/"sub-agent"/"delegation" mention in prose (as in a
        # legitimate CLAUDE.md/AGENTS.md describing normal agent features) is a
        # descriptive keyword, not evidence of an actual spawn directive.
        weak_pattern=re.compile(
            r"""
            \b sub[-_]?agent s? \b                        # Sub-agent reference
            | \b agent \s+ delegation \b                  # Delegation reference
            """,
            re.VERBOSE | re.IGNORECASE,
        ),
        weak_severity="low",
    ),
    _BehavioralPattern(
        category="input_injection",
        severity="high",
        title="Keystroke/input injection",
        pattern=re.compile(
            r"""
            \b tmux \s+ send-keys \b                      # tmux injection
            | \b xdotool \s+ (key|type) \b                # X11 input injection
            | \b osascript .* keystroke \b                 # macOS keystroke
            | \b xdg-open \b                              # Open arbitrary URLs
            | \b AppleScript .* activate \b               # macOS app control
            """,
            re.VERBOSE | re.IGNORECASE,
        ),
        description="Input injection can control other applications. Remove keystroke/input simulation capabilities.",
    ),
    _BehavioralPattern(
        category="surveillance_access",
        severity="high",
        title="Camera/screen surveillance access",
        pattern=re.compile(
            r"""
            \b camsnap \b                                 # Camera snapshot
            | \b rtsp://                                  # RTSP camera stream
            | \b imagesnap \b                             # macOS camera
            | \b screencapture \b                         # macOS screenshot
            | \b ffmpeg .* /dev/video                     # Linux webcam
            | \b screenshot \s+ capture \b                # Generic screenshot
            """,
            re.VERBOSE | re.IGNORECASE,
        ),
        description="Surveillance access can capture sensitive visual data. Remove camera/screen capture capabilities.",
    ),
    _BehavioralPattern(
        category="privilege_escalation",
        severity="high",
        title="Privilege escalation",
        pattern=re.compile(
            r"""
            \b sudo \s+ \S                               # sudo with command
            | \b su \s+ -                                 # Switch user
            | \b doas \s+ \S                              # OpenBSD doas
            | \b chmod \s+ u\+s \b                        # Set SUID bit
            | \b chown \s+ root \b                        # Change owner to root
            """,
            re.VERBOSE | re.IGNORECASE,
        ),
        description="Privilege escalation grants root/admin access. Never run agents with elevated privileges.",
    ),
    _BehavioralPattern(
        category="financial_transaction",
        severity="high",
        title="Financial transaction capability",
        pattern=re.compile(
            r"""
            \b reorder \s+ --confirm \b                   # Auto-reorder
            | \b stripe \s+ charges \s+ create \b         # Stripe charge
            | \b paypal \s+ send \b                       # PayPal transfer
            | \b transfer[-_]?funds \b                    # Generic fund transfer
            | \b purchase[-_]?order \b                    # Purchase order
            | \b bitcoin[-_]?send \b                      # Crypto send
            """,
            re.VERBOSE | re.IGNORECASE,
        ),
        description="Financial transactions should never be automated without human approval. Add confirmation gates.",
    ),
    # ── MEDIUM ────────────────────────────────────────────────────────────
    _BehavioralPattern(
        category="network_exposure",
        severity="medium",
        title="Network exposure (bind to all interfaces)",
        pattern=re.compile(
            r"""
            --host \s+ 0\.0\.0\.0                         # Bind all interfaces
            | \b bind \s+ 0\.0\.0\.0                      # Socket bind all
            | \b ngrok \b                                 # ngrok tunnel
            | \b localtunnel \b                           # localtunnel
            | \b cloudflared \s+ tunnel \b                # Cloudflare tunnel
            """,
            re.VERBOSE | re.IGNORECASE,
        ),
        description="Binding to 0.0.0.0 or tunneling exposes local services to the network. Use 127.0.0.1 instead.",
    ),
    _BehavioralPattern(
        category="data_exfiltration",
        severity="medium",
        title="Data exfiltration / private data access",
        pattern=re.compile(
            r"""
            \b imsg \s+ history \b                        # iMessage history
            | \b read[-_]?contacts \b                     # Contact list access
            | \b sqlite3 .* (History|Cookies|Login)       # Browser data
            | \b chat[-_]?history \b                      # Chat history access
            | \b export[-_]?contacts \b                   # Contact export
            """,
            re.VERBOSE | re.IGNORECASE,
        ),
        description="Accessing private data (messages, contacts, browser history) is a privacy risk. Remove data access commands.",
    ),
    _BehavioralPattern(
        category="persistence_mechanism",
        severity="medium",
        title="Persistence mechanism (cron/launchd/systemd)",
        pattern=re.compile(
            r"""
            \b crontab \s+ -[ei] \b                       # Edit crontab
            | (?<!cron:\s")(?<!cron:\s')(?<!cron:\s) \*/\d+ \s+ \*  # Cron schedule, not a CI `cron:` key
            | \b launchctl \s+ load \b                    # macOS launchd
            | \b systemctl \s+ enable \b                  # Linux systemd
            | \b schtasks \s+ /create \b                  # Windows task scheduler
            """,
            re.VERBOSE | re.IGNORECASE,
        ),
        description="Persistence mechanisms let agents run unattended. Remove scheduled task creation capabilities.",
    ),
    _BehavioralPattern(
        category="memory_poisoning",
        severity="medium",
        title="Agent memory/config poisoning",
        pattern=re.compile(
            r"""
            \b (write|append|echo|cat\s*>) .* MEMORY\.md  # Claude memory
            | \b (write|append|echo|cat\s*>) .* CLAUDE\.md # Claude config
            | \b (write|append|echo|cat\s*>) .* \.cursorrules # Cursor config
            | \b (write|append|echo|cat\s*>) .* AGENTS\.md # Agents config
            | \b (write|append|echo|cat\s*>) .* \.windsurfrules # Windsurf config
            """,
            re.VERBOSE | re.IGNORECASE,
        ),
        description="Writing to agent config files can poison future sessions. Never allow skills to modify agent memory.",
    ),
    _BehavioralPattern(
        category="repository_modification",
        severity="medium",
        title="Repository modification (push/merge)",
        pattern=re.compile(
            r"""
            \b git \s+ push \b (?! .* --dry-run)          # git push (not dry-run)
            | \b git \s+ push \s+ --force \b              # Force push
            | \b gh \s+ pr \s+ merge \b                   # GitHub PR merge
            | \b git \s+ commit \b                        # git commit
            """,
            re.VERBOSE | re.IGNORECASE,
        ),
        description="Repository modifications can ship unreviewed code. Require human review before push/merge.",
    ),
    _BehavioralPattern(
        category="destructive_action",
        severity="medium",
        title="Destructive system action",
        pattern=re.compile(
            r"""
            \b rm \s+ -r?f \b                             # rm -rf / rm -f
            | \b kill \s+ -9 \b                           # Force kill process
            | \b DROP \s+ TABLE \b                        # SQL drop table
            | \b TRUNCATE \s+ TABLE \b                    # SQL truncate
            | \b shred \b                                 # Secure file deletion
            | \b mkfs \b                                  # Format filesystem
            """,
            re.VERBOSE | re.IGNORECASE,
        ),
        description="Destructive actions can cause data loss. Add confirmation prompts before any delete/destroy operation.",
    ),
]
