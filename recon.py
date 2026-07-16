#!/usr/bin/env python3
"""
█
ReconX Framework  v2.0
────────────────────────
Author  : Mohamed Abd almalek
Version : 2.0.0

8-Phase Automated Reconnaissance Pipeline
Subdomains → Live Hosts → Network → Tech → URLs → Params → JS → Vulns

Usage:
  python recon.py [domain] [mode] [options]
  python recon.py --check          # tool doctor
  python recon.py --update         # update tools
"""

import argparse
import json
import logging
import re
import shutil
import subprocess
import sys
import textwrap
import time
from concurrent.futures import ThreadPoolExecutor, wait
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Callable
from urllib.parse import urlparse

# ---------------------------------------------------------------------------
# Optional rich support — prettier --check table
# ---------------------------------------------------------------------------
try:
    from rich.console import Console
    from rich.table import Table
    import rich.box as box
    HAS_RICH = True
except ImportError:
    HAS_RICH = False

# =============================================================================
# CONFIGURATION
# =============================================================================

MODE_CONFIG = {
    "stealth":    {"threads": 7,  "katana_depth": 7,  "rate_limit": 20},
    "aggressive": {"threads": 20, "katana_depth": 15, "rate_limit": 30},
}

ALL_PORTS = "21,22,23,25,53,80,110,139,143,389,443,445,1433,1521,2049,2375,3000,3128,3306,3389,4848,5000,5432,5601,5900,5985,6379,7001,8000,8008,8080,8081,8443,8888,9000,9090,9200,11211,27017"
SENSITIVE_PORTS = "21,22,23,25,445,1433,1521,2375,3306,3389,5432,5900,6379,7001,9200,27017"
SENSITIVE_PORTS_SET = set(SENSITIVE_PORTS.split(","))

# =============================================================================
# TOOL REGISTRY
# =============================================================================

class Tool:
    __slots__ = ("name", "category", "version_cmd", "update_cmd", "required")
    def __init__(self, name: str, category: str, version_cmd: List[str],
                 update_cmd: Optional[List[str]] = None, required: bool = False):
        self.name = name
        self.category = category
        self.version_cmd = version_cmd
        self.update_cmd = update_cmd
        self.required = required

TOOL_REGISTRY: List[Tool] = [
    Tool("subfinder",   "core",     ["subfinder", "-version"],      required=True,
        update_cmd=["subfinder", "-update"]),
    Tool("dnsx",        "core",     ["dnsx", "-version"],           required=True,
        update_cmd=["dnsx", "-up"]),
    Tool("httpx",       "core",     ["httpx", "-version"],          required=True,
        update_cmd=["httpx", "-update"]),
    Tool("jq",          "core",     ["jq", "--version"],            required=True),
    Tool("nuclei",      "optional", ["nuclei", "-version"],
        update_cmd=["nuclei", "-up"]),
    Tool("nmap",        "optional", ["nmap", "--version"]),
    Tool("naabu",       "optional", ["naabu", "-version"],
        update_cmd=["naabu", "-update"]),
    Tool("chaos",       "optional", ["chaos", "-version"],
        update_cmd=["chaos", "-update"]),
    Tool("shuffledns",  "optional", ["shuffledns", "-version"],
        update_cmd=["shuffledns", "-up"]),
    Tool("subzy",       "optional", ["subzy", "version"]),
    Tool("gowitness",   "optional", ["gowitness", "--version"]),
    Tool("katana",      "optional", ["katana", "-version"],
        update_cmd=["katana", "-up"]),
    Tool("hakrawler",   "optional", ["hakrawler"]),
    Tool("gauplus",     "optional", ["gauplus", "-version"]),
    Tool("waybackurls", "optional", ["waybackurls", "-version"]),
    Tool("subjs",       "optional", ["subjs", "-version"]),
    Tool("uro",         "optional", ["uro", "--version"],
        update_cmd=["pip3", "install", "--user", "--upgrade", "uro"]),
    Tool("xnLinkFinder","optional", ["xnLinkFinder", "--version"],
        update_cmd=["pip3", "install", "--user", "--upgrade", "xnlinkfinder"]),
    Tool("arjun",       "optional", ["arjun", "--version"],
        update_cmd=["pip3", "install", "--user", "--upgrade", "arjun"]),
    Tool("qsreplace",   "optional", ["qsreplace", "-version"]),
    Tool("gf",          "optional", ["gf", "--version"]),
    Tool("feroxbuster", "optional", ["feroxbuster", "--version"]),
    Tool("js-beautify", "optional", ["js-beautify", "--version"],
        update_cmd=["pip3", "install", "--user", "--upgrade", "jsbeautifier"]),
        
]

# =============================================================================
# LOGGING SYSTEM — 3 LAYERS
# =============================================================================

class ReconLogger:
    """Layer 1: Console | Layer 2: Detailed logs"""
    
    def __init__(self, log_dir: Path, verbose: int):
        self.log_dir = log_dir
        self.verbose = verbose
        self.tool_logs = log_dir / "tools"
        self.phase_logs = log_dir / "phases"
        self.tool_logs.mkdir(parents=True, exist_ok=True)
        self.phase_logs.mkdir(parents=True, exist_ok=True)
        
        # Python logger for file output
        self._file_logger = logging.getLogger("recon_file")
        self._file_logger.setLevel(logging.DEBUG)
        handler = logging.FileHandler(log_dir / "recon.log", mode="a")
        handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
        self._file_logger.addHandler(handler)
    
    def log(self, msg: str):
        """Always show (phase starts, summaries, critical)"""
        print(f"  \033[1;32m[{datetime.now().strftime('%H:%M:%S')}] {msg}\033[0m")
        self._file_logger.info(msg)
    
    def warn(self, msg: str):
        """Warnings — always shown"""
        print(f"  \033[1;33m[WARN] {msg}\033[0m", file=sys.stderr)
        self._file_logger.warning(msg)
    
    def error(self, msg: str):
        """Errors — always shown"""
        print(f"  \033[1;31m[ERROR] {msg}\033[0m", file=sys.stderr)
        self._file_logger.error(msg)
    
    def info(self, msg: str):
        """Normal progress — shown in normal + verbose modes"""
        if self.verbose >= 1:
            print(f"  [.] {msg}")
            self._file_logger.info(msg)
    
    def debug(self, msg: str):
        """Detailed output — only in verbose mode"""
        if self.verbose >= 2:
            print(f"  [DEBUG] {msg}")
            self._file_logger.debug(msg)
    
    def finding(self, severity: str, msg: str):
        """Highlighted finding (critical/high)"""
        color = "\033[1;31m" if severity.upper() in ("CRITICAL", "HIGH") else "\033[1;33m"
        print(f"  {color}[{severity.upper()}] {msg}\033[0m")
        self._file_logger.info(f"[FINDING][{severity}] {msg}")
    
    def phase_header(self, num: int, name: str):
        CONFIG.current_phase = num
        print("")
        self.log(f"{'='*8} Phase {num}: {name} {'='*8}")
    
    def phase_footer(self, num: int, elapsed: float):
        mins = int(elapsed // 60)
        secs = int(elapsed % 60)
        self.log(f"Phase {num} done — {mins}m {secs}s")
    
    def progress_bar(self, current: int, total: int, prefix: str = ""):
        pct = current / total if total > 0 else 0
        bar_len = 20
        filled = int(bar_len * pct)
        bar = "\u2588" * filled + "\u2591" * (bar_len - filled)
        if self.verbose >= 1:
            print(f"  \r{prefix}[{bar}] {current}/{total}", end="", flush=True)
            if current == total:
                print()


class NullLogger(ReconLogger):
    """No-op logger used before the real ReconLogger is initialised."""
    tool_logs: Path = Path()

    def __init__(self) -> None:
        self.verbose = 0
        self.tool_logs = Path()
        self.phase_logs = Path()

    def log(self, msg: str) -> None: pass
    def warn(self, msg: str) -> None: pass
    def error(self, msg: str) -> None: pass
    def info(self, msg: str) -> None: pass
    def debug(self, msg: str) -> None: pass
    def finding(self, severity: str, msg: str) -> None: pass
    def phase_header(self, num: int, name: str) -> None: pass
    def phase_footer(self, num: int, elapsed: float) -> None: pass
    def progress_bar(self, current: int, total: int, prefix: str = "") -> None: pass


# =============================================================================
# CONFIGURATION / GLOBAL STATE
# =============================================================================

@dataclass
class ReconConfig:
    """Central configuration - replaces global variables."""
    out_dir: Optional[Path] = None
    verbose: int = 1
    phase_total: int = 8
    current_phase: int = 0
    domain: str = ""
    mode: str = "stealth"
    cfg: dict = field(default_factory=dict)
    logger: ReconLogger = field(default_factory=NullLogger)

# Global config instance (single source of truth)
CONFIG = ReconConfig()

# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

def escape_domain(domain: str) -> str:
    return re.escape(domain)

def safe_count(path: Path) -> int:
    if path.exists() and path.stat().st_size > 0:
        try:
            with open(path) as f:
                return sum(1 for _ in f)
        except Exception:
            return 0
    return 0

def write_lines(path: Path, lines):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        for line in lines:
            f.write(str(line).rstrip("\n") + "\n")

def read_lines(path: Path) -> List[str]:
    if not path.exists():
        return []
    with open(path) as f:
        return [line.strip() for line in f if line.strip()]

def append_line(path: Path, line: str):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a") as f:
        f.write(line.rstrip("\n") + "\n")

# =============================================================================
# TOOL EXECUTION
# =============================================================================

def which(tool_name: str) -> Optional[str]:
    """Find tool path (cross-platform: checks .exe, .cmd on Windows)."""
    return shutil.which(tool_name)

_VERSION_RE = re.compile(r'v?\d+\.\d+(?:\.\d+)?')

def _extract_version(text: str) -> str:
    """Extract version string, return '?' on failure."""
    m = _VERSION_RE.search(text)
    return m.group() if m else "?"

SPECIAL_PARSERS = {
    "subfinder":  _extract_version,
    "nuclei":     _extract_version,
    "dnsx":       _extract_version,
    "httpx":      _extract_version,
    "naabu":      _extract_version,
    "katana":     _extract_version,
    "shuffledns": _extract_version,
    "chaos":      _extract_version,
}


def clean_output(text: str) -> str:
    if not text:
        return "-"
    text = re.sub(r"\x1b\[[0-9;]*m", "", text)
    text = text.splitlines()[0] if text else "-"
    text = " ".join(text.split())
    if len(text) > 35:
        text = text[:35] + "..."
    return text or "-"


def find_wordlist() -> Optional[Path]:
    """Locate a DNS bruteforce wordlist across common OS paths."""
    script_dir = Path(__file__).parent.resolve()
    candidates = [
        Path("/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"),
        Path("/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt"),
        Path.home() / "Documents" / "SecLists" / "Discovery" / "DNS" / "subdomains-top1million-5000.txt",
        Path.home() / "wordlists" / "best-dns-wordlist.txt",
        Path.home() / "wordlists" / "subdomains-top1million-5000.txt",
        script_dir / "config" / "default_wordlist.txt",
    ]
    for c in candidates:
        if c.exists():
            return c
    return None


def find_nuclei_templates_dir() -> Optional[Path]:
    """Locate nuclei templates directory across platforms."""
    candidates = [
        Path.home() / ".local" / "nuclei-templates",
        Path.home() / "Library" / "Application Support" / "nuclei-templates",
    ]
    for c in candidates:
        if c.exists():
            return c
    return None


def get_tool_version(tool: Tool) -> str:
    if not which(tool.name):
        return "-"
    try:
        result = subprocess.run(
            tool.version_cmd,
            capture_output=True, text=True, timeout=10
        )
        output = (result.stdout + "\n" + result.stderr).strip()
        if not output:
            return "-"

        # SPECIAL_PARSER: extract pure version (e.g. v2.6.6 from "[INF] ... v2.6.6")
        if tool.name in SPECIAL_PARSERS:
            match = _VERSION_RE.search(output)
            if match:
                return match.group()

        # General: find version pattern → return its line (cleaned)
        match = _VERSION_RE.search(output)
        if match:
            for line in output.splitlines():
                if match.group() in line:
                    return clean_output(line)
            return match.group()

        # Nothing version-like found
        return "-"
    except Exception:
        return "-"

def run_tool(
    name: str,
    cmd: List[str],
    stdout_path: Optional[Path] = None,
    stderr_log: bool = True,
    timeout: int = 3600,
    stdin_path: Optional[Path] = None,
    cwd: Optional[Path] = None,
    capture: bool = False,
) -> Optional[subprocess.CompletedProcess]:
    """Run an external tool with 3-layer logging.
    
    Layer 1 (console): Only the command name + eventual summary
    Layer 2 (logs/):   Full stderr → logs/tools/{name}.log
    Layer 3 (files):   stdout → specified file (recon data)
    """
    if not which(name):
        if stderr_log:
            CONFIG.logger.debug(f"Tool '{name}' not found — skipping")
        return None
    
    CONFIG.logger.debug(f"Running: {' '.join(cmd)}")
    
    # Layer 2: stderr → tool log
    tool_log_path = CONFIG.logger.tool_logs / f"{name}.log"
    stderr_f = open(tool_log_path, "a")
    stderr_f.write(f"\n--- {datetime.now().isoformat()} {' '.join(cmd)} ---\n")
    
    # Layer 3: stdout → data file or pipe
    stdout_f = None
    if stdout_path:
        stdout_path.parent.mkdir(parents=True, exist_ok=True)
        stdout_f = open(stdout_path, "a")
    
    stdin_f = None
    if stdin_path and stdin_path.exists():
        stdin_f = open(stdin_path)
    
    try:
        result = subprocess.run(
            cmd,
            stdin=stdin_f,
            stdout=stdout_f or (subprocess.PIPE if capture else subprocess.DEVNULL),
            stderr=stderr_f,
            timeout=timeout,
            cwd=str(cwd) if cwd else None,
            text=True,
        )
        return result
    except subprocess.TimeoutExpired:
        CONFIG.logger.warn(f"Tool '{name}' timed out after {timeout}s")
        return None
    except FileNotFoundError:
        CONFIG.logger.warn(f"Tool '{name}' not found at runtime")
        return None
    except Exception as e:
        CONFIG.logger.warn(f"Tool '{name}' failed: {e}")
        return None
    finally:
        if stdout_f:
            stdout_f.close()
        if stdin_f:
            stdin_f.close()
        stderr_f.close()

def tool_available(name: str) -> bool:
    return which(name) is not None

# =============================================================================
# PHASE RUNNER
# =============================================================================

class PhaseRunner:
    """Manages resume markers and phase execution."""
    
    def __init__(self, out_dir: Path):
        self.out_dir = out_dir
    
    def is_done(self, phase: int) -> bool:
        return (self.out_dir / f".phase_{phase}_done").exists()
    
    def mark_done(self, phase: int):
        (self.out_dir / f".phase_{phase}_done").touch()
    
    def run(self, phase: int, name: str, func: Callable[[], None]) -> None:
        if self.is_done(phase):
            CONFIG.logger.log(f"Skipping Phase {phase}: already completed")
            return
        CONFIG.logger.phase_header(phase, name)
        start = time.time()
        try:
            func()
        except Exception as e:
            CONFIG.logger.error(f"Phase {phase} failed: {e}")
            raise
        elapsed = time.time() - start
        CONFIG.logger.phase_footer(phase, elapsed)
        self.mark_done(phase)

# =============================================================================
# RECON PIPELINE
# =============================================================================

class ReconPipeline:
    """Main pipeline orchestrating all 8 phases."""
    
    def __init__(self, domain: str, mode: str, out_dir: Path, verbose: int):
        self.domain = domain
        self.domain_escaped = escape_domain(domain)
        self.mode = mode
        self.cfg = MODE_CONFIG[mode]
        self.out = out_dir
        self.verbose = verbose
        self.runner = PhaseRunner(out_dir)
        
        # Pre-compiled regex for subdomain validation
        self._subdomain_re = re.compile(rf"([a-zA-Z0-9_-]+\.)+{self.domain_escaped}$")
        
        # Sub-directories
        self.d_sub = out_dir / "subdomains"
        self.d_live = out_dir / "live_hosts"
        self.d_net = out_dir / "network"
        self.d_tech = out_dir / "technology"
        self.d_content = out_dir / "content"
        self.d_params = out_dir / "parameters"
        self.d_js = out_dir / "javascript"
        self.d_vulns = out_dir / "vulnerabilities"
        self.d_screens = out_dir / "screenshots"
        self.d_vuln_all = out_dir / "vulnerabilities"
        
        for d in [self.d_sub, self.d_live, self.d_net, self.d_tech,
                  self.d_content, self.d_params, self.d_js, self.d_vulns,
                  self.d_screens]:
            d.mkdir(parents=True, exist_ok=True)
        
        # Shared paths (Layer 3 — recon data)
        self.f_final_subdomains = self.d_sub / "final.txt"
        self.f_httpx_urls = self.d_live / "httpx.txt"
        self.f_httpx_web = self.d_live / "httpx_web.txt"
        self.f_live_urls = self.d_content / "live_urls.txt"
        self.f_live_urls_200 = self.d_content / "live_urls_200_only.txt"
    
    # ================================================================
    # PHASE 1: SUBDOMAIN ENUMERATION
    # ================================================================
    
    def _phase1(self) -> None:
        d = self.d_sub
        passive_file = d / "passive.txt"
        bruteforce_file = d / "bruteforce.txt"
        raw_file = d / "raw.txt"
        validated_file = d / "validated.txt"
        
        for f in [passive_file, bruteforce_file, raw_file, validated_file, self.f_final_subdomains]:
            f.write_text("")
        
        # Passive
        CONFIG.logger.info("Passive enumeration...")
        run_tool("subfinder", [
            "subfinder", "-d", self.domain,
            "-silent", "-all", "-timeout", "30", "-max-time", "60",
            "-o", str(passive_file)
        ])
        
        if tool_available("chaos"):
            run_tool("chaos", [
                "chaos", "-d", self.domain, "-silent"
            ], stdout_path=passive_file)
        
        # Bruteforce
        CONFIG.logger.info("DNS Bruteforce...")
        wordlist = find_wordlist()
        
        if tool_available("shuffledns") and wordlist and wordlist.exists():
            resolver = Path.home() / "resolvers.txt"
            # Fallback to config/resolvers.txt if home doesn't have it
            if not resolver.exists():
                config_resolver = Path(__file__).parent / "config" / "resolvers.txt"
                if config_resolver.exists():
                    resolver = config_resolver
                    CONFIG.logger.debug(f"Using config resolvers: {resolver}")
                else:
                    CONFIG.logger.warn("No resolvers.txt found - shuffledns may fail")
            run_tool("shuffledns", [
                "shuffledns", "-d", self.domain,
                "-w", str(wordlist),
                "-r", str(resolver),
                "-silent", "-o", str(bruteforce_file)
            ])
        elif not wordlist or not wordlist.exists():
            CONFIG.logger.warn("No wordlist found - skipping bruteforce")
        
        # Merge + clean
        CONFIG.logger.info("Merging and cleaning...")
        all_subs = set()
        for f in [passive_file, bruteforce_file]:
            if f.exists():
                for line in read_lines(f):
                    line = line.strip()
                    if not line:
                        continue
                    # Extract hostname from various tool output formats
                    # subfinder: just hostname
                    # dnsx/others: hostname [A 1.2.3.4] [CNAME ...]
                    hostname = line.split()[0] if line.split() else line
                    # Validate it's a subdomain of target
                    if self._subdomain_re.search(hostname):
                        all_subs.add(hostname)
        
        # Filter noise - only obvious test patterns
        all_subs = {s for s in all_subs if not re.match(r"^test\d?\.|^dev-old\.|^staging-old\.", s)}
        write_lines(raw_file, all_subs)
        CONFIG.logger.info(f"Raw (pre-validation): {len(all_subs)}")
        
        # DEBUG: show first 10 raw subdomains
        if CONFIG.verbose >= 2:
            for i, s in enumerate(list(all_subs)[:10]):
                CONFIG.logger.debug(f"  Raw[{i}]: {s}")
        
        # Validate with dnsx - REMOVED -wd (wildcard detection drops valid subs)
        CONFIG.logger.info("Validating with DNSX...")
        validated_tmp = d / "validated_tmp.txt"
        if raw_file.stat().st_size > 0:
            run_tool("dnsx", [
                "dnsx", "-l", str(raw_file),
                "-silent", "-resp", "-a", "-cname",
                "-retries", "2",
                "-o", str(validated_tmp)
            ])
        
        validated_subs = set()
        if validated_tmp.exists():
            for line in read_lines(validated_tmp):
                parts = line.split()
                if parts:
                    # First field is hostname
                    hostname = parts[0]
                    if self._subdomain_re.search(hostname):
                        validated_subs.add(hostname)
            validated_tmp.unlink(missing_ok=True)
        
        # DEBUG: show validated count
        CONFIG.logger.info(f"DNSX validated: {len(validated_subs)} subdomains")
        if CONFIG.verbose >= 2:
            for i, s in enumerate(list(validated_subs)[:10]):
                CONFIG.logger.debug(f"  Validated[{i}]: {s}")
        
        if validated_subs:
            write_lines(self.f_final_subdomains, validated_subs)
        else:
            CONFIG.logger.warn("No subdomains validated — using main domain as fallback")
            write_lines(self.f_final_subdomains, [self.domain])
        
        CONFIG.logger.info(f"Validated: {safe_count(self.f_final_subdomains)} subdomains")
        
        # Takeover detection
        if tool_available("subzy") and self.f_final_subdomains.exists():
            CONFIG.logger.info("Subdomain Takeover (subzy)...")
            run_tool("subzy", [
                "subzy", "run",
                "--targets", str(self.f_final_subdomains),
                "--vuln", "--https",
                "--concurrency", "50",
                "--timeout", "10",
                "--hide_fails"
            ], stdout_path=d / "takeover_subzy.txt")
        
        if tool_available("nuclei") and self.f_final_subdomains.exists():
            run_tool("nuclei", [
                "nuclei", "-l", str(self.f_final_subdomains),
                "-tags", "takeover",
                "-c", str(self.cfg["threads"]),
                "-rl", str(self.cfg["rate_limit"]),
                "-o", str(d / "takeover_nuclei.txt")
            ])
    
    # ================================================================
    # PHASE 2: LIVE HOST DETECTION
    # ================================================================
    
    def _phase2(self) -> None:
        if not self.f_final_subdomains.exists() or self.f_final_subdomains.stat().st_size == 0:
            CONFIG.logger.warn("No subdomains — skipping live host detection")
            write_lines(self.d_live / "httpx.txt", [f"https://{self.domain}"])
            write_lines(self.d_content / "live_subdomains.txt", [self.domain])
            return
        
        CONFIG.logger.info("Probing live hosts...")
        status_file = self.d_live / "httpx_with_status.txt"
        run_tool("httpx", [
            "httpx", "-l", str(self.f_final_subdomains),
            "-threads", str(self.cfg["threads"]),
            "-rate-limit", str(self.cfg["rate_limit"]),
            "-random-agent", "-follow-redirects",
            "-status-code",
            "-mc", "200,204,301,302,307,308,401,403,404,405,500,502,503",
            "-timeout", "8", "-silent",
            "-o", str(status_file)
        ])
        
        if not status_file.exists() or status_file.stat().st_size == 0:
            CONFIG.logger.warn("No live hosts detected, using main domain")
            write_lines(self.f_httpx_urls, [f"https://{self.domain}"])
            write_lines(self.d_content / "live_subdomains.txt", [self.domain])
            return
        
        urls = []
        live_urls = []
        subdomains = set()
        for line in read_lines(status_file):
            parts = line.split()
            if parts:
                url = parts[0]
                urls.append(url)
                # Check for status codes
                for p in parts[1:]:
                    if p.startswith("[") and p.endswith("]"):
                        status = p.strip("[]")
                        if status in ("200","301","302","307","308","401","403"):
                            live_urls.append(url)
                        break
                # Extract subdomain
                parsed = urlparse(url)
                host = parsed.hostname or url.replace("https://","").replace("http://","").split("/")[0].split(":")[0]
                subdomains.add(host)
        
        write_lines(self.f_httpx_urls, urls)
        write_lines(self.d_live / "httpx_live.txt", live_urls)
        write_lines(self.d_content / "live_subdomains.txt", subdomains)
        
        # Screenshots with gowitness
        if tool_available("gowitness"):
            CONFIG.logger.info("Screenshots with gowitness...")
            run_tool("gowitness", [
                "gowitness", "scan", "file",
                "-f", str(self.f_httpx_urls),
                "--screenshot-path", str(self.d_screens),
                "--db-path", str(self.d_screens / "gowitness.db"),
                "--threads", str(self.cfg["threads"]),
                "--timeout", "10", "--write-db"
            ])
            
            run_tool("gowitness", [
                "gowitness", "report", "generate",
                "--db-path", str(self.d_screens / "gowitness.db"),
                "--output", str(self.d_screens / "report.html")
            ])
            
            png_count = len(list(self.d_screens.glob("*.png")))
            CONFIG.logger.info(f"Screenshots: {png_count}")
        
        CONFIG.logger.info(f"Live URLs: {safe_count(self.f_httpx_urls)}")
        CONFIG.logger.info(f"Live subdomains: {safe_count(self.d_content / 'live_subdomains.txt')}")
    
    # ================================================================
    # PHASE 3: NETWORK SCANNING
    # ================================================================
    
    def _phase3(self) -> None:
        d_net = self.d_net
        live_subdomains_file = self.d_content / "live_subdomains.txt"
        
        if not live_subdomains_file.exists() or live_subdomains_file.stat().st_size == 0:
            CONFIG.logger.warn("No live subdomains — skipping network scan")
            return
        
        subdomain_list = read_lines(live_subdomains_file)
        target_count = len(subdomain_list)
        CONFIG.logger.info(f"Network scan: {target_count} targets")
        
        # Configure rates based on mode
        if self.mode == "aggressive":
            httpx_threads = 100
            naabu_rate = 2000
            nuclei_conc = 50
        else:
            httpx_threads = 50
            naabu_rate = 500
            nuclei_conc = 20
        
        summary_file = d_net / "network_summary.txt"
        manual_file = d_net / "manual_targets.txt"
        web_urls_file = self.d_live / "web_urls.txt"
        open_tcp_file = d_net / "open_tcp.txt"
        open_tcp_json = d_net / "open_tcp.json"
        nmap_fast_gnmap = d_net / "nmap_fast.gnmap"
        
        # Stage 1: httpx + naabu — parallel
        CONFIG.logger.info("Stage 1: httpx + naabu (parallel)...")
        
        with ThreadPoolExecutor(max_workers=2) as pool:
            # httpx
            def run_httpx():
                httpx_json_out = d_net / "httpx_web.json"
                run_tool("httpx", [
                    "httpx", "-l", str(live_subdomains_file),
                    "-silent",
                    "-threads", str(httpx_threads),
                    "-rate-limit", "200",
                    "-mc", "200,204,301,302,401,403,405,500",
                    "-tech-detect", "-title", "-status-code", "-ip",
                    "-cdn", "-cname",
                    "-follow-redirects", "-random-agent",
                    "-json",
                    "-o", str(httpx_json_out)
                ])
                # Derive httpx_web.txt (text format) from JSON
                if httpx_json_out.exists():
                    web_lines = []
                    for line in read_lines(httpx_json_out):
                        try:
                            obj = __import__("json").loads(line)
                            url = obj.get("url", "")
                            techs = ", ".join(obj.get("tech", []))
                            title = obj.get("title", "")
                            web_lines.append(f"{url} [{title}] [{techs}]")
                        except Exception:
                            web_lines.append(line.split()[0] if line.split() else line)
                    write_lines(self.f_httpx_web, web_lines)
                    urls = [line.split()[0] for line in web_lines if line]
                    write_lines(web_urls_file, urls)
            
            # naabu
            def run_naabu():
                if tool_available("naabu"):
                    run_tool("naabu", [
                        "naabu", "-list", str(live_subdomains_file),
                        "-p", ALL_PORTS,
                        "-rate", str(naabu_rate),
                        "-scan-all-ips",
                        "-silent", "-json",
                        "-o", str(open_tcp_json)
                    ])
                    
                    if open_tcp_json.exists() and tool_available("jq"):
                        result = subprocess.run(
                            ["jq", "-r", r'"\(.host):\(.port)"', str(open_tcp_json)],
                    capture_output=True, text=True, timeout=600
                        )
                        if result.stdout:
                            write_lines(open_tcp_file, result.stdout.strip().split("\n"))
                    elif open_tcp_json.exists():
                        # Fallback: fragile JSON parsing
                        hosts_ports = []
                        for line in read_lines(open_tcp_json):
                            m = re.search(r'"host":"([^"]*)".*"port":(\d+)', line)
                            if m:
                                hosts_ports.append(f"{m.group(1)}:{m.group(2)}")
                        write_lines(open_tcp_file, hosts_ports)
            
            f1 = pool.submit(run_httpx)
            f2 = pool.submit(run_naabu)
            wait([f1, f2])
        
        web_count = safe_count(web_urls_file)
        port_count = safe_count(open_tcp_file)
        summary_file.write_text(f"Targets: {target_count} | Web: {web_count} | Ports: {port_count}\n\n")
        CONFIG.logger.info(f"Web: {web_count} | Ports: {port_count}")
        
        # Stage 2: nmap fast + nuclei web — parallel
        # Use ALL ports from naabu, not just top 20
        if open_tcp_file.exists():
            ports_set = set()
            for line in read_lines(open_tcp_file):
                if ":" in line:
                    ports_set.add(line.split(":")[1])
            top_ports = ",".join(sorted(ports_set)) if ports_set else "22,80,443,8080,8443"
        else:
            top_ports = "22,80,443,8080,8443"
        
        CONFIG.logger.info("Stage 2: nmap fast + nuclei web (parallel)...")
        
        with ThreadPoolExecutor(max_workers=2) as pool:
            def run_nmap_fast():
                if tool_available("nmap") and live_subdomains_file.exists():
                    run_tool("nmap", [
                        "nmap", "-iL", str(live_subdomains_file),
                        "-p", top_ports,
                        "-sV", "--version-light",
                        "-n", "-T4", "--open",
                        "--max-retries", "0",
                        "--host-timeout", "1m",
                        "--min-rate", "1000",
                        "-oA", str(d_net / "nmap_fast")
                    ])
            
            def run_nuclei_web():
                if tool_available("nuclei") and web_urls_file.exists():
                    run_tool("nuclei", [
                        "nuclei", "-l", str(web_urls_file),
                        "-tags", "cve,exposure,misconfig",
                        "-severity", "critical,high,medium",
                        "-concurrency", str(nuclei_conc),
                        "-rate-limit", "1000",
                        "-retries", "1", "-timeout", "5",
                        "-silent",
                        "-o", str(self.d_vulns / "nuclei_web.txt")
                    ])
            
            pool.submit(run_nmap_fast)
            pool.submit(run_nuclei_web)
        
        # Stage 3: nmap deep + nuclei network — parallel
        deep_targets = set()
        host_ports_map: dict[str, list[str]] = {}
        if nmap_fast_gnmap.exists():
            gnmap_host_re = re.compile(r"Host:\s+(\S+)")
            gnmap_port_re = re.compile(r"(\d+)/open/tcp")
            current_host = None
            for line in read_lines(nmap_fast_gnmap):
                if not line or not line.startswith("Host:"):
                    continue
                host_match = gnmap_host_re.search(line)
                if host_match:
                    current_host = host_match.group(1)
                port_matches = gnmap_port_re.findall(line)
                if current_host and port_matches:
                    host_ports_map.setdefault(current_host, []).extend(port_matches)
                    for port in port_matches:
                        if port in SENSITIVE_PORTS_SET:
                            deep_targets.add(current_host)
        
        if deep_targets:
            deep_input = d_net / "deep_scan_input.txt"
            # Resolve via dnsx if available
            if tool_available("dnsx"):
                write_lines(deep_input, deep_targets)
                result = subprocess.run(
                    ["dnsx", "-l", str(deep_input), "-resp-only", "-silent"],
                    capture_output=True, text=True, timeout=600
                )
                resolved = [host.strip() for host in result.stdout.strip().split("\n") if host.strip()]
                write_lines(deep_input, resolved)
            else:
                write_lines(deep_input, deep_targets)
            
            CONFIG.logger.info(f"Stage 3: deep scan — {safe_count(deep_input)} targets")
            
            with ThreadPoolExecutor(max_workers=2) as pool:
                def run_nmap_deep():
                    if tool_available("nmap"):
                        run_tool("nmap", [
                            "nmap", "-iL", str(deep_input),
                            "-p", SENSITIVE_PORTS,
                            "-n", "-sV", "--version-light",
                            "--script", "vuln and not dos",
                            "-T4", "--open",
                            "--max-retries", "1",
                            "--host-timeout", "2m",
                            "--min-rate", "1000",
                            "-oN", str(d_net / "nmap_vuln.txt")
                        ])
                
                def run_nuclei_net():
                    if tool_available("nuclei"):
                        run_tool("nuclei", [
                            "nuclei", "-l", str(deep_input),
                            "-tags", "network,default",
                            "-severity", "critical,high,medium",
                            "-concurrency", "30",
                            "-rate-limit", "1000",
                            "-retries", "1", "-timeout", "5",
                            "-silent",
                            "-o", str(self.d_vulns / "nuclei_network.txt")
                        ])
                
                pool.submit(run_nmap_deep)
                pool.submit(run_nuclei_net)
        
        # Prioritization (P1/P2)
        p1_meta = {
            "2375": "Docker API",
            "6379": "Redis",
            "9200": "Elasticsearch",
            "27017": "MongoDB",
            "11211": "Memcached",
            "5900": "VNC",
        }
        p2_meta = {
            "21": "FTP (anonymous?)",
            "23": "Telnet",
            "445": "SMB",
            "1433": "MSSQL",
            "3389": "RDP",
            "5432": "PostgreSQL",
            "7001": "WebLogic",
        }
        
        p1_entries, p2_entries = [], []
        
        # Pre-build httpx_web lookup dict for O(1) Elasticsearch checks
        httpx_web_hosts: dict[str, str] = {}
        if self.f_httpx_web.exists():
            for wline in read_lines(self.f_httpx_web):
                wline_lower = wline.lower()
                for wpart in wline.split():
                    if "." in wpart and not wpart.startswith("["):
                        httpx_web_hosts[wpart] = wline_lower
                        break
        
        for host, ports in host_ports_map.items():
            for port in ports:
                if port in p1_meta:
                    entry = f"{host} | {p1_meta[port]}"
                    if port == "9200" and host in httpx_web_hosts:
                        wline_lower = httpx_web_hosts[host]
                        if "elastic" in wline_lower or "kibana" in wline_lower:
                            entry = f"{host} | Elasticsearch | CRITICAL web+confirmed"
                    p1_entries.append(entry)
                elif port in p2_meta:
                    p2_entries.append(f"{host} | {p2_meta[port]}")
        
        # Generate manual targets file
        with open(manual_file, "w") as f:
            f.write(f"# MANUAL TARGET LIST — {datetime.now().isoformat()}\n")
            f.write("# host | service | action\n\n")
            f.write("# P1 - CRITICAL\n")
            for e in sorted(set(p1_entries)):
                f.write(f"{e}\n")
            f.write("\n# P2 - HIGH\n")
            for e in sorted(set(p2_entries)):
                f.write(f"{e}\n")
        
        # Critical findings summary
        for vuln_file in [self.d_vulns / "nuclei_web.txt", self.d_vulns / "nuclei_network.txt"]:
            if vuln_file.exists():
                for line in read_lines(vuln_file):
                    if "[critical]" in line.lower() or "[high]" in line.lower():
                        CONFIG.logger.finding("HIGH", line[:120])
        
        CONFIG.logger.info("Network scanning complete")
    
    # ================================================================
    # PHASE 4: TECHNOLOGY DETECTION
    # ================================================================
    
    def _phase4(self) -> None:
        if not self.f_httpx_urls.exists() or self.f_httpx_urls.stat().st_size == 0:
            CONFIG.logger.warn("No live hosts — skipping tech detection")
            return
        
        CONFIG.logger.info("Tech fingerprinting...")
        json_out = self.d_tech / "full_stack.json"
        
        # Reuse Phase 3's JSON output if available, otherwise run httpx
        phase3_json = self.d_net / "httpx_web.json"
        if phase3_json.exists() and phase3_json.stat().st_size > 0:
            CONFIG.logger.info("Reusing Phase 3 httpx JSON for tech detection")
            import shutil as _shutil
            _shutil.copy2(str(phase3_json), str(json_out))
        else:
            run_tool("httpx", [
                "httpx", "-l", str(self.f_httpx_urls),
                "-threads", str(self.cfg["threads"]),
                "-rate-limit", str(self.cfg["rate_limit"]),
                "-title", "-web-server", "-status-code",
                "-tech-detect", "-cdn", "-ip", "-cname",
                "-follow-redirects", "-random-agent",
                "-json", "-silent",
                "-o", str(json_out)
            ])
        
        if not json_out.exists():
            CONFIG.logger.warn("No tech data collected")
            return
        
        # Parse JSON output
        full_txt = self.d_tech / "full_stack.txt"
        cms_file = self.d_tech / "cms.txt"
        frameworks_file = self.d_tech / "frameworks.txt"
        js_frameworks = self.d_tech / "js_frameworks.txt"
        cloud_file = self.d_tech / "cloud_cdn_waf.txt"
        servers_file = self.d_tech / "servers.txt"
        
        tech_lines = []
        cms_lines = []
        framework_lines = []
        js_lines = []
        cloud_lines = []
        server_lines = []
        all_techs: set[str] = set()
        
        try:
            with open(json_out) as f:
                for line in f:
                    try:
                        data = json.loads(line.strip())
                    except json.JSONDecodeError:
                        continue
                    
                    url = data.get("url", "")
                    status = data.get("status_code", "")
                    server = data.get("webserver", "")
                    cdn = data.get("cdn", "")
                    techs = data.get("tech", []) or []
                    
                    line_txt = f"{url} | Status: {status} | Server: {server} | CDN: {cdn} | Tech: [{', '.join(techs)}]"
                    tech_lines.append(line_txt)
                    all_techs.update(techs)
                    
                    techs_lower = " ".join(techs).lower()
                    if any(t in techs_lower for t in ["wordpress","joomla","drupal","ghost","shopify","magento"]):
                        cms_lines.append(line_txt)
                    if any(t in techs_lower for t in ["laravel","django","flask","spring","asp.net","express","rails","symfony","next.js","nuxt.js"]):
                        framework_lines.append(line_txt)
                    if any(t in techs_lower for t in ["react","vue.js","angular","svelte","alpine.js"]):
                        js_lines.append(line_txt)
                    if any(t in techs_lower for t in ["cloudflare","akamai","fastly","imperva","aws","azure","gcp","vercel","netlify"]):
                        cloud_lines.append(line_txt)
                    if any(t in techs_lower for t in ["nginx","apache","iis","caddy","lighttpd"]):
                        server_lines.append(line_txt)
        except Exception as e:
            CONFIG.logger.warn(f"Error parsing tech JSON: {e}")
        
        write_lines(full_txt, tech_lines)
        write_lines(cms_file, cms_lines)
        write_lines(frameworks_file, framework_lines)
        write_lines(js_frameworks, js_lines)
        write_lines(cloud_file, cloud_lines)
        write_lines(servers_file, server_lines)
        write_lines(self.d_tech / "unique_technologies.txt", all_techs)
        
        CONFIG.logger.info(f"Hosts analyzed: {len(tech_lines)}")
        CONFIG.logger.info(f"Unique technologies: {len(all_techs)}")
    
    # ================================================================
    # PHASE 5: URL COLLECTION
    # ================================================================
    
    def _phase5(self) -> None:
        if not self.f_httpx_web.exists() or self.f_httpx_web.stat().st_size == 0:
            if self.f_httpx_urls.exists() and self.f_httpx_urls.stat().st_size > 0:
                input_file = self.f_httpx_urls
                CONFIG.logger.info("No httpx_web — falling back to httpx.txt")
            else:
                CONFIG.logger.warn("No live web hosts — skipping URL collection")
                return
        else:
            input_file = self.f_httpx_web
        
        input_urls = read_lines(input_file)
        crawl_urls = [line.split()[0] if line.strip() else "" for line in input_urls if line.strip()]
        write_lines(self.d_live / "crawl_urls.txt", crawl_urls)
        
        # Extract domains
        domains = set()
        for url in crawl_urls:
            parsed = urlparse(url)
            host = parsed.hostname or url.replace("https://","").replace("http://","").split("/")[0].split(":")[0]
            domains.add(host)
        write_lines(self.d_content / "domains.txt", domains)
        
        # Stage 1: crawlers in parallel
        CONFIG.logger.info("Stage 1: crawling (katana, hakrawler, gauplus, waybackurls, subjs)...")
        
        katana_file = self.d_content / "katana.txt"
        hakrawler_file = self.d_content / "hakrawler.txt"
        gaup_file = self.d_content / "gaup.txt"
        wayback_file = self.d_content / "wayback.txt"
        subjs_file = self.d_content / "subjs.txt"
        crawl_list = self.d_live / "crawl_urls.txt"
        
        def run_katana():
            if tool_available("katana"):
                run_tool("katana", [
                    "katana", "-silent",
                    "-list", str(crawl_list),
                    "-d", str(self.cfg["katana_depth"]),
                    "-rl", str(self.cfg["rate_limit"]),
                    "-ef", "png,jpg,jpeg,gif,svg,woff,woff2,css,ico",
                    "-o", str(katana_file)
                ])
        
        def run_hakrawler():
            if tool_available("hakrawler"):
                try:
                    with open(crawl_list) as f:
                        content = f.read()
                    result = subprocess.run(
                        ["hakrawler", "-subs", "-insecure", "-plain"],
                        input=content, capture_output=True, text=True, timeout=300
                    )
                    if result.stdout:
                        write_lines(hakrawler_file, result.stdout.strip().split("\n"))
                except subprocess.TimeoutExpired:
                    CONFIG.logger.debug("hakrawler timed out")
                except Exception as e:
                    CONFIG.logger.debug(f"hakrawler failed: {type(e).__name__}")
        
        def run_gauplus():
            if tool_available("gauplus"):
                try:
                    with open(self.d_content / "domains.txt") as f:
                        content = f.read()
                    result = subprocess.run(
                        ["gauplus"],
                        input=content, capture_output=True, text=True, timeout=300
                    )
                    if result.stdout:
                        write_lines(gaup_file, result.stdout.strip().split("\n"))
                except subprocess.TimeoutExpired:
                    CONFIG.logger.debug("gauplus timed out")
                except Exception as e:
                    CONFIG.logger.debug(f"gauplus failed: {type(e).__name__}")
        
        def run_wayback():
            if tool_available("waybackurls"):
                try:
                    with open(self.d_content / "domains.txt") as f:
                        content = f.read()
                    result = subprocess.run(
                        ["waybackurls"],
                        input=content, capture_output=True, text=True, timeout=300
                    )
                    if result.stdout:
                        write_lines(wayback_file, result.stdout.strip().split("\n"))
                except subprocess.TimeoutExpired:
                    CONFIG.logger.debug("waybackurls timed out")
                except Exception as e:
                    CONFIG.logger.debug(f"waybackurls failed: {type(e).__name__}")
        
        def run_subjs():
            if tool_available("subjs"):
                try:
                    result = subprocess.run(
                        ["subjs", "-i", str(crawl_list)],
                        capture_output=True, text=True, timeout=300
                    )
                    if result.stdout:
                        write_lines(subjs_file, result.stdout.strip().split("\n"))
                except subprocess.TimeoutExpired:
                    CONFIG.logger.debug("subjs timed out")
                except Exception as e:
                    CONFIG.logger.debug(f"subjs failed: {type(e).__name__}")
        
        with ThreadPoolExecutor(max_workers=5) as pool:
            fs = [
                pool.submit(run_katana),
                pool.submit(run_hakrawler),
                pool.submit(run_gauplus),
                pool.submit(run_wayback),
                pool.submit(run_subjs),
            ]
            wait(fs)
        
        # Stage 2: JS processing from subjs output
        priority_file = self.d_content / "priority_urls.txt"
        js_endpoints_file = self.d_content / "js_endpoints.txt"
        
        if subjs_file.exists():
            subjs_urls = read_lines(subjs_file)
            full_urls = set()
            for line in subjs_urls:
                for m in re.finditer(r'https?://[a-zA-Z0-9./?=_&-]+', line):
                    full_urls.add(m.group(0))
            # Append all subjs URLs at once instead of one-by-one
            existing = read_lines(katana_file)
            write_lines(katana_file, existing + list(full_urls))
            
            # Extract API-like endpoints
            api_eps = set()
            for line in subjs_urls:
                for m in re.finditer(r'/(?:api|v\d+|graphql|rest|auth|user|admin)[a-zA-Z0-9./?=_&-]*', line):
                    api_eps.add(m.group(0))
            write_lines(js_endpoints_file, api_eps)
            
            # Build priority URLs from endpoints + base URLs
            if js_endpoints_file.exists() and crawl_list.exists():
                bases = read_lines(crawl_list)
                eps = read_lines(js_endpoints_file)
                prio_urls = []
                for base in bases:
                    base = base.rstrip("/")
                    for ep in eps:
                        prio_urls.append(f"{base}{ep}")
                existing = read_lines(priority_file)
                write_lines(priority_file, existing + prio_urls)
        
        # Stage 3: normalize
        CONFIG.logger.info("Stage 3: Normalizing...")
        raw_urls = self.d_content / "all_urls_raw.txt"
        all_urls = self.d_content / "all_urls.txt"
        
        all_url_set = set()
        for src in [katana_file, hakrawler_file, gaup_file, wayback_file]:
            if src.exists():
                for line in read_lines(src):
                    # Filter mailto:, javascript:, static assets
                    if re.match(r'^(mailto|javascript):', line):
                        continue
                    if re.search(r'\.(png|jpg|jpeg|gif|svg|woff2?|css|ico)(\?.*)?$', line, re.I):
                        continue
                    # Remove fragments
                    line = line.split("#")[0]
                    if line:
                        all_url_set.add(line)
        
        write_lines(raw_urls, all_url_set)
        
        # Dedup with uro if available
        if tool_available("uro"):
            result = subprocess.run(
                ["uro"],
                input="\n".join(all_url_set),
                capture_output=True, text=True, timeout=600
            )
            if result.stdout:
                write_lines(all_urls, result.stdout.strip().split("\n"))
            else:
                write_lines(all_urls, all_url_set)
        else:
            write_lines(all_urls, all_url_set)
        
        total_urls = safe_count(all_urls)
        CONFIG.logger.info(f"Total URLs: {total_urls}")
        
        # Stage 4: prioritize
        priority_urls = set()
        for line in read_lines(all_urls):
            if re.search(r'(\.php|\.asp|\.aspx|\.jsp|\.json)(\?|$)|/(?:api|admin|login|dashboard|upload|config|backup|auth|user|account)(?:/|$|\?)', line, re.I):
                priority_urls.add(line)
        for url in priority_urls:
            append_line(priority_file, url)
        
        # Merge priority + all (priority first, deduped)
        final_urls = self.d_content / "final_urls.txt"
        seen = set()
        with open(final_urls, "w") as f:
            for src in [priority_file, all_urls]:
                if src.exists():
                    for line in read_lines(src):
                        if line not in seen:
                            f.write(line + "\n")
                            seen.add(line)
        
        CONFIG.logger.info(f"Priority: {len(priority_urls)} | Total: {len(seen)}")
        
        # Stage 5: httpx validation
        if final_urls.stat().st_size == 0 or not tool_available("httpx"):
            return
        
        total = safe_count(final_urls)
        CONFIG.logger.info(f"Stage 5: httpx ({total} URLs)...")
        
        live_status_file = self.d_content / "live_urls_with_status.txt"
        
        def run_httpx_check(input_path: Path, output_path: Path):
            run_tool("httpx", [
                "httpx", "-silent",
                "-threads", str(self.cfg["threads"]),
                "-rate-limit", str(self.cfg["rate_limit"]),
                "-l", str(input_path),
                "-mc", "200,204,301,302,401,403,405",
                "-status-code", "-title", "-content-length",
                "-tech-detect", "-no-color",
                "-follow-redirects", "-random-agent",
                "-o", str(output_path)
            ])
        
        if total > 50000:
            # Chunk it
            CONFIG.logger.info("Large set — chunking...")
            lines = read_lines(final_urls)
            chunk_size = 5000
            chunks = [lines[i:i+chunk_size] for i in range(0, len(lines), chunk_size)]
            
            with ThreadPoolExecutor(max_workers=5) as pool:
                futures = []
                for i, chunk in enumerate(chunks):
                    chunk_file = self.d_content / f"chunk_{i:04d}.txt"
                    write_lines(chunk_file, chunk)
                    out_file = self.d_content / f"chunk_{i:04d}.out"
                    futures.append(pool.submit(run_httpx_check, chunk_file, out_file))
                wait(futures)
            
            # Merge chunks
            all_live = []
            for i in range(len(chunks)):
                out_file = self.d_content / f"chunk_{i:04d}.out"
                if out_file.exists():
                    all_live.extend(read_lines(out_file))
                for chunk_path in [self.d_content / f"chunk_{i:04d}.txt", out_file]:
                    chunk_path.unlink(missing_ok=True)
            write_lines(live_status_file, all_live)
        else:
            run_httpx_check(final_urls, live_status_file)
        
        # Parse results - httpx output format: "url [status] [content-length] [title] [tech...]"
        live_urls = []
        live_200 = []
        protected_urls = []
        small_urls = []
        tech_identified = []
        
        # Regex: url [status] [content-length] ... 
        # Status and content-length are in brackets, but tech fields can have brackets too
        status_re = re.compile(r"\[(\d+)\]")
        
        if live_status_file.exists():
            for line in read_lines(live_status_file):
                parts = line.split()
                if not parts:
                    continue
                url = parts[0]
                live_urls.append(url)
                
                # Find all bracketed numbers - first is status, second is content-length
                brackets = status_re.findall(line)
                if len(brackets) >= 1:
                    status = brackets[0]
                    if status == "200":
                        live_200.append(url)
                    if status in ("401", "403"):
                        protected_urls.append(url)
                    if len(brackets) >= 2:
                        content_len = brackets[1]
                        if content_len.isdigit() and 0 < int(content_len) < 1000:
                            small_urls.append(url)
                
                if any(t in line.lower() for t in ["php","laravel","django","wordpress","drupal","nginx","apache"]):
                    tech_identified.append(url)
        
        write_lines(self.f_live_urls, list(dict.fromkeys(live_urls)))
        write_lines(self.f_live_urls_200, list(dict.fromkeys(live_200)))
        write_lines(self.d_content / "protected_urls.txt", list(dict.fromkeys(protected_urls)))
        write_lines(self.d_content / "small_response_urls.txt", list(dict.fromkeys(small_urls)))
        write_lines(self.d_content / "tech_identified_urls.txt", list(dict.fromkeys(tech_identified)))
        
        CONFIG.logger.info(f"Live: {len(live_urls)} | 200: {len(live_200)} | Protected: {len(protected_urls)}")
    
    # ================================================================
    # PHASE 6: PARAMETER ANALYSIS
    # ================================================================
    
    def _phase6(self) -> None:
        p_dir = self.d_params
        
        # Step 1: extract params from URLs
        if self.f_live_urls.exists():
            params = set()
            for line in read_lines(self.f_live_urls):
                for m in re.finditer(r'[?&]([a-zA-Z0-9_.\[\]-]{1,50})=', line):
                    params.add(m.group(1))
            write_lines(p_dir / "from_urls.txt", params)
            CONFIG.logger.info(f"Params from URLs: {len(params)}")
        
        # Step 2: extract params from JS
        js_beautified = self.d_js / "beautified"
        if js_beautified.exists() and tool_available("xnLinkFinder"):
            js_params = set()
            for js_file in js_beautified.iterdir():
                if js_file.is_file() and js_file.stat().st_size > 0:
                    result = subprocess.run(
                        ["xnLinkFinder", "-i", str(js_file), "-o", "cli"],
                        capture_output=True, text=True, timeout=60
                    )
                    for m in re.finditer(r'[?&]([a-zA-Z0-9_.\[\]-]{1,50})=', result.stdout):
                        js_params.add(m.group(1))
            write_lines(p_dir / "from_js.txt", js_params)
        
        # Step 3: Arjun
        if tool_available("arjun") and self.f_live_urls_200.exists():
            arjun_targets = read_lines(self.f_live_urls_200)[:50]
            if arjun_targets:
                arjun_input = p_dir / "arjun_targets.txt"
                write_lines(arjun_input, arjun_targets)
                run_tool("arjun", [
                    "arjun", "-i", str(arjun_input),
                    "-oT", str(p_dir / "from_arjun.txt")
                ])
        
        # Step 4: merge all params
        all_params = set()
        for fname in ["from_urls.txt", "from_js.txt", "from_arjun.txt"]:
            fp = p_dir / fname
            if fp.exists():
                for line in read_lines(fp):
                    all_params.add(line)
        
        if not all_params:
            CONFIG.logger.warn("No parameters found")
            return
        
        write_lines(p_dir / "all.txt", all_params)
        CONFIG.logger.info(f"Unique params: {len(all_params)}")
        
        # Step 5: build param URLs (capped at 50 params)
        base_urls = []
        for line in read_lines(self.f_live_urls):
            if "?" in line:
                base = line.split("?")[0]
                base_urls.append(base)
        base_urls = list(dict.fromkeys(base_urls))[:100]
        
        if not base_urls:
            base_urls = read_lines(self.f_live_urls)[:100]
        
        write_lines(p_dir / "base_urls.txt", base_urls)
        
        # Build param URLs
        param_urls = []
        for param in list(all_params)[:50]:
            for base in base_urls:
                param_urls.append(f"{base}?{param}=test")
        write_lines(p_dir / "param_urls.txt", param_urls)
        
        CONFIG.logger.info(f"Param URLs built: {safe_count(p_dir / 'param_urls.txt')}")
        
        # Step 6: httpx validation
        if p_dir / "param_urls.txt" and tool_available("httpx"):
            run_tool("httpx", [
                "httpx", "-silent",
                "-threads", str(self.cfg["threads"]),
                "-rate-limit", str(self.cfg["rate_limit"]),
                "-l", str(p_dir / "param_urls.txt"),
                "-mc", "200,204,301,302,401,403,405",
                "-status-code", "-content-length", "-title",
                "-no-color",
                "-o", str(p_dir / "httpx_status.txt")
            ])
            
            live_param_urls = []
            interesting = []
            if (p_dir / "httpx_status.txt").exists():
                for line in read_lines(p_dir / "httpx_status.txt"):
                    parts = line.split()
                    if parts:
                        live_param_urls.append(parts[0])
                        # Check content length (3rd field with brackets)
                        for p in parts[1:]:
                            if p.startswith("[") and p.endswith("]") and p.strip("[]").isdigit():
                                clen = int(p.strip("[]"))
                                if 0 < clen < 2000:
                                    interesting.append(parts[0])
                                break
            
            write_lines(p_dir / "all_live.txt", list(dict.fromkeys(live_param_urls)))
            write_lines(p_dir / "interesting.txt", list(dict.fromkeys(interesting)))
            
            # Step 7: qsreplace
            if live_param_urls and tool_available("qsreplace"):
                result = subprocess.run(
                    ["qsreplace", "FUZZ"],
                    input="\n".join(live_param_urls),
                    capture_output=True, text=True, timeout=600
                )
                if result.stdout:
                    fuzz_urls = list(dict.fromkeys(result.stdout.strip().split("\n")))
                    write_lines(p_dir / "fuzz_ready.txt", fuzz_urls)
                    CONFIG.logger.info(f"Fuzz-ready URLs: {len(fuzz_urls)}")
            
            CONFIG.logger.info(f"Live param URLs: {len(live_param_urls)}")
            CONFIG.logger.info(f"Interesting: {len(interesting)}")
        
        # Step 8: GF pattern matching — parallel
        if tool_available("gf") and (p_dir / "all_live.txt").exists():
            gf_dir = p_dir / "gf_patterns"
            gf_dir.mkdir(exist_ok=True)
            patterns = ["xss", "sqli", "ssrf", "ssti", "lfi", "redirect", "rce", "idor", "api"]
            
            def run_gf_pattern(pattern):
                try:
                    result = subprocess.run(
                        ["gf", pattern, str(p_dir / "all_live.txt")],
                        capture_output=True, text=True, timeout=600
                    )
                    if result.stdout:
                        lines = list(dict.fromkeys(result.stdout.strip().split("\n")))
                        write_lines(gf_dir / f"{pattern}.txt", lines)
                        return pattern, len(lines)
                except subprocess.TimeoutExpired:
                    CONFIG.logger.debug(f"GF pattern '{pattern}' timed out")
                except Exception as e:
                    CONFIG.logger.debug(f"GF pattern '{pattern}' failed: {type(e).__name__}")
                return pattern, 0
            
            with ThreadPoolExecutor(max_workers=4) as pool:
                for pattern, count in pool.map(run_gf_pattern, patterns):
                    if count > 0:
                        CONFIG.logger.info(f"GF [{pattern}]: {count}")
    
    # ================================================================
    # PHASE 7: JAVASCRIPT & SECRETS ANALYSIS
    # ================================================================
    
    def _phase7(self) -> None:
        js_dir = self.d_js
        
        # Init output files
        for fname in ["js_urls.txt", "js_endpoints.txt", "js_params.txt",
                       "js_headers.txt", "js_requests.txt", "js_secrets.txt",
                       "auth_related.txt"]:
            (js_dir / fname).write_text("")
        
        # Step 1: collect JS URLs
        if self.f_httpx_web.exists() and tool_available("subjs"):
            run_tool("subjs", [
                "subjs", "-i", str(self.f_httpx_web)
            ], stdout_path=js_dir / "js_urls.txt")
        
        # Also scan from all_urls
        all_urls_file = self.d_content / "all_urls.txt"
        if all_urls_file.exists():
            js_urls = set()
            for line in read_lines(all_urls_file):
                if re.search(r'\.js(\?|$)', line):
                    js_urls.add(line)
            for u in js_urls:
                append_line(js_dir / "js_urls.txt", u)
        
        # Dedup
        all_js = list(dict.fromkeys(read_lines(js_dir / "js_urls.txt")))
        if not all_js:
            CONFIG.logger.warn("No JS URLs found")
            return
        write_lines(js_dir / "js_urls.txt", all_js)
        CONFIG.logger.info(f"JS URLs: {len(all_js)}")
        
        # Step 2: score by URL keywords, pick top 60
        def score_js_url(url: str) -> int:
            lower = url.lower()
            score = 0
            if re.search(r"auth|api|config|client|service|token|key|secret", lower):
                score += 30
            if re.search(r"react|vue|angular|vendor|chunk|runtime|analytics|gtm", lower):
                score -= 20
            return score
        
        scored = [(score_js_url(u), u) for u in all_js]
        scored.sort(key=lambda x: -x[0])
        download_list = [u for _, u in scored][:60]
        write_lines(js_dir / "js_download_list.txt", download_list)
        CONFIG.logger.info(f"Selected JS: {len(download_list)}")
        
        # Step 3: download + beautify
        raw_dir = js_dir / "raw"
        beautified_dir = js_dir / "beautified"
        raw_dir.mkdir(exist_ok=True)
        beautified_dir.mkdir(exist_ok=True)
        
        url_file_map = js_dir / "js_url_file_map.txt"
        
        try:
            import requests
            HAS_REQUESTS = True
        except ImportError:
            HAS_REQUESTS = False
        
        def download_and_beautify(args):
            i, url = args
            fname = f"{i+1}_{re.sub(r'[^a-zA-Z0-9.]', '_', url.replace('https://','').replace('http://',''))}.js"
            raw_path = raw_dir / fname
            beautified_path = beautified_dir / fname
            
            success = False
            if HAS_REQUESTS:
                try:
                    resp = requests.get(url, timeout=15, allow_redirects=True, headers={"User-Agent": "ReconX/2.0"})
                    if resp.status_code == 200 and resp.content:
                        raw_path.write_bytes(resp.content)
                        success = True
                except Exception as e:
                    CONFIG.logger.debug(f"Download failed {url[:60]}: {type(e).__name__}")
            
            if not success:
                try:
                    subprocess.run(
                        ["curl", "-sL", "--fail", "--max-time", "15", "--connect-timeout", "5",
                         url, "-o", str(raw_path)],
                        capture_output=True, timeout=60
                    )
                    if raw_path.exists() and raw_path.stat().st_size > 0:
                        success = True
                except Exception as e:
                    CONFIG.logger.debug(f"Curl failed {url[:60]}: {type(e).__name__}")
            
            if not success or not raw_path.exists() or raw_path.stat().st_size == 0:
                return None
            
            if tool_available("js-beautify"):
                try:
                    subprocess.run(
                        ["js-beautify", str(raw_path)],
                        stdout=open(beautified_path, "w"),
                        stderr=subprocess.DEVNULL, timeout=60
                    )
                except Exception:
                    shutil.copy(str(raw_path), str(beautified_path))
            else:
                shutil.copy(str(raw_path), str(beautified_path))
            
            return f"{url}|{beautified_path}"
        
        with ThreadPoolExecutor(max_workers=10) as pool:
            results = list(pool.map(download_and_beautify, enumerate(download_list)))
        
        url_map_entries = [r for r in results if r is not None]
        write_lines(url_file_map, url_map_entries)
        CONFIG.logger.info(f"Downloaded: {len(url_map_entries)}")
        
        # Step 4: extraction — accumulate in lists, write once
        if not url_file_map.exists():
            return
        
        all_endpoints = []
        all_params = []
        all_headers = []
        all_requests = []
        all_auth = []
        
        for line in read_lines(url_file_map):
            if "|" not in line:
                continue
            url, filepath = line.split("|", 1)
            fp = Path(filepath)
            if not fp.exists():
                continue
            
            base = re.sub(r'(https?://[^/]+).*', r'\1', url)
            
            try:
                content = fp.read_text(errors="ignore")
            except Exception:
                continue
            
            for m in re.finditer(r'https?://[a-zA-Z0-9./?=_&%-]+|/[a-zA-Z0-9_/.-]{3,}', content):
                ep = m.group(0)
                if re.search(r'\.(css|png|jpg|jpeg|svg|gif|woff2?|ttf|ico|map)(\?|$)', ep, re.I):
                    continue
                if re.search(r'(vendor|bundle|chunk|runtime|polyfill|webpack)[.\[]', ep, re.I):
                    continue
                if re.search(r'/[a-f0-9]{8,}\.', ep, re.I):
                    continue
                all_endpoints.append(ep if ep.startswith("http") else f"{base}{ep}")
            
            for m in re.finditer(r'[?&]([a-zA-Z0-9_.\[\]-]{1,50})=', content):
                all_params.append(m.group(1))
            
            for m in re.finditer(r'Authorization\s*:\s*["\'][^"\']+|Bearer\s+[a-zA-Z0-9._-]{10,}|x-[a-zA-Z0-9-]+\s*:\s*["\'][^"\']+', content, re.I):
                all_headers.append(m.group(0))
            
            for m in re.finditer(r'(?:fetch|axios)\([^)]{20,300}\)', content):
                all_requests.append(m.group(0))
            
            if re.search(r"auth|token|authorization", content, re.I):
                all_auth.append(url)
        
        write_lines(js_dir / "js_endpoints.txt", list(dict.fromkeys(all_endpoints)))
        write_lines(js_dir / "js_params.txt", list(dict.fromkeys(all_params)))
        write_lines(js_dir / "js_headers.txt", list(dict.fromkeys(all_headers)))
        write_lines(js_dir / "js_requests.txt", list(dict.fromkeys(all_requests)))
        write_lines(js_dir / "auth_related.txt", list(dict.fromkeys(all_auth)))
        
        # Step 5: secrets — accumulate, write once
        secrets_pattern = re.compile(
            r'(AKIA[A-Z0-9]{16}|'
            r'ghp_[a-zA-Z0-9]{36}|'
            r'sk_live_[a-zA-Z0-9]{32,}|'
            r'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+|'
            r'AIza[0-9A-Za-z_-]{35}|'
            r'gho_[a-zA-Z0-9]{36}|'
            r'xox[baprs]-[0-9]{10,13}|'
            r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----)'
        )
        
        all_secrets = []
        for beautified in beautified_dir.iterdir():
            if beautified.is_file() and beautified.stat().st_size > 0:
                try:
                    content = beautified.read_text(errors="ignore")
                    for m in secrets_pattern.finditer(content):
                        all_secrets.append(m.group(0))
                except Exception:
                    continue
        
        # Write deduped secrets
        secrets = list(dict.fromkeys(all_secrets))
        write_lines(js_dir / "js_secrets.txt", secrets)
        
        # Summary
        CONFIG.logger.info(f"Endpoints: {safe_count(js_dir / 'js_endpoints.txt')}")
        CONFIG.logger.info(f"Params:    {safe_count(js_dir / 'js_params.txt')}")
        CONFIG.logger.info(f"Requests:  {safe_count(js_dir / 'js_requests.txt')}")
        CONFIG.logger.info(f"Headers:   {safe_count(js_dir / 'js_headers.txt')}")
        CONFIG.logger.info(f"Secrets:   {safe_count(js_dir / 'js_secrets.txt')}")
        if secrets:
            CONFIG.logger.finding("HIGH", f"{len(secrets)} potential secrets found — check {js_dir / 'js_secrets.txt'}")
    
    # ================================================================
    # PHASE 8: VULNERABILITY SCANNING
    # ================================================================
    
    def _phase8(self) -> None:
        vulns_dir = self.d_vulns
        targets_file = vulns_dir / "targets.txt"
        
        # Collect targets
        targets = []
        if self.f_live_urls.exists():
            for line in read_lines(self.f_live_urls):
                if line.startswith("http"):
                    targets.append(line)
        targets = list(dict.fromkeys(targets))
        
        if not targets:
            CONFIG.logger.warn("No live URLs — skipping vuln scan")
            return
        
        write_lines(targets_file, targets)
        CONFIG.logger.info(f"Vulnerability scanning: {len(targets)} targets")
        
        if not tool_available("nuclei"):
            CONFIG.logger.warn("nuclei not installed — skipping")
            return
        
        # Tech-aware (high + critical)
        CONFIG.logger.info("Running Nuclei (high + critical)...")
        run_tool("nuclei", [
            "nuclei", "-l", str(targets_file),
            "-as",
            "-severity", "high,critical",
            "-c", str(self.cfg["threads"]),
            "-rl", str(self.cfg["rate_limit"]),
            "-silent", "-timeout", "8",
            "-o", str(vulns_dir / "high_critical.txt")
        ])
        
        # CVEs only (critical)
        CONFIG.logger.info("Running Nuclei (critical CVEs)...")
        cve_dir = None
        templates_root = find_nuclei_templates_dir()
        if templates_root:
            cve_dir = templates_root / "http" / "cves"
        if cve_dir is not None and cve_dir.exists():
            run_tool("nuclei", [
                "nuclei", "-l", str(targets_file),
                "-t", str(cve_dir),
                "-severity", "critical",
                "-c", str(self.cfg["threads"]),
                "-rl", str(self.cfg["rate_limit"]),
                "-silent", "-timeout", "8",
                "-o", str(vulns_dir / "cves_critical.txt")
            ])
        
        # Merge
        all_findings = set()
        for fname in ["high_critical.txt", "cves_critical.txt"]:
            fp = vulns_dir / fname
            if fp.exists():
                for line in read_lines(fp):
                    all_findings.add(line)
        write_lines(vulns_dir / "all.txt", all_findings)
        
        # Report critical findings
        for finding in all_findings:
            if "critical" in finding.lower():
                CONFIG.logger.finding("CRITICAL", finding[:150])
            elif "high" in finding.lower():
                CONFIG.logger.finding("HIGH", finding[:150])
        
        CONFIG.logger.info(f"High/Critical findings: {len(all_findings)}")
    
    # ================================================================
    # REPORT
    # ================================================================
    
    def _report(self) -> None:
        CONFIG.logger.info("Generating final report...")
        
        total_subdomains = safe_count(self.f_final_subdomains)
        total_live = safe_count(self.f_httpx_urls)
        total_ports = safe_count(self.d_net / "open_tcp.txt")
        total_tech = safe_count(self.d_tech / "full_stack.txt")
        total_urls = safe_count(self.f_live_urls)
        total_urls_200 = safe_count(self.f_live_urls_200)
        total_params = safe_count(self.d_params / "all_live.txt")
        total_js = safe_count(self.d_js / "js_urls.txt")
        
        report_md = f"""# Reconnaissance Report
## Target: {self.domain}
## Mode: {self.mode}
## Date: {datetime.now().isoformat()}

## Statistics
- Subdomains          : {total_subdomains}
- Live Hosts          : {total_live}
- Open Ports (TCP)    : {total_ports}
- Technologies        : {total_tech}
- URLs (all status)   : {total_urls}
- URLs (200 only)     : {total_urls_200}
- Parameters (live)   : {total_params}
- JavaScript Files    : {total_js}

## Files Generated
```
$(find . -type f \\( -name "*.txt" -o -name "*.md" -o -name "*.json" \\) | sort | head -50)
```
"""
        (self.out / "REPORT.md").write_text(report_md)
        
        summary_txt = f"""TARGET : {self.domain}
MODE   : {self.mode}
TIME   : {datetime.now().isoformat()}

STATISTICS:
  Subdomains          : {total_subdomains}
  Live Hosts          : {total_live}
  Open Ports (TCP)    : {total_ports}
  Technologies        : {total_tech}
  URLs (all status)   : {total_urls}
  URLs (200 only)     : {total_urls_200}
  Parameters (live)   : {total_params}
  JS Files            : {total_js}

NEXT STEPS:
  1. Review vulnerabilities/high_critical.txt
  2. Check javascript/js_secrets.txt
  3. Review network/manual_targets.txt
"""
        (self.out / "SUMMARY.txt").write_text(summary_txt)
    
    # ================================================================
    # RUN ALL
    # ================================================================
    
    def run(self) -> None:
        start = time.time()
        
        phases = [
            (1, "Subdomain Enumeration",  self._phase1),
            (2, "Live Host Detection",    self._phase2),
            (3, "Network Scanning",       self._phase3),
            (4, "Technology Detection",   self._phase4),
            (5, "URL Collection",         self._phase5),
            (6, "Parameter Analysis & Takeover", self._phase6),
            (7, "JS & Secrets Analysis",  self._phase7),
            (8, "Vulnerability Scanning", self._phase8),
        ]
        
        for num, name, func in phases:
            self.runner.run(num, name, func)
        
        self._report()
        
        elapsed = time.time() - start
        mins = int(elapsed // 60)
        secs = int(elapsed % 60)
        
        print("")
        CONFIG.logger.log(f"{'='*20}")
        CONFIG.logger.log(f"\033[1;32mPipeline completed in {mins}m {secs}s\033[0m")
        CONFIG.logger.log(f"Output: {self.out.resolve()}")
        CONFIG.logger.log(f"Summary: cat {self.out / 'SUMMARY.txt'}")
        
        # Final findings summary
        vulns_all = self.d_vuln_all / "all.txt"
        if vulns_all.exists():
            c_count = sum(1 for line in read_lines(vulns_all) if "critical" in line.lower())
            CONFIG.logger.log(f"Nuclei critical findings: {c_count}")
        
        secrets = self.d_js / "js_secrets.txt"
        if secrets.exists():
            CONFIG.logger.log(f"Potential secrets: {safe_count(secrets)}")


# =============================================================================
# DOCTOR / CHECK TOOLS
# =============================================================================


def cmd_check():
    """--check mode: list all tools and their installation status."""
    if HAS_RICH:
        return _cmd_check_rich()
    return _cmd_check_fallback()


def _cmd_check_rich():
    console = Console()
    installed = 0
    not_installed = 0

    table = Table(
        title="[bold]Recon Tool Check[/bold]",
        title_justify="left",
        box=box.HEAVY_EDGE,
    )
    table.add_column("Tool", style="bold cyan", no_wrap=True)
    table.add_column("Version", style="green")
    table.add_column("Status")

    for tool in TOOL_REGISTRY:
        if which(tool.name):
            version = get_tool_version(tool)
            ver = version[:40] if version != "-" else "-"
            status = "[green]\u2713 installed[/green]"
            installed += 1
        else:
            ver = "-"
            status = "[red]\u2717 not found[/red]"
            not_installed += 1
        table.add_row(tool.name, ver, status)

    console.print()
    console.print(table)
    console.print()
    console.print(f"[bold white]{installed} installed[/bold white]  \u2502  [yellow]{not_installed} not found[/yellow]")

    if not_installed:
        console.print("\n[yellow]Missing tools will be skipped during execution.[/yellow]")
        missing_core = sum(1 for t in TOOL_REGISTRY if t.required and not which(t.name))
        if missing_core:
            console.print("[yellow]Core tools are required for the pipeline to run.[/yellow]")

    return 1 if not_installed > 0 and not_installed == len([t for t in TOOL_REGISTRY if t.required]) else 0


def _cmd_check_fallback():
    print("")
    print("  Recon Tool Check")
    print("")

    tw, vw, sw = 16, 42, 14
    sep, hc = " | ", "-"

    def pborder(a, b, c, d):
        print(a + hc * (tw + 2) + b + hc * (vw + 2) + b + hc * (sw + 2) + d)

    pborder("+", "+", "+", "+")
    print(f"| {'Tool':<{tw}}{sep}{'Version':<{vw}}{sep}{'Status':<{sw}} |")
    pborder("+", "+", "+", "+")

    installed = 0
    not_installed = 0

    for tool in TOOL_REGISTRY:
        if which(tool.name):
            version = get_tool_version(tool)
            ver = version[:40] if version != "-" else "-"
            status = "OK"
            installed += 1
            print(f"| {tool.name:<{tw}}{sep}{ver:<{vw}}{sep}\033[1;32m{status:<{sw}}\033[0m |")
        else:
            ver = "-"
            print(f"| {tool.name:<{tw}}{sep}{ver:<{vw}}{sep}\033[1;31m{'MISSING':<{sw}}\033[0m |")
            not_installed += 1

    pborder("+", "+", "+", "+")
    print(f"  \033[1;37m{installed} installed\033[0m  |  \033[1;33m{not_installed} not found\033[0m")
    print("")

    if not_installed > 0:
        print("  \033[1;33mMissing tools will be skipped during execution.\033[0m")
        print("  \033[1;33mCore tools are required for the pipeline to run.\033[0m")

    return 1 if not_installed > 0 and not_installed == len([t for t in TOOL_REGISTRY if t.required]) else 0


def _print_version_table_rich():
    console = Console()
    installed_list = [t for t in TOOL_REGISTRY if which(t.name)]
    if not installed_list:
        return
    table = Table(
        title="[bold]Tool Versions[/bold]",
        title_justify="left",
        box=box.HEAVY_EDGE,
    )
    table.add_column("Tool", style="bold cyan", no_wrap=True)
    table.add_column("Version", style="green")
    for tool in installed_list:
        ver = get_tool_version(tool)
        table.add_row(tool.name, ver if ver != "-" else "[dim]-[/dim]")
    console.print(table)


def _print_version_table_fallback():
    installed_list = [t for t in TOOL_REGISTRY if which(t.name)]
    if not installed_list:
        return
    tw, vw = 16, 42
    print("  Tool versions:")
    print("  +" + "-" * (tw + 2) + "+" + "-" * (vw + 2) + "+")
    print(f"  | {'Tool':<{tw}} | {'Version':<{vw}} |")
    print("  +" + "-" * (tw + 2) + "+" + "-" * (vw + 2) + "+")
    for tool in installed_list:
        ver = get_tool_version(tool)
        print(f"  | {tool.name:<{tw}} | {ver:<{vw}} |")
    print("  +" + "-" * (tw + 2) + "+" + "-" * (vw + 2) + "+")


def _is_banner_line(line: str) -> bool:
    stripped = line.strip()
    if not stripped:
        return False
    alnum = sum(c.isalnum() for c in stripped)
    return alnum / max(len(stripped), 1) < 0.3


def _manual_update_hint(name: str) -> str:
    hints = {
        "subfinder":    "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
        "dnsx":         "go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
        "httpx":        "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest",
        "nuclei":       "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
        "naabu":        "go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
        "chaos":        "go install -v github.com/projectdiscovery/chaos-client/cmd/chaos@latest",
        "shuffledns":   "go install -v github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest",
        "katana":       "go install -v github.com/projectdiscovery/katana/cmd/katana@latest",
    }
    return hints.get(name, f"Update {name} manually from its repository")


def cmd_update():
    """--update mode: update tools and nuclei templates."""
    updated = 0
    failed = 0
    skipped = 0
    
    print("")
    print("=" * 58)
    print("  Updating Tools")
    print("=" * 58)
    
    # 1. Update tool binaries
    for tool in TOOL_REGISTRY:
        if not tool.update_cmd or not which(tool.name):
            skipped += 1
            continue
        
        name = tool.name
        print(f"\n  [{name}] Updating...", end=" ")
        
        try:
            before = get_tool_version(tool)
            result = subprocess.run(
                tool.update_cmd,
                capture_output=True, text=True, timeout=120
            )
            after = get_tool_version(tool)
            if before != after:
                print("\033[1;32mupdated\033[0m")
                print(f"    {before[:40]} \033[1;32m→\033[0m {after[:40]}")
                updated += 1
            elif result.returncode == 0:
                print("\033[1;33malready latest\033[0m")
                updated += 1
            else:
                print("\033[1;31mfailed\033[0m")
                err_lines = result.stderr.strip().split("\n")
                real_errors = [err_line for err_line in err_lines if not _is_banner_line(err_line)]
                err_msg = "\n".join(real_errors).strip()[:200]
                if err_msg:
                    print(f"    {err_msg}")
                else:
                    hint = _manual_update_hint(name)
                    print(f"    Manual: {hint}")
                failed += 1
        except subprocess.TimeoutExpired:
            print("\033[1;31mtimeout\033[0m")
            failed += 1
        except Exception as e:
            print(f"\033[1;31m{str(e)[:50]}\033[0m")
            failed += 1
    
    # 2. Update nuclei templates separately
    if tool_available("nuclei"):
        print("\n  [nuclei-templates] Updating...", end=" ")
        try:
            result = subprocess.run(
                ["nuclei", "-update-templates"],
                capture_output=True, text=True, timeout=120
            )
            if result.returncode == 0:
                print("\033[1;32mupdated\033[0m")
                updated += 1
            else:
                print("\033[1;31mfailed\033[0m")
                err_lines = result.stderr.strip().split("\n")
                real_errors = [err_line for err_line in err_lines if not _is_banner_line(err_line)]
                err_msg = "\n".join(real_errors).strip()[:200]
                if err_msg:
                    print(f"    {err_msg}")
                else:
                    print("    Manual: nuclei -update-templates")
                failed += 1
        except Exception as e:
            print(f"\033[1;31m{str(e)[:50]}\033[0m")
            failed += 1
    
    # 3. Summary
    print("")
    print("-" * 58)
    print(f"  Updated: {updated}  |  Failed: {failed}  |  Skipped: {skipped}")
    print("=" * 58)
    
    # 4. Show final versions table
    print("")
    if HAS_RICH:
        _print_version_table_rich()
    else:
        _print_version_table_fallback()
    
    return 1 if failed > 0 else 0


# =============================================================================
# CLI
# =============================================================================

def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Professional Recon Pipeline — 8-phase automated reconnaissance",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Examples:
              python recon.py example.com
              python recon.py example.com aggressive
              python recon.py example.com --quiet
              python recon.py --check
              python recon.py --update
        """),
    )
    
    parser.add_argument("domain", nargs="?", help="Target domain")
    parser.add_argument("mode", nargs="?", default="stealth",
                        choices=["stealth", "aggressive"],
                        help="Scan mode (default: stealth)")
    parser.add_argument("-v", "--verbose", action="count", default=0,
                        help="Verbose output (-v = normal, -vv = debug)")
    parser.add_argument("--quiet", action="store_true",
                        help="Minimal output (phase headers + summaries only)")
    parser.add_argument("--check", action="store_true",
                        help="Check installed tools and exit")
    parser.add_argument("--update", action="store_true",
                        help="Update all tools + nuclei templates")
    parser.add_argument("-o", "--output", help="Custom output directory")
    
    args = parser.parse_args(argv)
    
    # Special modes
    if args.check:
        return args
    if args.update:
        return args
    if not args.domain:
        return args  # interactive mode — caller handles prompts
    
    return args


# =============================================================================
# BANNER
# =============================================================================

def print_banner():
    """Print welcome banner."""
    C = "\033[1;36m"
    G = "\033[1;32m"
    Y = "\033[1;33m"
    R = "\033[0m"
    print(f"""
{C}         ████         ████         ████         ████
{C}        █    █       █    █       █    █       █    █
{C}    ════█════█═══════█════█═══════█════█═══════█════════
{C}        █    █       █    █       █    █       █    █
{C}         ████         ████         ████         ████

{C}              {R}{G}R E C O N X{R}   {Y}F R A M E W O R K{R}

{C}         ████         ████         ████         ████
{C}        █    █       █    █       █    █       █    █
{C}    ════█════█═══════█════█═══════█════█═══════█════════
{C}        █    █       █    █       █    █       █    █
{C}         ████         ████         ████         ████

{R}    {Y}Author{R}  : Mohamed Abd almalek
{Y}    Version{R} : 2.0.0
{Y}    Strand{R}  : 8-Phase Recon Pipeline{R}
""")

# =============================================================================
# MAIN
# =============================================================================

def main():
    args = parse_args()
    
    # Handle special modes
    if args.check:
        sys.exit(cmd_check())
    if args.update:
        sys.exit(cmd_update())
    
    print_banner()
    
    # Interactive mode when no domain given
    try:
        if not args.domain:
            args.domain = input("  [?] Enter target: ").strip()
            m = input("  [?] Stealth or aggressive? (s/a): ").strip().lower()
            args.mode = "stealth" if m in ("s", "stealth") else "aggressive"
    except KeyboardInterrupt:
        print("")
        sys.exit(1)
    
    # Determine verbosity
    if args.quiet:
        CONFIG.verbose = 0
    elif args.verbose >= 2:
        CONFIG.verbose = 2
    elif args.verbose == 1:
        CONFIG.verbose = 1
    else:
        CONFIG.verbose = 1  # default
    
    domain = args.domain
    mode = args.mode
    
    # Validate mode
    if mode not in MODE_CONFIG:
        mode = "stealth"
    
    # Create output directory
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir_name = args.output or f"recon_{domain}_{timestamp}"
    out_dir = Path(out_dir_name)
    out_dir.mkdir(parents=True, exist_ok=True)
    
    # Initialize config
    CONFIG.out_dir = out_dir
    CONFIG.domain = domain
    CONFIG.mode = mode
    CONFIG.cfg = MODE_CONFIG[mode]
    
    # Initialize global logger
    logger = ReconLogger(out_dir / "logs", CONFIG.verbose)
    CONFIG.logger = logger
    
    CONFIG.logger.log(f"Target: {domain}")
    CONFIG.logger.log(f"Mode: {mode}")
    CONFIG.logger.log(f"Output: {out_dir.resolve()}")
    
    # Run pipeline
    pipeline = ReconPipeline(domain, mode, out_dir, CONFIG.verbose)
    
    try:
        pipeline.run()
    except KeyboardInterrupt:
        CONFIG.logger.error("Interrupted by user")
        sys.exit(1)
    except Exception as e:
        CONFIG.logger.error(f"Pipeline failed: {e}")
        if CONFIG.verbose >= 2:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
