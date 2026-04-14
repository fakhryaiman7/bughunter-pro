import time
import inspect
import requests
import argparse
from pathlib import Path
from typing import List, Dict, Any, Optional, Generator
from functools import wraps
from utils import log, Colors

import os
import shutil

class PipelineConfig:
    """
    Centralized configuration management.
    Handles environment variables, OS-specific defaults, and runtime overrides.
    """
    def __init__(self, args: argparse.Namespace):
        self.threads = getattr(args, "threads", 10)
        self.timeout = 30 # Default timeout for network operations
        self.shodan_key = getattr(args, "shodan_key", "")
        self.seclists_path = getattr(args, "seclists_path", "")
        self.notify_slack = getattr(args, "notify_slack", None)
        self.discord_webhook = getattr(args, "notify_discord", None)
        
        # Wordlist resolution paths
        self.seclists_base = self._detect_seclists(self.seclists_path)
        self.wordlists_dir = Path("wordlists")
        self.wordlists_dir.mkdir(exist_ok=True)

        # ── Intelligence Patterns ──────────────────
        self.seclists_map = {
            "default": "Discovery/Web-Content/common.txt",
            "API":     "Discovery/Web-Content/api/api-endpoints.txt",
            "ADMIN":   "Discovery/Web-Content/AdminPanels.fuzz.txt",
        }

        self.sqli_errors = [
            r"sql syntax", r"mysql_fetch", r"ORA-\d+",
            r"unclosed quotation", r"pg_exec", r"SQLite3::",
            r"SQLSTATE", r"syntax error.*sql",
        ]

        self.sensitive_patterns = {
            "email":       r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+",
            "aws_key":     r"AKIA[0-9A-Z]{16}",
            "aws_secret":  r"(?i)aws.{0,20}secret.{0,20}['\"]([A-Za-z0-9/+=]{40})['\"]",
            "jwt":         r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*",
            "private_key": r"-----BEGIN (RSA |EC )?PRIVATE KEY-----",
            "slack_token": r"xox[baprs]-[A-Za-z0-9\-]+",
        }

        self.admin_paths = ["/admin", "/admin/login", "/administrator", "/dashboard", "/manage"]
        self.debug_paths = ["/debug", "/test", "/trace", "/phpinfo.php", "/.env", "/server-status"]
        self.sensitive_files = ["/.env", "/config.json", "/.htpasswd", "/.git/config", "/wp-config.php"]
        
        self.takeover_fingerprints = {
            "GitHub Pages":     "There isn't a GitHub Pages site here",
            "Heroku":           "No such app",
            "AWS S3":           "NoSuchBucket",
            "Azure":            "is not configured for",
        }

        self.waf_signatures = {
            "Cloudflare":     ["cloudflare", "cf-ray"],
            "Akamai":         ["akamai", "akamaighost"],
            "Incapsula":      ["incap_ses", "visid_incap"],
        }

        self.security_headers = [
            "Strict-Transport-Security", "Content-Security-Policy",
            "X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy"
        ]

        self.ssrf_canaries = [
            "http://169.254.169.254/latest/meta-data/",
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://127.0.0.1:80",
        ]

        self.redirect_payloads = ["//evil.com", "https://evil.com", "/\\evil.com"]
        self.redirect_params = ["redirect", "url", "next", "u", "link", "t", "r", "goto", "target"]
        
        self.ssrf_params = ["url", "redirect", "next", "return", "callback", "fetch", "target", "link"]
        
        self.backup_extensions = [".bak", ".old", ".zip", ".tar.gz", ".1", "~", ".swp"]
        
        self.graphql_paths = ["/graphql", "/api/graphql", "/v1/graphql", "/v2/graphql", "/graphiql"]
        self.graphql_query = '{"query":"{__schema{queryType{name}mutationType{name}subscriptionType{name}types{...FullType}directives{name description locations args{...InputValue}}}}fragment FullType on __Type{kind name description fields(includeDeprecated:true){name description args{...InputValue}type{...TypeRef}isDeprecated deprecationReason}inputFields{...InputValue}interfaces{...TypeRef}enumValues(includeDeprecated:true){name description isDeprecated deprecationReason}possibleTypes{...TypeRef}}fragment InputValue on __InputValue{name description type{...TypeRef}defaultValue}fragment TypeRef on __Type{kind name充分type{kind充分name充分type{kind充分name充分type{kind充分name充分type{kind充分name充分type{kind充分name充分type{kind充分name}}}}}}}'
        
        self.cve_db_path = Path("cve_database.json")


    def _detect_seclists(self, override: str) -> Path:
        if override:
            p = Path(override)
            if p.exists(): return p
        
        # OS Defaults
        paths = [
            Path("/usr/share/seclists"),             # Kali / Debian
            Path("/opt/seclists"),                  # Custom Linux
            Path("C:/Tools/seclists"),              # Common Windows path
            Path("./wordlists/seclists"),           # Local fallback
        ]
        
        for p in paths:
            if p.exists():
                return p
        
        # Environment Variable override
        env_p = os.environ.get("SECLISTS_BASE")
        if env_p:
            return Path(env_p)

        return Path("/usr/share/seclists") # Absolute default (Kali)

class DependencyGuard:
    """
    Self-healing dependency management layer.
    Checks for tool availability and provides warnings/fallbacks.
    """
    def __init__(self, config: PipelineConfig):
        self.config = config
        self.status = {}

    def validate(self, tools: List[str]):
        """Check availability of external binaries."""
        for tool in tools:
            path = shutil.which(tool)
            self.status[tool] = {"found": bool(path), "path": path}
            if not path:
                log(f"[DEPENDENCY WARNING] Tool '{tool}' not found in PATH.", Colors.YELLOW)

    def has_tool(self, tool: str) -> bool:
        return self.status.get(tool, {}).get("found", False)

    def has_seclists(self) -> bool:
        return self.config.seclists_base.exists()


class PipelineContext:
    """
    Centralized state container for the BugHunter Pro pipeline.
    Encapsulates target scope, configurations, and shared resources.
    """
    def __init__(self, target: str, scope: List[str], output: Path, config: PipelineConfig, deps: DependencyGuard):
        self.target = target
        self.scope = scope
        self.output = output
        self.config = config
        self.deps = deps
        self.metadata = {}
        
        # Shared session for connection pooling
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Security Researcher - BugHunter Pro v2.0)"
        })

    def get_config(self, key: str, default: Any = None) -> Any:
        return getattr(self.config, key, default)



class StageOutput:
    """
    Standardized container for module outputs.
    Ensures consistent data passing between pipeline stages.
    """
    def __init__(self, data: List[Any], stats: Optional[Dict[str, Any]] = None, meta: Optional[Dict[str, Any]] = None):
        self.data = data
        self.stats = stats or {}
        self.meta = meta or {}

    def __repr__(self):
        return f"<StageOutput items={len(self.data)} stats={len(self.stats)}>"


def retry(max_attempts: int = 3, backoff: int = 2):
    """Decorator to implement exponential backoff on failure."""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            attempts = 0
            while attempts < max_attempts:
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    attempts += 1
                    if attempts == max_attempts:
                        log(f"[core] Failed after {max_attempts} attempts: {e}", Colors.RED)
                        raise e
                    wait = backoff ** attempts
                    log(f"[core] Attempt {attempts} failed. Retrying in {wait}s...", Colors.YELLOW)
                    time.sleep(wait)
            return None
        return wrapper
    return decorator


def batcher(data: Any, size: int = 500) -> Generator[List[Any], None, None]:
    """
    Type-safe generator that yields data in processed chunks.
    Automatically handles common data structures (List, Dict, StageOutput).
    """
    if data is None:
        return
    
    clean_data = []
    
    if isinstance(data, list):
        clean_data = data
    elif isinstance(data, dict):
        clean_data = data.get("subdomains", data.get("urls", data.get("targets", list(data.values()))))
    elif isinstance(data, StageOutput):
        clean_data = data.data
    else:
        raise TypeError(f"[core] Batcher received invalid type: {type(data)}. Expected list or dict.")

    if not isinstance(clean_data, list):
        # Last resort: if it's iterable, convert to list
        try:
            clean_data = list(clean_data)
        except:
            raise TypeError(f"[core] Batcher could not normalize input to list.")

    for i in range(0, len(clean_data), size):
        yield clean_data[i:i + size]


def validate_module(module_obj: Any):
    """
    Strict validation of module contracts.
    Enforces run(data, context, pb) signature.
    """
    if not hasattr(module_obj, "run"):
        raise AttributeError(f"Module {module_obj.__class__.__name__} is missing required 'run' method.")
    
    sig = inspect.signature(module_obj.run)
    params = list(sig.parameters.keys())
    
    required = {'data', 'context', 'pb'}
    missing = required - set(params)
    if missing:
        raise TypeError(f"Module {module_obj.__class__.__name__}.run() is missing required parameters: {missing}")


class ModuleRegistry:
    """
    Centralized registry for pipeline modules.
    Ensures safe instantiation with injected dependencies.
    """
    def __init__(self, config: PipelineConfig, context: PipelineContext, deps: DependencyGuard):
        self.config = config
        self.context = context
        self.deps = deps
        self._modules: Dict[str, Any] = {}

    def register(self, name: str, module_class: Any, validate: bool = True, **kwargs):
        """Instantiates and registers a module with standard dependencies."""
        try:
            instance = module_class(self.config, self.context, self.deps, **kwargs)
            if validate:
                validate_module(instance)
            self._modules[name] = instance
            return instance
        except Exception as e:
            log(f"[FATAL] Registration failed for module '{name}': {e}", Colors.RED)
            raise e

    def get(self, name: str) -> Any:
        return self._modules.get(name)


class Bootstrap:
    """
    The Foundation Layer (Bootstrap Pattern).
    Responsible for the entire system initialization and pre-flight validation.
    """
    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.config = None
        self.deps = None
        self.context = None
        self.registry = None

    def initialize(self) -> 'Bootstrap':
        log("[*] Bootstrapping BugHunter Pro v2.0 Architecture...", Colors.CYAN)
        
        # 1. Core Objects
        self.config = PipelineConfig(self.args)
        self.deps = DependencyGuard(self.config)
        
        # 2. Scope & Target
        scope = self._load_scope()
        output = Path(self.args.output)
        
        # 3. Context Injection (Dependency Injection)
        self.context = PipelineContext(self.args.target, scope, output, self.config, self.deps)
        
        # 4. Registry Setup
        self.registry = ModuleRegistry(self.config, self.context, self.deps)
        
        return self

    def _load_scope(self) -> List[str]:
        if not self.args.scope:
            return [self.args.target]
        try:
            with open(self.args.scope) as f:
                return [l.strip() for l in f if l.strip() and not l.startswith("#")]
        except Exception:
            return [self.args.target]

