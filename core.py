import time
import inspect
import requests
import argparse
from pathlib import Path
from typing import List, Dict, Any, Optional, Generator
from functools import wraps
from utils import log, Colors

class PipelineContext:
    """
    Centralized state container for the BugHunter Pro pipeline.
    Encapsulates target scope, configurations, and shared resources.
    """
    def __init__(self, target: str, scope: List[str], output: Path, args: argparse.Namespace):
        self.target = target
        self.scope = scope
        self.output = output
        self.args = args
        self.metadata = {}
        
        # Shared session for connection pooling
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Security Researcher - BugHunter Pro v2.0)"
        })

    def get_config(self, key: str, default: Any = None) -> Any:
        return getattr(self.args, key, default)


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
    Enforces run(data, context, pb) signature and nomenclature.
    """
    if not hasattr(module_obj, "run"):
        raise AttributeError(f"Module {module_obj.__class__.__name__} is missing required 'run' method.")
    
    sig = inspect.signature(module_obj.run)
    params = list(sig.parameters.keys())
    
    # Check for (self, data, context, pb)
    if len(params) < 3: # allow self to be implicit or explicit depending on usage
        raise TypeError(f"Module {module_obj.__class__.__name__}.run() signature is too short. Expected (data, context, pb).")
    
    # If it's a bound method, params[0] is data. If it's unbound, params[1] is data.
    # We'll just check if 'data', 'context', and 'pb' are present.
    required = {'data', 'context', 'pb'}
    missing = required - set(params)
    if missing:
        raise TypeError(f"Module {module_obj.__class__.__name__}.run() is missing required parameters: {missing}")
    
    if params[0] == 'self':
        if params[1] != 'data' or params[2] != 'context':
            log(f"[!] Warning: Module {module_obj.__class__.__name__} uses non-standard parameter ordering/naming.", Colors.YELLOW)
    elif params[0] != 'data' or params[1] != 'context':
             log(f"[!] Warning: Module {module_obj.__class__.__name__} uses non-standard parameter ordering/naming.", Colors.YELLOW)

