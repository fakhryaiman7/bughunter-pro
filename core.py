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


def batcher(data: List[Any], size: int = 500) -> Generator[List[Any], None, None]:
    """Generator that yields data in processed chunks."""
    for i in range(0, len(data), size):
        yield data[i:i + size]


def validate_module(module_obj: Any):
    """Validates that a module adheres to the strict run(data, context, pb) contract."""
    if not hasattr(module_obj, "run"):
        raise AttributeError(f"Module {module_obj.__class__.__name__} is missing required 'run' method.")
    
    sig = inspect.signature(module_obj.run)
    params = list(sig.parameters.keys())
    
    # Expecting ['self', 'data', 'context', 'pb'] or similar
    if len(params) < 3:
        raise TypeError(f"Module {module_obj.__class__.__name__}.run() signature is too short. Expected (data, context, pb).")
    
    if params[1] != 'data' or params[2] != 'context':
        log(f"[!] Warning: Module {module_obj.__class__.__name__} uses non-standard parameter names: {params}", Colors.YELLOW)
    
    if 'pb' not in params:
        raise TypeError(f"Module {module_obj.__class__.__name__}.run() is missing 'pb' (ProgressBar) parameter.")
