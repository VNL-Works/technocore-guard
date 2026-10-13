"""Technocore Guard: offline URL effect classification and evidence utilities."""

from .classifier import inspect_url
from .models import Effect, Inspection, Risk

__all__ = ["Effect", "Inspection", "Risk", "inspect_url"]
__version__ = "0.2.0"
