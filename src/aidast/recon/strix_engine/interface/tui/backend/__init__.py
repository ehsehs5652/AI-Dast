"""Backend bridge for external TUI clients."""

from aidast.recon.strix_engine.interface.tui.backend.controller import TuiController
from aidast.recon.strix_engine.interface.tui.backend.server import TuiBackendServer


__all__ = ["TuiBackendServer", "TuiController"]
