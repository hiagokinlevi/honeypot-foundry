from __future__ import annotations

from typing import Any, Optional


# Small shared hook used by event writer/forwarder paths.
# Components should call notify_event_emitted(context) once an event is
# successfully written/forwarded.
def notify_event_emitted(context: Any) -> None:
    controller: Optional[Any] = getattr(context, "_max_events_controller", None)
    if controller is None:
        return
    on_emit = getattr(controller, "on_event_emitted", None)
    if callable(on_emit):
        on_emit()
