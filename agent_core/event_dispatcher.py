"""Event dispatcher routing accepted domain events to registered handlers."""

from __future__ import annotations

from shared.enums import EventType
from shared.schemas import IncidentEvent

from agent_core.context import DownstreamRequest, TransitionContext
from agent_core.event_handlers import DEFAULT_EVENT_HANDLERS, EventHandler
from agent_core.incident import IncidentAggregate


class EventDispatcher:
    """Dispatches accepted incident events to deterministic handler instances."""

    def __init__(self, handlers: dict[EventType, EventHandler] | None = None) -> None:
        self._handlers: dict[EventType, EventHandler] = (
            dict(handlers) if handlers is not None else dict(DEFAULT_EVENT_HANDLERS)
        )

    def register_handler(self, event_type: EventType, handler: EventHandler) -> None:
        """Register or override a handler for a specific ``EventType``."""
        self._handlers[event_type] = handler

    def dispatch(
        self,
        *,
        previous_incident: IncidentAggregate,
        updated_incident: IncidentAggregate,
        event: IncidentEvent,
        context: TransitionContext,
    ) -> list[DownstreamRequest]:
        """Execute the matching handler and return permitted non-privileged requests."""
        handler = self._handlers.get(event.event_type)
        if handler is None:
            return []
        return handler.handle(
            previous_incident=previous_incident,
            updated_incident=updated_incident,
            event=event,
            context=context,
        )
