from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, time
from enum import Enum
from typing import Callable, List, Optional


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class EventType(str, Enum):
    CARD_INSERTED = "card_inserted"
    PIN_FAILED = "pin_failed"
    PIN_VERIFIED = "pin_verified"
    SAFE_DOOR_OPENED = "safe_door_opened"
    VIBRATION_DETECTED = "vibration_detected"
    NETWORK_OFFLINE = "network_offline"
    NETWORK_ONLINE = "network_online"
    MAINTENANCE_MODE_ENABLED = "maintenance_mode_enabled"
    CASH_REPLENISHED = "cash_replenished"


@dataclass
class ATMEvent:
    event_type: EventType
    timestamp: datetime
    value: Optional[float] = None
    actor_id: Optional[str] = None
    details: str = ""


@dataclass
class SecurityAlert:
    severity: Severity
    title: str
    description: str
    timestamp: datetime


@dataclass
class ATMState:
    pin_failures: int = 0
    network_online: bool = True
    maintenance_mode: bool = False
    maintenance_authorized: bool = False
    safe_open: bool = False
    last_card_actor: Optional[str] = None
    recent_events: List[ATMEvent] = field(default_factory=list)
    alerts: List[SecurityAlert] = field(default_factory=list)


RuleCheck = Callable[[ATMEvent, ATMState], Optional[SecurityAlert]]


@dataclass
class SecurityRule:
    name: str
    check: RuleCheck


class ATMSecurityEngine:
    def __init__(self) -> None:
        self.rules = [
            SecurityRule("multiple_pin_failures", self._check_multiple_pin_failures),
            SecurityRule("unauthorized_safe_open", self._check_unauthorized_safe_open),
            SecurityRule("high_vibration", self._check_high_vibration),
            SecurityRule("network_offline", self._check_network_offline),
            SecurityRule("maintenance_outside_window", self._check_maintenance_window),
        ]
        self.state = ATMState()
        self.max_recent_events = 25

    def reset(self) -> ATMState:
        self.state = ATMState()
        return self.state

    def process_event(self, event: ATMEvent) -> List[SecurityAlert]:
        self._update_state(event)
        generated_alerts: List[SecurityAlert] = []

        for rule in self.rules:
            alert = rule.check(event, self.state)
            if alert:
                self.state.alerts.append(alert)
                generated_alerts.append(alert)

        return generated_alerts

    def _update_state(self, event: ATMEvent) -> None:
        self.state.recent_events.append(event)
        if len(self.state.recent_events) > self.max_recent_events:
            self.state.recent_events = self.state.recent_events[-self.max_recent_events :]

        if event.event_type == EventType.CARD_INSERTED:
            self.state.last_card_actor = event.actor_id
        elif event.event_type == EventType.PIN_FAILED:
            self.state.pin_failures += 1
        elif event.event_type == EventType.PIN_VERIFIED:
            self.state.pin_failures = 0
        elif event.event_type == EventType.SAFE_DOOR_OPENED:
            self.state.safe_open = True
        elif event.event_type == EventType.NETWORK_OFFLINE:
            self.state.network_online = False
        elif event.event_type == EventType.NETWORK_ONLINE:
            self.state.network_online = True
        elif event.event_type == EventType.CASH_REPLENISHED:
            self.state.safe_open = False
        elif event.event_type == EventType.MAINTENANCE_MODE_ENABLED:
            self.state.maintenance_mode = True
            current_time = event.timestamp.time()
            self.state.maintenance_authorized = time(1, 0) <= current_time <= time(5, 0)

    def _check_multiple_pin_failures(
        self, event: ATMEvent, state: ATMState
    ) -> Optional[SecurityAlert]:
        if event.event_type == EventType.PIN_FAILED and state.pin_failures >= 3:
            return SecurityAlert(
                severity=Severity.HIGH,
                title="Multiplas falhas de PIN",
                description=(
                    f"Foram detectadas {state.pin_failures} tentativas consecutivas "
                    "de PIN incorreto."
                ),
                timestamp=event.timestamp,
            )
        return None

    def _check_unauthorized_safe_open(
        self, event: ATMEvent, state: ATMState
    ) -> Optional[SecurityAlert]:
        if event.event_type == EventType.SAFE_DOOR_OPENED and not (
            state.maintenance_mode and state.maintenance_authorized
        ):
            return SecurityAlert(
                severity=Severity.CRITICAL,
                title="Cofre aberto sem manutencao ativa",
                description=(
                    "O compartimento seguro foi aberto sem uma manutencao valida e autorizada."
                ),
                timestamp=event.timestamp,
            )
        return None

    def _check_high_vibration(
        self, event: ATMEvent, _state: ATMState
    ) -> Optional[SecurityAlert]:
        if event.event_type == EventType.VIBRATION_DETECTED and (event.value or 0) >= 8.0:
            return SecurityAlert(
                severity=Severity.CRITICAL,
                title="Vibracao intensa detectada",
                description=(
                    f"O sensor registrou vibracao acima do limite seguro: {event.value}."
                ),
                timestamp=event.timestamp,
            )
        return None

    def _check_network_offline(
        self, event: ATMEvent, _state: ATMState
    ) -> Optional[SecurityAlert]:
        if event.event_type == EventType.NETWORK_OFFLINE:
            return SecurityAlert(
                severity=Severity.MEDIUM,
                title="Terminal sem conexao",
                description="O caixa eletronico perdeu comunicacao com a central.",
                timestamp=event.timestamp,
            )
        return None

    def _check_maintenance_window(
        self, event: ATMEvent, _state: ATMState
    ) -> Optional[SecurityAlert]:
        if event.event_type != EventType.MAINTENANCE_MODE_ENABLED:
            return None

        current_time = event.timestamp.time()
        if not (time(1, 0) <= current_time <= time(5, 0)):
            return SecurityAlert(
                severity=Severity.HIGH,
                title="Manutencao fora de horario",
                description=(
                    "O modo de manutencao foi habilitado fora da janela permitida "
                    "de 01:00 a 05:00."
                ),
                timestamp=event.timestamp,
            )
        return None


def print_alerts(alerts: List[SecurityAlert]) -> None:
    if not alerts:
        return

    for alert in alerts:
        print(
            f"[{alert.timestamp.isoformat()}] "
            f"{alert.severity.upper()} | {alert.title} | {alert.description}"
        )


def build_demo_events() -> List[ATMEvent]:
    base = datetime(2026, 4, 6, 14, 0, 0)
    return [
        ATMEvent(EventType.CARD_INSERTED, base, actor_id="card-001"),
        ATMEvent(EventType.PIN_FAILED, base.replace(minute=1), actor_id="card-001"),
        ATMEvent(EventType.PIN_FAILED, base.replace(minute=2), actor_id="card-001"),
        ATMEvent(EventType.PIN_FAILED, base.replace(minute=3), actor_id="card-001"),
        ATMEvent(EventType.NETWORK_OFFLINE, base.replace(minute=4), details="link down"),
        ATMEvent(EventType.VIBRATION_DETECTED, base.replace(minute=5), value=9.4),
        ATMEvent(
            EventType.MAINTENANCE_MODE_ENABLED,
            base.replace(minute=6),
            actor_id="tech-12",
        ),
        ATMEvent(EventType.SAFE_DOOR_OPENED, base.replace(minute=7), actor_id="tech-12"),
    ]


def main() -> None:
    engine = ATMSecurityEngine()
    events = build_demo_events()

    print("Monitorando eventos do caixa eletronico...\n")
    for event in events:
        print(f"Evento: {event.event_type.value} | horario: {event.timestamp.isoformat()}")
        alerts = engine.process_event(event)
        print_alerts(alerts)

    print("\nResumo:")
    print(f"Total de alertas: {len(engine.state.alerts)}")
    for index, alert in enumerate(engine.state.alerts, start=1):
        print(f"{index}. {alert.severity.upper()} - {alert.title}")


if __name__ == "__main__":
    main()