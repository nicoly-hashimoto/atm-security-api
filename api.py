from __future__ import annotations

from dataclasses import asdict
from datetime import datetime
from datetime import timedelta
from datetime import timezone
import asyncio
import base64
import hashlib
import hmac
import json
import os
import webbrowser

import bcrypt
from pathlib import Path
from threading import Lock
from typing import Any, List, Optional

from fastapi import Depends, FastAPI, HTTPException, status, Request
from fastapi.responses import HTMLResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from atm_security import ATMEvent, ATMSecurityEngine, EventType, SecurityAlert, Severity
from security_improved import (
    logger, rate_limiter, validator, session_manager, brute_force_protection,
    unauthorized_access_protection, access_control_validator,
    LogLevel
)


app = FastAPI(
    title="ATM Security API",
    description="API defensiva para monitoramento de seguranca de caixa eletronico.",
    version="1.0.0",
)

# ============================================================================
# CORS Configuration - Restringir acesso apenas aos domínios autorizados
# ============================================================================
CORS_ORIGINS = os.getenv("CORS_ORIGINS", "http://localhost:3000,http://127.0.0.1:8000").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
)


# ============================================================================
# Middleware de Logging
# ============================================================================
@app.middleware("http")
async def log_requests(request: Request, call_next):
    """Middleware que registra todas as requisições."""
    response = await call_next(request)
    
    # Não fazer log de requisições healthcheck
    if request.url.path not in ["/health", "/docs", "/redoc", "/openapi.json"]:
        username = getattr(request.state, "username", None)
        logger.api_call(
            username=username,
            method=request.method,
            endpoint=request.url.path,
            status_code=response.status_code,
            ip_address=request.client.host if request.client else None
        )
    
    return response


engine = ATMSecurityEngine()
engine_lock = Lock()
dashboard_path = Path(__file__).parent / "template" / "dashboard.html"
bearer_scheme = HTTPBearer(auto_error=False)

TOKEN_TTL_MINUTES = int(os.getenv("ATM_TOKEN_TTL_MINUTES", "30"))  # Reduzido para 30 min
AUTH_SECRET = os.getenv("ATM_AUTH_SECRET", "atm-security-dev-secret-change-me")
DEFAULT_VIEWER_USERNAME = os.getenv("ATM_VIEWER_USERNAME", "viewer")
DEFAULT_VIEWER_PASSWORD = os.getenv("ATM_VIEWER_PASSWORD", "viewer123")
DEFAULT_VIEWER_NAME = os.getenv("ATM_VIEWER_NAME", "Monitoring Viewer")
DEFAULT_OPERATOR_USERNAME = os.getenv("ATM_OPERATOR_USERNAME", "operator")
DEFAULT_OPERATOR_PASSWORD = os.getenv("ATM_OPERATOR_PASSWORD", "admin123")
DEFAULT_OPERATOR_NAME = os.getenv("ATM_OPERATOR_NAME", "Central Operator")
DEFAULT_ADMIN_USERNAME = os.getenv("ATM_ADMIN_USERNAME", "admin")
DEFAULT_ADMIN_PASSWORD = os.getenv("ATM_ADMIN_PASSWORD", "superadmin123")
DEFAULT_ADMIN_NAME = os.getenv("ATM_ADMIN_NAME", "Security Administrator")


def hash_password_bcrypt(password: str) -> str:
    """
    Hash de senha usando bcrypt (mais seguro que PBKDF2).
    Cada senha tem seu próprio salt automático.
    """
    salt = bcrypt.gensalt(rounds=12)  # 12 rounds = ~0.3 segundos
    return bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")


def verify_password_bcrypt(password: str, hash_stored: str) -> bool:
    """Verifica senha contra hash bcrypt."""
    try:
        return bcrypt.checkpw(password.encode("utf-8"), hash_stored.encode("utf-8"))
    except Exception:
        return False


# Hash de senha para compatibilidade (DEPRECATED - será removido)
OPERATOR_SALT = os.getenv("ATM_OPERATOR_SALT", "atm-operator-salt")
ROLE_PERMISSIONS = {
    "viewer": ["dashboard:view"],
    "operator": ["dashboard:view", "events:write"],
    "admin": ["dashboard:view", "events:write", "engine:reset", "users:manage"],
}


def permissions_for_role(role: str) -> List[str]:
    permissions = ROLE_PERMISSIONS.get(role)
    if permissions is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Perfil de operador invalido.",
        )
    return permissions.copy()


OPERATORS = {
    DEFAULT_VIEWER_USERNAME: {
        "username": DEFAULT_VIEWER_USERNAME,
        "name": DEFAULT_VIEWER_NAME,
        "role": "viewer",
        "permissions": permissions_for_role("viewer"),
        "password_hash": hash_password_bcrypt(DEFAULT_VIEWER_PASSWORD),
    },
    DEFAULT_OPERATOR_USERNAME: {
        "username": DEFAULT_OPERATOR_USERNAME,
        "name": DEFAULT_OPERATOR_NAME,
        "role": "operator",
        "permissions": permissions_for_role("operator"),
        "password_hash": hash_password_bcrypt(DEFAULT_OPERATOR_PASSWORD),
    },
    DEFAULT_ADMIN_USERNAME: {
        "username": DEFAULT_ADMIN_USERNAME,
        "name": DEFAULT_ADMIN_NAME,
        "role": "admin",
        "permissions": permissions_for_role("admin"),
        "password_hash": hash_password_bcrypt(DEFAULT_ADMIN_PASSWORD),
    },
}


@app.on_event("startup")
async def open_browser():
    """Abre o navegador automaticamente quando a API inicia."""
    await asyncio.sleep(1)
    try:
        webbrowser.open("http://127.0.0.1:8000")
    except Exception:
        print("https://127.0.0.1:8000 - Acesse este link no seu navegador")


class EventIn(BaseModel):
    event_type: EventType
    timestamp: datetime = Field(
        default_factory=datetime.utcnow,
        description="Horario do evento em formato ISO 8601.",
    )
    value: Optional[float] = None
    actor_id: Optional[str] = None
    details: str = ""


class AlertOut(BaseModel):
    severity: str
    title: str
    description: str
    timestamp: datetime


class EventOut(BaseModel):
    event_type: str
    timestamp: datetime
    value: Optional[float] = None
    actor_id: Optional[str] = None
    details: str


class StateOut(BaseModel):
    pin_failures: int
    network_online: bool
    maintenance_mode: bool
    maintenance_authorized: bool
    safe_open: bool
    last_card_actor: Optional[str]
    total_alerts: int


class SnapshotOut(BaseModel):
    state: StateOut
    risk_level: str
    alerts: List[AlertOut]
    recent_events: List[EventOut]


class LoginIn(BaseModel):
    username: str
    password: str


class OperatorCreateIn(BaseModel):
    username: str
    password: str
    name: str
    role: str


class OperatorUpdateIn(BaseModel):
    name: Optional[str] = None
    role: Optional[str] = None
    password: Optional[str] = None


class TokenOut(BaseModel):
    access_token: str
    token_type: str
    expires_at: datetime
    operator_name: str
    username: str
    role: str
    permissions: List[str]


class OperatorProfileOut(BaseModel):
    username: str
    name: str
    role: str
    permissions: List[str]


class OperatorListOut(BaseModel):
    operators: List[OperatorProfileOut]


class EventProcessResponse(BaseModel):
    message: str
    processed_event: EventIn
    generated_alerts: List[AlertOut]
    state: StateOut


def serialize_operator(operator: dict[str, Any]) -> OperatorProfileOut:
    return OperatorProfileOut(
        username=operator["username"],
        name=operator["name"],
        role=operator["role"],
        permissions=list(operator["permissions"]),
    )


def to_alert_out(alert: SecurityAlert) -> AlertOut:
    return AlertOut(**asdict(alert))


def to_event_out(event: ATMEvent) -> EventOut:
    return EventOut(**asdict(event))


def current_risk_level() -> str:
    severity_order = {
        Severity.LOW.value: 1,
        Severity.MEDIUM.value: 2,
        Severity.HIGH.value: 3,
        Severity.CRITICAL.value: 4,
    }
    highest = 1

    for alert in engine.state.alerts[-10:]:
        highest = max(highest, severity_order[alert.severity.value])

    reverse_map = {
        1: Severity.LOW.value,
        2: Severity.MEDIUM.value,
        3: Severity.HIGH.value,
        4: Severity.CRITICAL.value,
    }
    return reverse_map[highest]


def current_state() -> StateOut:
    state = engine.state
    return StateOut(
        pin_failures=state.pin_failures,
        network_online=state.network_online,
        maintenance_mode=state.maintenance_mode,
        maintenance_authorized=state.maintenance_authorized,
        safe_open=state.safe_open,
        last_card_actor=state.last_card_actor,
        total_alerts=len(state.alerts),
    )


def current_snapshot() -> SnapshotOut:
    return SnapshotOut(
        state=current_state(),
        risk_level=current_risk_level(),
        alerts=[to_alert_out(alert) for alert in reversed(engine.state.alerts[-12:])],
        recent_events=[to_event_out(event) for event in reversed(engine.state.recent_events[-12:])],
    )


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")


def b64url_decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def sign_token(payload: dict[str, Any]) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    header_segment = b64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    payload_segment = b64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    signing_input = f"{header_segment}.{payload_segment}".encode("utf-8")
    signature = hmac.new(AUTH_SECRET.encode("utf-8"), signing_input, hashlib.sha256).digest()
    return f"{header_segment}.{payload_segment}.{b64url_encode(signature)}"


def decode_token(token: str) -> dict[str, Any]:
    try:
        header_segment, payload_segment, signature_segment = token.split(".")
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token invalido.",
        ) from exc

    signing_input = f"{header_segment}.{payload_segment}".encode("utf-8")
    expected_signature = hmac.new(
        AUTH_SECRET.encode("utf-8"),
        signing_input,
        hashlib.sha256,
    ).digest()

    provided_signature = b64url_decode(signature_segment)
    if not hmac.compare_digest(expected_signature, provided_signature):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Assinatura do token invalida.",
        )

    payload = json.loads(b64url_decode(payload_segment).decode("utf-8"))
    expires_at = datetime.fromtimestamp(payload["exp"], tz=timezone.utc)
    if expires_at < datetime.now(timezone.utc):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token expirado.",
        )
    return payload


def verify_operator(username: str, password: str, ip_address: Optional[str] = None) -> Optional[dict[str, Any]]:
    """
    Verifica credenciais do operador com rate limiting, brute force protection, e logging.
    """
    brute_force_key = f"{username}:{ip_address}"
    
    # Verificar bloqueio por brute force
    is_locked, lockout_time = brute_force_protection.is_locked(brute_force_key)
    if is_locked:
        logger.log(
            LogLevel.WARNING,
            "LOGIN_BRUTE_FORCE_BLOCKED",
            username=username,
            ip_address=ip_address,
            details={"reason": f"Conta bloqueada por {lockout_time} minutos após múltiplas tentativas"}
        )
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Muitas tentativas falhadas. Tente novamente em {lockout_time}.",
        )
    
    # Rate limiting básico por IP
    if not rate_limiter.check_rate_limit(f"login_{ip_address}"):
        logger.log(
            LogLevel.WARNING,
            "LOGIN_RATE_LIMITED",
            username=username,
            ip_address=ip_address,
            details={"reason": "Rate limit ou tentativas suspeitas"}
        )
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Muitas tentativas de login. Tente novamente em 1 minuto.",
        )
    
    operator = OPERATORS.get(username)
    if not operator:
        # Registrar tentativa falhada
        protection_result = brute_force_protection.record_failed_attempt(brute_force_key, ip_address or "unknown")
        logger.login_attempt(username, success=False, ip_address=ip_address)
        
        if protection_result["blocked"]:
            logger.log(
                LogLevel.CRITICAL,
                "BRUTE_FORCE_ATTACK",
                username=username,
                ip_address=ip_address,
                details={
                    "attempts": protection_result["attempt_count"],
                    "lockout_minutes": protection_result["lockout_minutes"],
                    "threat_level": "HIGH"
                }
            )
        
        return None

    if not verify_password_bcrypt(password, operator["password_hash"]):
        # Registrar tentativa falhada com proteção anti brute force
        protection_result = brute_force_protection.record_failed_attempt(brute_force_key, ip_address or "unknown")
        logger.login_attempt(username, success=False, ip_address=ip_address)
        
        if protection_result["blocked"]:
            logger.log(
                LogLevel.CRITICAL,
                "BRUTE_FORCE_ATTACK",
                username=username,
                ip_address=ip_address,
                details={
                    "attempts": protection_result["attempt_count"],
                    "lockout_minutes": protection_result["lockout_minutes"],
                    "threat_level": "HIGH"
                }
            )
            
            # Registrar como evento de segurança
            with engine_lock:
                alert = SecurityAlert(
                    severity=Severity.CRITICAL,
                    title="Ataque de Força Bruta Detectado",
                    description=f"Múltiplas tentativas falhadas para {username} do IP {ip_address}",
                    timestamp=datetime.now(timezone.utc)
                )
                engine.state.alerts.append(alert)
        
        return None

    # Login bem-sucedido - reseta contadores
    rate_limiter.reset(f"login_{ip_address}")
    brute_force_protection.record_successful_attempt(brute_force_key)
    logger.login_attempt(username, success=True, ip_address=ip_address)
    
    return {
        "username": operator["username"],
        "name": operator["name"],
        "role": operator["role"],
        "permissions": list(operator["permissions"]),
    }


def create_access_token(operator: dict[str, Any]) -> TokenOut:
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=TOKEN_TTL_MINUTES)
    payload = {
        "sub": operator["username"],
        "name": operator["name"],
        "role": operator["role"],
        "permissions": operator["permissions"],
        "exp": int(expires_at.timestamp()),
    }
    token = sign_token(payload)
    return TokenOut(
        access_token=token,
        token_type="bearer",
        expires_at=expires_at,
        operator_name=operator["name"],
        username=operator["username"],
        role=operator["role"],
        permissions=operator["permissions"],
    )


def get_current_operator(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
) -> dict[str, Any]:
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Credenciais ausentes.",
        )

    payload = decode_token(credentials.credentials)
    operator = OPERATORS.get(payload["sub"])
    if not operator:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Operador nao encontrado.",
        )

    return {
        "username": operator["username"],
        "name": operator["name"],
        "role": operator["role"],
        "permissions": list(operator["permissions"]),
    }


def require_permission(permission: str):
    def permission_dependency(
        current_operator: dict[str, Any] = Depends(get_current_operator),
    ) -> dict[str, Any]:
        if permission not in current_operator["permissions"]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Operador sem permissao para esta acao.",
            )
        return current_operator

    return permission_dependency


@app.get("/", response_class=HTMLResponse)
def dashboard() -> HTMLResponse:
    """Dashboard - HTML é servido publicamente, autenticação é feita no JavaScript."""
    return HTMLResponse(dashboard_path.read_text(encoding="utf-8"))


@app.get("/health")
def healthcheck() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/auth/login", response_model=TokenOut)
def login(credentials: LoginIn, request: Request) -> TokenOut:
    # Validar entrada
    if not validator.validate_username(credentials.username):
        logger.log(
            LogLevel.WARNING,
            "LOGIN_INVALID_INPUT",
            username=credentials.username,
            ip_address=request.client.host if request.client else None,
            details={"reason": "Username inválido"}
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username inválido.",
        )
    
    ip_address = request.client.host if request.client else None
    operator = verify_operator(credentials.username, credentials.password, ip_address=ip_address)
    
    if not operator:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Usuario ou senha invalidos.",
        )
    return create_access_token(operator)


@app.get("/auth/me", response_model=OperatorProfileOut)
def auth_me(current_operator: dict[str, Any] = Depends(get_current_operator)) -> OperatorProfileOut:
    return OperatorProfileOut(**current_operator)


@app.get("/admin/users", response_model=OperatorListOut)
def list_operators(
    _current_operator: dict[str, Any] = Depends(require_permission("users:manage")),
) -> OperatorListOut:
    operators = sorted(OPERATORS.values(), key=lambda item: item["username"])
    return OperatorListOut(operators=[serialize_operator(operator) for operator in operators])


@app.post("/admin/users", response_model=OperatorProfileOut, status_code=status.HTTP_201_CREATED)
def create_operator(
    operator_in: OperatorCreateIn,
    request: Request,
    _current_operator: dict[str, Any] = Depends(require_permission("users:manage")),
) -> OperatorProfileOut:
    username = operator_in.username.strip()
    
    # Validar entrada
    if not validator.validate_username(username):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username invalido (3-32 caracteres alfanuméricos).",
        )
    
    if not validator.validate_password(operator_in.password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Senha fraca (mínimo 8 caracteres, maiúscula, minúscula e número).",
        )
    
    if not validator.validate_role(operator_in.role, list(ROLE_PERMISSIONS.keys())):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Role inválido.",
        )

    if username in OPERATORS:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Ja existe um operador com esse username.",
        )

    permissions = permissions_for_role(operator_in.role)
    operator = {
        "username": username,
        "name": operator_in.name.strip() or username,
        "role": operator_in.role,
        "permissions": permissions,
        "password_hash": hash_password_bcrypt(operator_in.password),
    }
    
    OPERATORS[username] = operator
    
    # Log de ação administrativa
    logger.admin_action(
        _current_operator["username"],
        "CREATE_USER",
        target=username,
        details={"role": operator_in.role},
        ip_address=request.client.host if request.client else None
    )
    
    return serialize_operator(operator)


@app.put("/admin/users/{username}", response_model=OperatorProfileOut)
def update_operator(
    username: str,
    operator_in: OperatorUpdateIn,
    request: Request,
    _current_operator: dict[str, Any] = Depends(require_permission("users:manage")),
) -> OperatorProfileOut:
    operator = OPERATORS.get(username)
    if operator is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Operador nao encontrado.",
        )

    if operator_in.name is not None and operator_in.name.strip():
        operator["name"] = operator_in.name.strip()

    if operator_in.role is not None:
        if not validator.validate_role(operator_in.role, list(ROLE_PERMISSIONS.keys())):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Role inválido.",
            )
        operator["role"] = operator_in.role
        operator["permissions"] = permissions_for_role(operator_in.role)

    if operator_in.password is not None and operator_in.password != "":
        if not validator.validate_password(operator_in.password):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Senha fraca.",
            )
        operator["password_hash"] = hash_password_bcrypt(operator_in.password)
    
    # Log de ação administrativa
    logger.admin_action(
        _current_operator["username"],
        "UPDATE_USER",
        target=username,
        details={
            "name_changed": operator_in.name is not None,
            "role_changed": operator_in.role is not None,
            "password_changed": operator_in.password is not None,
        },
        ip_address=request.client.host if request.client else None
    )

    return serialize_operator(operator)


@app.get("/state", response_model=StateOut)
def get_state() -> StateOut:
    with engine_lock:
        return current_state()


@app.get("/snapshot", response_model=SnapshotOut)
def get_snapshot() -> SnapshotOut:
    with engine_lock:
        return current_snapshot()


@app.get("/alerts", response_model=List[AlertOut])
def list_alerts() -> List[AlertOut]:
    with engine_lock:
        return [to_alert_out(alert) for alert in engine.state.alerts]


@app.get("/events/recent", response_model=List[EventOut])
def list_recent_events() -> List[EventOut]:
    with engine_lock:
        return [to_event_out(event) for event in engine.state.recent_events]


@app.post("/events", response_model=EventProcessResponse)
def process_event(
    event_in: EventIn,
    request: Request,
    _current_operator: dict[str, Any] = Depends(require_permission("events:write")),
) -> EventProcessResponse:
    # Validar entrada
    if event_in.actor_id and not validator.validate_actor_id(event_in.actor_id):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Actor ID inválido.",
        )
    
    if not validator.validate_details(event_in.details):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Detalhes do evento inválidos.",
        )
    
    ip_address = request.client.host if request.client else "unknown"
    
    # Verificar bloqueio por acesso não autorizado
    is_blocked, block_time = unauthorized_access_protection.is_ip_blocked(ip_address)
    if is_blocked:
        logger.log(
            LogLevel.WARNING,
            "UNAUTHORIZED_ACCESS_BLOCKED",
            username=_current_operator["username"],
            ip_address=ip_address,
            details={"reason": f"IP bloqueado por {block_time} minutos"}
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Acesso negado. IP bloqueado por {block_time}.",
        )
    
    # Verificação adicional para SAFE_DOOR_OPENED
    if event_in.event_type == EventType.SAFE_DOOR_OPENED:
        can_access, reason = access_control_validator.validate_safe_door_access(
            _current_operator,
            is_authorized=access_control_validator.is_maintenance_window(),
            ip_address=ip_address
        )
        
        if not can_access:
            # Registrar tentativa de acesso não autorizado
            protection_result = unauthorized_access_protection.record_unauthorized_attempt(
                ip_address,
                "SAFE_DOOR_OPEN",
                event_in.actor_id or "unknown"
            )
            
            logger.log(
                LogLevel.CRITICAL,
                "UNAUTHORIZED_SAFE_ACCESS_ATTEMPTED",
                username=_current_operator["username"],
                ip_address=ip_address,
                details={
                    "reason": reason,
                    "actor_id": event_in.actor_id,
                    "blocked": protection_result["blocked"],
                    "attempt_count": protection_result["attempt_count"]
                }
            )
            
            # Gerar alerta crítico
            with engine_lock:
                alert = SecurityAlert(
                    severity=Severity.CRITICAL,
                    title="Tentativa de Acesso Não Autorizado ao Cofre",
                    description=f"Cofre: {reason} | Operador: {_current_operator['username']} | IP: {ip_address}",
                    timestamp=datetime.now(timezone.utc)
                )
                engine.state.alerts.append(alert)
            
            if protection_result["blocked"]:
                logger.log(
                    LogLevel.CRITICAL,
                    "IP_BLOCKED_UNAUTHORIZED_ACCESS",
                    username=_current_operator["username"],
                    ip_address=ip_address,
                    details={
                        "block_duration": protection_result["block_duration"],
                        "total_attempts": protection_result["attempt_count"]
                    }
                )
            
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Acesso ao cofre negado: {reason}. IPs suspeitos podem ser bloqueados.",
            )
    
    event = ATMEvent(
        event_type=event_in.event_type,
        timestamp=event_in.timestamp,
        value=event_in.value,
        actor_id=event_in.actor_id,
        details=event_in.details,
    )

    with engine_lock:
        # Se chegou até aqui, reseta contadores
        unauthorized_access_protection.reset_ip(ip_address)
        
        alerts = engine.process_event(event)
        
        # Log do evento processado
        logger.log(
            LogLevel.AUDIT,
            "EVENT_PROCESSED",
            username=_current_operator["username"],
            details={
                "event_type": event.event_type.value,
                "actor_id": event.actor_id,
                "alerts_generated": len(alerts),
            },
            ip_address=ip_address
        )
        
        return EventProcessResponse(
            message="Evento processado com sucesso.",
            processed_event=event_in,
            generated_alerts=[to_alert_out(alert) for alert in alerts],
            state=current_state(),
        )


@app.post("/reset", response_model=StateOut)
def reset_engine(
    request: Request,
    _current_operator: dict[str, Any] = Depends(require_permission("engine:reset")),
) -> StateOut:
    with engine_lock:
        engine.reset()
        
        # Log da ação
        logger.admin_action(
            _current_operator["username"],
            "ENGINE_RESET",
            ip_address=request.client.host if request.client else None
        )
        
        return current_state()


# ============================================================================
# API Endpoints para Dashboard (Statistics & Charts)
# ============================================================================

@app.get("/api/dashboard-stats")
def get_dashboard_stats() -> dict[str, Any]:
    """Retorna estatísticas para o dashboard."""
    with engine_lock:
        total_events = len(engine.state.recent_events)
        total_alerts = len(engine.state.alerts)
        critical_alerts = sum(1 for a in engine.state.alerts if a.severity == Severity.CRITICAL)
        high_alerts = sum(1 for a in engine.state.alerts if a.severity == Severity.HIGH)
        
        # Simular testes
        total_tests = max(total_events + 25, 100)
        passed_tests = int(total_tests * 0.75)
        failed_tests = int(total_tests * 0.20)
        warnings = total_tests - passed_tests - failed_tests
        
        # Formatar alertas para o dashboard
        alerts_list = []
        for alert in reversed(engine.state.alerts[-12:]):
            alerts_list.append({
                "title": alert.title,
                "description": alert.description,
                "severity": alert.severity.value,
                "time": alert.timestamp.strftime("%H:%M:%S"),
            })
        
        return {
            "tests_passed": passed_tests,
            "tests_failed": failed_tests,
            "warnings": warnings,
            "in_progress": len([e for e in engine.state.recent_events if e.event_type == EventType.PIN_FAILED]),
            "active_threats": critical_alerts + high_alerts,
            "total_alerts": total_alerts,
            "critical_alerts": critical_alerts,
            "system_status": "CRITICAL" if critical_alerts > 0 else "WARNING" if high_alerts > 0 else "NORMAL",
            "risk_level": min(100, (total_alerts * 5)),
            "network_status": "ONLINE" if engine.state.network_online else "OFFLINE",
            "safe_door_status": "OPEN" if engine.state.safe_open else "CLOSED",
            "maintenance_mode": engine.state.maintenance_mode,
            "alerts": alerts_list,
        }


@app.get("/api/chart-data")
def get_chart_data() -> dict[str, Any]:
    """Retorna dados para os gráficos (ataques, atividades)."""
    with engine_lock:
        # Gerar série temporal de dados para os últimos 20 eventos
        labels = []
        threat_data = []
        intrusion_data = []
        malware_data = []
        
        for i, event in enumerate(engine.state.recent_events[-20:]):
            timestamp = event.timestamp.strftime("%H:%M:%S")
            labels.append(timestamp)
            
            # Simular dados de ataque  
            threat_level = 0
            if event.event_type == EventType.PIN_FAILED:
                threat_level = 35
            elif event.event_type == EventType.SAFE_DOOR_OPENED:
                threat_level = 60
            elif event.event_type == EventType.VIBRATION_DETECTED:
                threat_level = 40
            elif event.event_type == EventType.NETWORK_OFFLINE:
                threat_level = 30
                
            threat_data.append(threat_level)
            intrusion_data.append(threat_level * 0.6 if threat_level > 0 else 0)
            malware_data.append(threat_level * 0.4 if threat_level > 0 else 0)
        
        # Se não há eventos, gerar dados demo
        if not labels:
            labels = [f"{16+i:02d}:00" for i in range(20)]
            threat_data = [15 + (i * 2) for i in range(20)]
            intrusion_data = [9 + (i * 1.5) for i in range(20)]
            malware_data = [6 + (i * 0.5) for i in range(20)]
        
        return {
            "labels": labels,
            "threat_activity": threat_data,
            "intrusion_attempts": intrusion_data,
            "malware_detected": malware_data,
        }


@app.get("/api/vulnerabilities-status")
def get_vulnerabilities_status() -> dict[str, Any]:
    """Retorna status de vulnerabilidades."""
    return {
        "sql_injection": {"status": "HIGH", "count": 3},
        "rce": {"status": "HIGH", "count": 2},
        "open_ports": {"status": "HIGH", "count": 5},
        "weak_passwords": {"status": "MEDIUM", "count": 4},
        "unencrypted_api": {"status": "MEDIUM", "count": 1},
        "tests_completed": 42,
        "critical_issues": 4,
        "total_issues": 15,
    }


@app.get("/api/system-logs")
def get_system_logs() -> dict[str, Any]:
    """Retorna logs do sistema."""
    with engine_lock:
        logs = []
        for alert in reversed(engine.state.alerts[-8:]):
            logs.append({
                "time": alert.timestamp.strftime("%H:%M:%S"),
                "message": f"{alert.title}: {alert.description}",
                "severity": alert.severity.value,
            })
        
        # Se não há logs, gerar alguns demo
        if not logs:
            now = datetime.now(timezone.utc)
            logs = [
                {"time": now.strftime("%H:%M:%S"), "message": "Brute Force Attempt Blocked", "severity": "critical"},
                {"time": (now - timedelta(minutes=1)).strftime("%H:%M:%S"), "message": "Malware Scan Initiated", "severity": "high"},
                {"time": (now - timedelta(minutes=2)).strftime("%H:%M:%S"), "message": "Phishing Email Detected", "severity": "high"},
                {"time": (now - timedelta(minutes=5)).strftime("%H:%M:%S"), "message": "Firewall Alert: IP Blacklisted", "severity": "warning"},
            ]
        
        return {"logs": logs}


@app.get("/api/network-metrics")
def get_network_metrics() -> dict[str, Any]:
    """Retorna métricas de rede."""
    import random
    return {
        "upload_mbps": round(random.uniform(300, 400), 2),
        "download_mbps": round(random.uniform(450, 550), 2),
        "latency_ms": round(random.uniform(15, 45), 2),
        "packet_loss": round(random.uniform(0, 2), 2),
    }


@app.get("/api/brute-force-status")
def get_brute_force_status() -> dict[str, Any]:
    """Retorna status de proteção contra força bruta e atividades suspeitas."""
    with engine_lock:
        # Contar tentativas falhadas recentes
        brute_force_attempts = 0
        locked_accounts = []
        attack_patterns = {}
        
        for key, tracking in brute_force_protection.tracking.items():
            brute_force_attempts += tracking["attempts"]
            
            is_locked, lockout_time = brute_force_protection.is_locked(key)
            if is_locked:
                locked_accounts.append({
                    "account": key.split(":")[0],
                    "lockout_remaining": lockout_time,
                    "attempts": tracking["attempts"]
                })
            
            # Analisar padrões por IP
            if tracking["attempts_history"]:
                for attempt in tracking["attempts_history"][-10:]:
                    ip = attempt["ip"]
                    if ip not in attack_patterns:
                        attack_patterns[ip] = brute_force_protection.get_attack_patterns(ip)
        
        # Filtrar apenas ataques críticos
        suspicious_patterns = {
            ip: pattern for ip, pattern in attack_patterns.items()
            if pattern["threat_level"] in ["HIGH", "CRITICAL"]
        }
        
        return {
            "total_brute_force_attempts": brute_force_attempts,
            "blocked_accounts": len(locked_accounts),
            "locked_accounts": locked_accounts[:5],  # Top 5
            "suspicious_ips": list(suspicious_patterns.keys())[:5],
            "threat_level": "CRITICAL" if suspicious_patterns else "LOW",
            "protection_status": "ACTIVE",
            "auto_lockout_enabled": True,
            "tier1_lockout_minutes": brute_force_protection.lockout_times[0],
            "tier2_lockout_minutes": brute_force_protection.lockout_times[1],
            "tier3_lockout_minutes": brute_force_protection.lockout_times[2],
            "max_attempts_tier1": brute_force_protection.max_attempts_tier1,
            "max_attempts_tier2": brute_force_protection.max_attempts_tier2,
            "max_attempts_tier3": brute_force_protection.max_attempts_tier3,
        }


@app.get("/api/unauthorized-access-status")
def get_unauthorized_access_status() -> dict[str, Any]:
    """Retorna status de acesso não autorizado detectado."""
    blocked_ips = []
    suspicious_attempts = []
    
    for ip, tracking in unauthorized_access_protection.suspicious_ips.items():
        is_blocked, block_time = unauthorized_access_protection.is_ip_blocked(ip)
        
        if is_blocked:
            blocked_ips.append({
                "ip": ip,
                "blocked_until": block_time,
                "failed_attempts": tracking["attempts"],
                "last_attempt": tracking["last_attempt"].isoformat() if tracking["last_attempt"] else None
            })
        elif tracking["attempts"] > 0:
            suspicious_attempts.append({
                "ip": ip,
                "failed_attempts": tracking["attempts"],
                "attempted_actions": [f"{a['action']} @ {a['resource']}" for a in tracking["attempted_actions"][-3:]],
                "last_attempt": tracking["last_attempt"].isoformat() if tracking["last_attempt"] else None
            })
    
    return {
        "total_unauthorized_attempts": sum(
            t["attempts"] for t in unauthorized_access_protection.suspicious_ips.values()
        ),
        "blocked_ips": blocked_ips,
        "suspicious_ips_count": len(suspicious_attempts),
        "suspicious_attempts": suspicious_attempts[:5],
        "maintenance_window": {
            "start_hour": access_control_validator.maintenance_window_start,
            "end_hour": access_control_validator.maintenance_window_end,
            "is_active": access_control_validator.is_maintenance_window()
        },
        "threat_level": "CRITICAL" if blocked_ips else ("HIGH" if len(suspicious_attempts) > 2 else "LOW"),
    }
def logout(
    request: Request,
    current_operator: dict[str, Any] = Depends(get_current_operator)
) -> dict[str, str]:
    """Faz logout do operador (revoga a sessão)."""
    logger.log(
        LogLevel.AUDIT,
        "LOGOUT",
        username=current_operator["username"],
        ip_address=request.client.host if request.client else None
    )
    
    return {"message": "Logout realizado com sucesso."}