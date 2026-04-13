"""
Módulo de Segurança Aprimorada
Implementa: Rate Limiting, Logging, Validação, CORS, etc.
"""

from datetime import datetime, timedelta
from typing import Dict, Optional
import json
import os
from pathlib import Path
from collections import defaultdict
from enum import Enum


class LogLevel(str, Enum):
    """Níveis de log de auditoria."""
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"
    AUDIT = "AUDIT"


class SecurityLogger:
    """
    Sistema de logging estruturado para auditoria.
    Registra todas as ações sensíveis com timestamp, usuário e detalhes.
    """
    
    def __init__(self, log_dir: str = "./logs"):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(exist_ok=True)
        
        # Arquivo de log atual
        today = datetime.now().strftime("%Y-%m-%d")
        self.log_file = self.log_dir / f"audit_{today}.jsonl"
    
    def log(
        self,
        level: LogLevel,
        event: str,
        username: Optional[str] = None,
        details: Optional[Dict] = None,
        ip_address: Optional[str] = None
    ):
        """
        Registra um evento de auditoria.
        
        Args:
            level: Nível de severidade
            event: Descrição do evento (ex: "LOGIN_SUCCESS", "EVENT_CREATED")
            username: Usuário envolvido
            details: Dados adicionais do evento
            ip_address: IP de origem da requisição
        """
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "level": level.value,
            "event": event,
            "username": username,
            "ip_address": ip_address,
            "details": details or {}
        }
        
        # Escrever em arquivo (JSON Lines format)
        with open(self.log_file, "a") as f:
            f.write(json.dumps(log_entry) + "\n")
    
    def login_attempt(self, username: str, success: bool, ip_address: Optional[str] = None):
        """Log de tentativa de login."""
        level = LogLevel.AUDIT if success else LogLevel.WARNING
        event = "LOGIN_SUCCESS" if success else "LOGIN_FAILED"
        self.log(level, event, username=username, ip_address=ip_address)
    
    def api_call(
        self,
        username: Optional[str],
        method: str,
        endpoint: str,
        status_code: int,
        ip_address: Optional[str] = None
    ):
        """Log de chamada de API."""
        level = LogLevel.AUDIT if status_code < 400 else LogLevel.WARNING
        event = f"{method}_{endpoint.replace('/', '_').upper()}"
        details = {"method": method, "endpoint": endpoint, "status_code": status_code}
        self.log(level, event, username=username, details=details, ip_address=ip_address)
    
    def permission_denied(self, username: str, endpoint: str, ip_address: Optional[str] = None):
        """Log de acesso negado."""
        self.log(
            LogLevel.WARNING,
            "PERMISSION_DENIED",
            username=username,
            details={"endpoint": endpoint},
            ip_address=ip_address
        )
    
    def admin_action(
        self,
        admin_username: str,
        action: str,
        target: Optional[str] = None,
        details: Optional[Dict] = None,
        ip_address: Optional[str] = None
    ):
        """Log de ação administrativa."""
        log_details = {"action": action, "target": target}
        if details:
            log_details.update(details)
        
        self.log(
            LogLevel.AUDIT,
            f"ADMIN_{action}",
            username=admin_username,
            details=log_details,
            ip_address=ip_address
        )


class RateLimiter:
    """
    Rate limiter em memória com chaves baseadas em IP ou username.
    Protege contra força bruta em login.
    """
    
    def __init__(self):
        # {key: [(timestamp, count), ...]}
        self.attempts: Dict[str, list] = defaultdict(list)
        self.max_attempts = 5  # 5 tentativas
        self.window_minutes = 1  # por minuto
    
    def check_rate_limit(self, key: str) -> bool:
        """
        Verifica se a chave excedeu o rate limit.
        
        Args:
            key: IP, username ou combinação para rate limit
        
        Returns:
            True se está dentro do limite, False se excedeu
        """
        now = datetime.now()
        cutoff = now - timedelta(minutes=self.window_minutes)
        
        # Remove tentativas antigas
        self.attempts[key] = [
            (ts, count) for ts, count in self.attempts[key]
            if ts > cutoff
        ]
        
        # Conta tentativas recentes
        total_attempts = sum(count for _, count in self.attempts[key])
        
        if total_attempts >= self.max_attempts:
            return False
        
        # Registra tentativa nova
        self.attempts[key].append((now, 1))
        return True
    
    def reset(self, key: str):
        """Reseta tentativas para uma chave (após login bem-sucedido)."""
        if key in self.attempts:
            del self.attempts[key]


class InputValidator:
    """
    Validação rigorosa de entrada para prevenir injeções.
    """
    
    # Caracteres permitidos em nomes/IDs
    SAFE_CHARS = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.")
    
    @staticmethod
    def validate_username(username: str, min_len: int = 3, max_len: int = 32) -> bool:
        """Valida username."""
        if not username or len(username) < min_len or len(username) > max_len:
            return False
        return all(c in InputValidator.SAFE_CHARS for c in username)
    
    @staticmethod
    def validate_password(password: str, min_len: int = 8) -> bool:
        """Valida força de senha."""
        if not password or len(password) < min_len:
            return False
        
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        
        # Exigir maiúscula, minúscula e número
        return has_upper and has_lower and has_digit
    
    @staticmethod
    def validate_actor_id(actor_id: str, max_len: int = 50) -> bool:
        """Valida actor_id para evitar injeções."""
        if not actor_id or len(actor_id) > max_len:
            return False
        # Permitir mais caracteres para IDs mas evitar null bytes e newlines
        return "\x00" not in actor_id and "\n" not in actor_id
    
    @staticmethod
    def validate_details(details: str, max_len: int = 500) -> bool:
        """Valida campo de detalhes."""
        if not isinstance(details, str):
            return False
        if len(details) > max_len:
            return False
        # Evitar null bytes e controle de caracteres perigosos
        return all(ord(c) >= 32 or c in "\t\n\r" for c in details)
    
    @staticmethod
    def validate_role(role: str, allowed_roles: list) -> bool:
        """Valida role contra lista permitida."""
        return role in allowed_roles


class SessionManager:
    """
    Gerenciador de sessões com timeout e revogação.
    """
    
    def __init__(self, timeout_minutes: int = 30):
        self.timeout = timedelta(minutes=timeout_minutes)
        self.sessions: Dict[str, Dict] = {}  # {token: session_info}
    
    def create_session(self, token: str, username: str, ip_address: str):
        """Cria uma nova sessão."""
        self.sessions[token] = {
            "username": username,
            "ip_address": ip_address,
            "created_at": datetime.now(),
            "last_activity": datetime.now(),
            "revoked": False
        }
    
    def validate_session(self, token: str, current_ip: str) -> bool:
        """Valida se sessão é válida e não expirou."""
        if token not in self.sessions:
            return False
        
        session = self.sessions[token]
        
        # Revogada?
        if session["revoked"]:
            return False
        
        # Expirou?
        elapsed = datetime.now() - session["created_at"]
        if elapsed > self.timeout:
            return False
        
        # IP mudou? (opcional - comentado para flexibilidade)
        # if session["ip_address"] != current_ip:
        #     return False
        
        # Atualiza last_activity
        session["last_activity"] = datetime.now()
        return True
    
    def revoke_session(self, token: str):
        """Revoga uma sessão (logout)."""
        if token in self.sessions:
            self.sessions[token]["revoked"] = True
    
    def revoke_user_sessions(self, username: str):
        """Revoga todas as sessões de um usuário (logout em outro lugar)."""
        for token, session in self.sessions.items():
            if session["username"] == username:
                session["revoked"] = True


class BruteForceProtection:
    """
    Proteção avançada contra ataque de força bruta com lockout adaptativo.
    Implementa: bloqueio progressivo, detecção de padrões, alertas.
    """
    
    def __init__(self):
        # {key: {"attempts": int, "locked_until": datetime, "attempts_history": []}}
        self.tracking: Dict[str, dict] = defaultdict(lambda: {
            "attempts": 0,
            "locked_until": None,
            "attempts_history": [],
            "blocked_ips": []
        })
        
        # Configurações
        self.max_attempts_tier1 = 3      # 3 tentativas = bloqueio 5 min
        self.max_attempts_tier2 = 6      # 6 tentativas = bloqueio 15 min  
        self.max_attempts_tier3 = 10     # 10 tentativas = bloqueio 60 min
        self.lockout_times = {
            0: 5,    # 5 minutos
            1: 15,   # 15 minutos
            2: 60,   # 1 hora
        }
    
    def is_locked(self, key: str) -> tuple[bool, Optional[str]]:
        """Verifica se uma chave está bloqueada e por quanto tempo."""
        if key not in self.tracking:
            return False, None
        
        locked_until = self.tracking[key]["locked_until"]
        if not locked_until:
            return False, None
        
        now = datetime.now()
        if now >= locked_until:
            # Desbloqueou, reseta
            self.tracking[key] = {
                "attempts": 0,
                "locked_until": None,
                "attempts_history": [],
                "blocked_ips": []
            }
            return False, None
        
        remaining = (locked_until - now).total_seconds() / 60
        return True, f"{int(remaining)}m"
    
    def record_failed_attempt(self, key: str, ip: str) -> dict[str, Any]:
        """
        Registra tentativa falhada e decide se bloqueia.
        
        Returns:
            {
                "blocked": bool,
                "lockout_minutes": int | None,
                "attempt_count": int,
                "next_tier": bool
            }
        """
        tracking = self.tracking[key]
        tracking["attempts"] += 1
        tracking["attempts_history"].append({
            "timestamp": datetime.now(),
            "ip": ip
        })
        
        # Manter apenas últimas 20 tentativas
        if len(tracking["attempts_history"]) > 20:
            tracking["attempts_history"] = tracking["attempts_history"][-20:]
        
        attempt_count = tracking["attempts"]
        
        # Determinar nível de bloqueio
        tier = -1
        lockout_minutes = None
        
        if attempt_count >= self.max_attempts_tier3:
            tier = 2
            lockout_minutes = self.lockout_times[2]
        elif attempt_count >= self.max_attempts_tier2:
            tier = 1
            lockout_minutes = self.lockout_times[1]
        elif attempt_count >= self.max_attempts_tier1:
            tier = 0
            lockout_minutes = self.lockout_times[0]
        
        if tier >= 0:
            tracking["locked_until"] = datetime.now() + timedelta(minutes=lockout_minutes)
            return {
                "blocked": True,
                "lockout_minutes": lockout_minutes,
                "attempt_count": attempt_count,
                "next_tier": tier < 2
            }
        
        return {
            "blocked": False,
            "lockout_minutes": None,
            "attempt_count": attempt_count,
            "next_tier": False
        }
    
    def record_successful_attempt(self, key: str):
        """Reseta contadores após sucesso."""
        if key in self.tracking:
            self.tracking[key] = {
                "attempts": 0,
                "locked_until": None,
                "attempts_history": [],
                "blocked_ips": []
            }
    
    def get_attack_patterns(self, ip: str) -> dict[str, Any]:
        """Analisa padrões de ataque de um IP."""
        patterns = {
            "total_attempts": 0,
            "failed_ips": [],
            "timestamp_pattern": [],
            "is_distributed": False,
            "threat_level": "LOW"
        }
        
        for key, tracking in self.tracking.items():
            for attempt in tracking["attempts_history"]:
                if attempt["ip"] == ip:
                    patterns["total_attempts"] += 1
                    patterns["timestamp_pattern"].append(attempt["timestamp"])
        
        # Detectar ataque distribuído
        unique_ips = {}
        for key, tracking in self.tracking.items():
            for attempt in tracking["attempts_history"]:
                unique_ips[attempt["ip"]] = unique_ips.get(attempt["ip"], 0) + 1
        
        patterns["failed_ips"] = [ip_addr for ip_addr, count in unique_ips.items() if count > 2]
        patterns["is_distributed"] = len(patterns["failed_ips"]) > 3
        
        # Determinar nível de ameaça
        if patterns["total_attempts"] > 20:
            patterns["threat_level"] = "CRITICAL"
        elif patterns["total_attempts"] > 10:
            patterns["threat_level"] = "HIGH"
        elif patterns["is_distributed"]:
            patterns["threat_level"] = "HIGH"
        elif patterns["total_attempts"] > 5:
            patterns["threat_level"] = "MEDIUM"
        
        return patterns


class UnauthorizedAccessProtection:
    """
    Sistema de proteção contra acesso não autorizado.
    Monitora e bloqueia tentativas de acesso a recursos protegidos.
    """
    
    def __init__(self):
        # {ip: {"attempts": int, "blocked_until": datetime, "last_attempt": datetime}}
        self.suspicious_ips: Dict[str, dict] = defaultdict(lambda: {
            "attempts": 0,
            "blocked_until": None,
            "last_attempt": None,
            "attempted_actions": []
        })
        
        self.max_unauthorized_attempts = 3
        self.block_duration_minutes = 30
    
    def is_ip_blocked(self, ip: str) -> tuple[bool, Optional[str]]:
        """Verifica se um IP está bloqueado por acesso não autorizado."""
        if ip not in self.suspicious_ips:
            return False, None
        
        blocked_until = self.suspicious_ips[ip]["blocked_until"]
        if not blocked_until:
            return False, None
        
        now = datetime.now()
        if now >= blocked_until:
            # Desbloqueou
            self.suspicious_ips[ip]["attempts"] = 0
            self.suspicious_ips[ip]["blocked_until"] = None
            return False, None
        
        remaining = (blocked_until - now).total_seconds() / 60
        return True, f"{int(remaining)}m"
    
    def record_unauthorized_attempt(self, ip: str, action: str, resource: str) -> dict[str, Any]:
        """
        Registra tentativa de acesso não autorizado.
        
        Returns:
            {
                "blocked": bool,
                "block_duration": int | None,
                "attempt_count": int
            }
        """
        tracking = self.suspicious_ips[ip]
        tracking["attempts"] += 1
        tracking["last_attempt"] = datetime.now()
        tracking["attempted_actions"].append({
            "action": action,
            "resource": resource,
            "timestamp": datetime.now()
        })
        
        # Manter apenas últimas 10 tentativas
        if len(tracking["attempted_actions"]) > 10:
            tracking["attempted_actions"] = tracking["attempted_actions"][-10:]
        
        if tracking["attempts"] >= self.max_unauthorized_attempts:
            tracking["blocked_until"] = datetime.now() + timedelta(minutes=self.block_duration_minutes)
            return {
                "blocked": True,
                "block_duration": self.block_duration_minutes,
                "attempt_count": tracking["attempts"]
            }
        
        return {
            "blocked": False,
            "block_duration": None,
            "attempt_count": tracking["attempts"]
        }
    
    def reset_ip(self, ip: str):
        """Reseta contadores de um IP após autenticação bem-sucedida."""
        if ip in self.suspicious_ips:
            self.suspicious_ips[ip] = {
                "attempts": 0,
                "blocked_until": None,
                "last_attempt": None,
                "attempted_actions": []
            }


class AccessControlValidator:
    """
    Valida permissões e controla acesso a recursos sensíveis como cofre.
    """
    
    def __init__(self):
        self.maintenance_window_start = 2    # 02:00
        self.maintenance_window_end = 5      # 05:00
    
    def is_maintenance_window(self, hour: Optional[int] = None) -> bool:
        """Verifica se está dentro da janela de manutenção (02:00-05:00)."""
        if hour is None:
            hour = datetime.now().hour
        
        if self.maintenance_window_start <= self.maintenance_window_end:
            return self.maintenance_window_start <= hour < self.maintenance_window_end
        else:
            return hour >= self.maintenance_window_start or hour < self.maintenance_window_end
    
    def can_access_safe(
        self,
        role: str,
        is_maintenance_authorized: bool,
        maintenance_window_active: bool = None
    ) -> tuple[bool, str]:
        """
        Verifica se pode acessar o cofre.
        
        Returns:
            (can_access: bool, reason: str)
        """
        if maintenance_window_active is None:
            maintenance_window_active = self.is_maintenance_window()
        
        # Admin sempre pode (em manutenção)
        if role == "admin" and maintenance_window_active:
            return True, "ADMIN_MAINTENANCE"
        
        # Operadores precisam estar em janela de manutenção + autorização
        if role == "operator":
            if maintenance_window_active and is_maintenance_authorized:
                return True, "OPERATOR_AUTHORIZED"
            elif maintenance_window_active:
                return False, "MAINTENANCE_MODE_ACTIVE_NO_AUTHORIZATION"
            else:
                return False, "OUTSIDE_MAINTENANCE_WINDOW"
        
        # Viewers nunca podem acessar cofre
        if role == "viewer":
            return False, "VIEWER_NO_ACCESS"
        
        return False, "UNKNOWN_ROLE"
    
    def validate_safe_door_access(
        self,
        operator: dict[str, Any],
        is_authorized: bool,
        ip_address: str
    ) -> tuple[bool, str]:
        """
        Valida acesso completo ao cofre com todas as verificações.
        """
        can_access, reason = self.can_access_safe(
            operator["role"],
            is_authorized
        )
        
        if not can_access:
            return False, reason
        
        return True, "ACCESS_GRANTED"


# Instâncias globais
logger = SecurityLogger()
rate_limiter = RateLimiter()
validator = InputValidator()
session_manager = SessionManager(timeout_minutes=30)
brute_force_protection = BruteForceProtection()
unauthorized_access_protection = UnauthorizedAccessProtection()
access_control_validator = AccessControlValidator()
