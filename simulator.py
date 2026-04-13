"""
ATM Security API - Simulador de Testes em Tempo Real
Testa a API automaticamente enviando eventos realistas e monitorando respostas
"""

import asyncio
import json
import time
from datetime import datetime
from typing import Optional
import httpx
from enum import Enum

# Configuração
API_URL = "http://127.0.0.1:8000"
DEFAULT_USERNAME = "operator"
DEFAULT_PASSWORD = "admin123"

class Color:
    """ANSI Color codes for terminal output"""
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    MAGENTA = '\033[95m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    END = '\033[0m'

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

class Simulator:
    def __init__(self, username: str = DEFAULT_USERNAME, password: str = DEFAULT_PASSWORD):
        self.api_url = API_URL
        self.username = username
        self.password = password
        self.token: Optional[str] = None
        self.session_data = {}
        self.stats = {
            "events_sent": 0,
            "alerts_generated": 0,
            "errors": 0,
            "login_success": False
        }

    async def login(self) -> bool:
        """Login na API e obter token"""
        print(f"\n{Color.CYAN}[LOGIN]{Color.END} Tentando autenticar como {Color.BOLD}{self.username}{Color.END}...")
        
        async with httpx.AsyncClient() as client:
            try:
                response = await client.post(
                    f"{self.api_url}/auth/login",
                    json={"username": self.username, "password": self.password}
                )
                
                if response.status_code == 200:
                    data = response.json()
                    self.token = data["access_token"]
                    self.session_data = {
                        "name": data["operator_name"],
                        "role": data["role"],
                        "permissions": data["permissions"]
                    }
                    self.stats["login_success"] = True
                    print(f"{Color.GREEN}✓ Login bem-sucedido!{Color.END}")
                    print(f"  Nome: {Color.BOLD}{data['operator_name']}{Color.END}")
                    print(f"  Role: {Color.BOLD}{data['role']}{Color.END}")
                    print(f"  Permissões: {', '.join(data['permissions'])}")
                    return True
                else:
                    print(f"{Color.RED}✗ Falha no login: {response.json()}{Color.END}")
                    self.stats["errors"] += 1
                    return False
                    
            except Exception as e:
                print(f"{Color.RED}✗ Erro de conexão: {e}{Color.END}")
                self.stats["errors"] += 1
                return False

    async def get_snapshot(self) -> Optional[dict]:
        """Obter snapshot do estado atual"""
        async with httpx.AsyncClient() as client:
            try:
                headers = {"Authorization": f"Bearer {self.token}"}
                response = await client.get(f"{self.api_url}/snapshot", headers=headers)
                return response.json() if response.status_code == 200 else None
            except:
                return None

    async def send_event(
        self,
        event_type: EventType,
        actor_id: str = "SIM001",
        value: Optional[float] = None,
        details: str = ""
    ) -> bool:
        """Enviar um evento para a API"""
        
        async with httpx.AsyncClient() as client:
            try:
                headers = {"Authorization": f"Bearer {self.token}"}
                payload = {
                    "event_type": event_type.value,
                    "actor_id": actor_id,
                    "details": details
                }
                if value is not None:
                    payload["value"] = value
                
                response = await client.post(
                    f"{self.api_url}/events",
                    json=payload,
                    headers=headers
                )
                
                self.stats["events_sent"] += 1
                
                if response.status_code == 200:
                    data = response.json()
                    alerts_count = len(data.get("generated_alerts", []))
                    self.stats["alerts_generated"] += alerts_count
                    
                    timestamp = datetime.now().strftime("%H:%M:%S")
                    print(f"{Color.BLUE}[{timestamp}]{Color.END} " +
                          f"{Color.BOLD}{event_type.value.upper()}{Color.END} » " +
                          f"Actor: {Color.CYAN}{actor_id}{Color.END} | " +
                          f"Alertas: {Color.YELLOW}{alerts_count}{Color.END}")
                    
                    if alerts_count > 0:
                        for alert in data["generated_alerts"]:
                            severity_color = self._get_severity_color(alert["severity"])
                            print(f"  ⚠️  {severity_color}{alert['severity'].upper()}{Color.END}: {alert['title']}")
                    
                    return True
                else:
                    print(f"{Color.RED}✗ Erro ao enviar evento: {response.json()}{Color.END}")
                    self.stats["errors"] += 1
                    return False
                    
            except Exception as e:
                print(f"{Color.RED}✗ Exceção: {e}{Color.END}")
                self.stats["errors"] += 1
                return False

    async def scenario_basic_operation(self):
        """Cenário 1: Operação Normal - Cartão inserido e PIN verificado"""
        print(f"\n{Color.MAGENTA}{'='*60}")
        print(f"CENÁRIO 1: Operação Normal (Cartão + PIN)".center(60))
        print(f"{'='*60}{Color.END}\n")
        
        await self.send_event(
            EventType.CARD_INSERTED,
            actor_id="CARD_001",
            details="Cartão bancário inserido"
        )
        await asyncio.sleep(1)
        
        await self.send_event(
            EventType.PIN_VERIFIED,
            actor_id="CUSTOMER_A",
            details="PIN verificado com sucesso"
        )
        await asyncio.sleep(1)

    async def scenario_pin_attack(self):
        """Cenário 2: Tentativa de PIN - Força Bruta"""
        print(f"\n{Color.MAGENTA}{'='*60}")
        print(f"CENÁRIO 2: Ataque de Força Bruta (3x PIN Falha)".center(60))
        print(f"{'='*60}{Color.END}\n")
        
        for i in range(3):
            await self.send_event(
                EventType.PIN_FAILED,
                actor_id="ATTACKER_01",
                details=f"Tentativa {i+1} de PIN incorreto"
            )
            await asyncio.sleep(0.5)

    async def scenario_safe_breach(self):
        """Cenário 3: Abertura não autorizada do cofre"""
        print(f"\n{Color.MAGENTA}{'='*60}")
        print(f"CENÁRIO 3: Abertura Não Autorizada do Cofre".center(60))
        print(f"{'='*60}{Color.END}\n")
        
        # Tentar abrir o cofre sem estar em modo de manutenção
        await self.send_event(
            EventType.SAFE_DOOR_OPENED,
            actor_id="UNKNOWN_001",
            details="Cofre aberto sem autorização"
        )
        await asyncio.sleep(1)

    async def scenario_maintenance_authorized(self):
        """Cenário 4: Manutenção autorizada"""
        print(f"\n{Color.MAGENTA}{'='*60}")
        print(f"CENÁRIO 4: Manutenção Autorizada (02:00-05:00)".center(60))
        print(f"{'='*60}{Color.END}\n")
        
        await self.send_event(
            EventType.MAINTENANCE_MODE_ENABLED,
            actor_id="TECH_001",
            details="Modo de manutenção ativado"
        )
        await asyncio.sleep(1)
        
        await self.send_event(
            EventType.SAFE_DOOR_OPENED,
            actor_id="TECH_001",
            details="Cofre aberto durante manutenção autorizada"
        )
        await asyncio.sleep(1)
        
        await self.send_event(
            EventType.CASH_REPLENISHED,
            actor_id="TECH_001",
            value=5000.00,
            details="Dinheiro reabastecido"
        )

    async def scenario_network_issue(self):
        """Cenário 5: Problema de rede"""
        print(f"\n{Color.MAGENTA}{'='*60}")
        print(f"CENÁRIO 5: Falha de Conexão de Rede".center(60))
        print(f"{'='*60}{Color.END}\n")
        
        await self.send_event(
            EventType.NETWORK_OFFLINE,
            actor_id="SYSTEM",
            details="Conexão com a central perdida"
        )
        await asyncio.sleep(2)
        
        await self.send_event(
            EventType.NETWORK_ONLINE,
            actor_id="SYSTEM",
            details="Conexão restaurada"
        )

    async def scenario_stress_test(self, num_events: int = 10):
        """Cenário 6: Teste de stress - Múltiplos eventos rápidos"""
        print(f"\n{Color.MAGENTA}{'='*60}")
        print(f"CENÁRIO 6: Teste de Stress ({num_events} eventos)".center(60))
        print(f"{'='*60}{Color.END}\n")
        
        event_types = [
            EventType.CARD_INSERTED,
            EventType.PIN_VERIFIED,
            EventType.VIBRATION_DETECTED,
        ]
        
        for i in range(num_events):
            event_type = event_types[i % len(event_types)]
            await self.send_event(
                event_type,
                actor_id=f"STRESS_{i:03d}",
                details=f"Evento de teste #{i+1}"
            )
            await asyncio.sleep(0.2)

    async def print_status(self):
        """Imprimir status atual do sistema"""
        snapshot = await self.get_snapshot()
        
        if not snapshot:
            print(f"{Color.RED}✗ Não foi possível obter status{Color.END}")
            return
        
        state = snapshot["state"]
        risk_level = snapshot["risk_level"]
        alerts = snapshot["alerts"]
        
        print(f"\n{Color.CYAN}{'='*60}")
        print(f"STATUS ATUAL DO SISTEMA".center(60))
        print(f"{'='*60}{Color.END}")
        
        # Risk Level
        risk_color = self._get_severity_color(risk_level)
        print(f"\n📊 Nível de Risco: {risk_color}{risk_level.upper()}{Color.END}")
        
        # Métricas
        print(f"\n📈 Métricas:")
        print(f"  • Falhas de PIN: {Color.YELLOW}{state['pin_failures']}{Color.END}")
        print(f"  • Rede: {Color.GREEN if state['network_online'] else Color.RED}" +
              f"{'🟢 ONLINE' if state['network_online'] else '🔴 OFFLINE'}{Color.END}")
        print(f"  • Cofre: {Color.RED if state['safe_open'] else Color.GREEN}" +
              f"{'🔴 ABERTO' if state['safe_open'] else '🟢 FECHADO'}{Color.END}")
        print(f"  • Manutenção: {Color.YELLOW if state['maintenance_mode'] else Color.GREEN}" +
              f"{'🟡 ATIVA' if state['maintenance_mode'] else '🟢 INATIVA'}{Color.END}")
        
        # Alertas recentes
        if alerts:
            print(f"\n🚨 Alertas Recentes ({len(alerts)}):")
            for alert in alerts[-5:]:
                severity_color = self._get_severity_color(alert["severity"])
                timestamp = alert["timestamp"][-8:]
                print(f"  {severity_color}▸{Color.END} [{timestamp}] {alert['title']}")
        else:
            print(f"\n{Color.GREEN}✓ Nenhum alerta ativo{Color.END}")

    def print_stats(self):
        """Imprimir estatísticas do teste"""
        print(f"\n{Color.CYAN}{'='*60}")
        print(f"ESTATÍSTICAS DE TESTE".center(60))
        print(f"{'='*60}{Color.END}\n")
        
        print(f"Login: {Color.GREEN if self.stats['login_success'] else Color.RED}" +
              f"{'✓ OK' if self.stats['login_success'] else '✗ FALHOU'}{Color.END}")
        print(f"Eventos Enviados: {Color.BOLD}{self.stats['events_sent']}{Color.END}")
        print(f"Alertas Gerados: {Color.BOLD}{self.stats['alerts_generated']}{Color.END}")
        print(f"Erros: {Color.RED if self.stats['errors'] > 0 else Color.GREEN}" +
              f"{self.stats['errors']}{Color.END}")
        
        if self.stats['events_sent'] > 0:
            avg_alerts = self.stats['alerts_generated'] / self.stats['events_sent']
            print(f"Média de Alertas/Evento: {Color.BOLD}{avg_alerts:.2f}{Color.END}")

    def _get_severity_color(self, severity: str) -> str:
        """Retornar cor da severidade"""
        colors = {
            "critical": Color.RED,
            "high": Color.MAGENTA,
            "medium": Color.YELLOW,
            "low": Color.GREEN
        }
        return colors.get(severity.lower(), Color.WHITE)

    async def run_all_scenarios(self):
        """Executar todos os cenários de teste"""
        print(f"\n{Color.BOLD}{Color.GREEN}")
        print("╔════════════════════════════════════════════════════════════╗")
        print("║     ATM SECURITY API - SIMULADOR DE TESTES COMPLETO       ║")
        print("╚════════════════════════════════════════════════════════════╝")
        print(f"{Color.END}")
        
        if not await self.login():
            print(f"\n{Color.RED}Teste abortado - login falhou{Color.END}")
            return
        
        try:
            # Executar cenários
            await self.scenario_basic_operation()
            await asyncio.sleep(2)
            
            await self.scenario_pin_attack()
            await asyncio.sleep(2)
            
            await self.scenario_safe_breach()
            await asyncio.sleep(2)
            
            await self.scenario_maintenance_authorized()
            await asyncio.sleep(2)
            
            await self.scenario_network_issue()
            await asyncio.sleep(2)
            
            await self.scenario_stress_test(10)
            await asyncio.sleep(2)
            
            # Mostrar status final
            await self.print_status()
            
            # Mostrar estatísticas
            self.print_stats()
            
            print(f"\n{Color.GREEN}✓ TODOS OS CENÁRIOS EXECUTADOS COM SUCESSO{Color.END}\n")
            
        except KeyboardInterrupt:
            print(f"\n\n{Color.YELLOW}Teste interrompido pelo usuário{Color.END}")
            self.print_stats()

async def interactive_mode(simulator: Simulator):
    """Modo interativo - permitir enviar eventos manualmente"""
    print(f"\n{Color.CYAN}{'='*60}")
    print(f"MODO INTERATIVO".center(60))
    print(f"{'='*60}{Color.END}\n")
    
    print("Tipos de eventos disponíveis:")
    for i, event_type in enumerate(EventType, 1):
        print(f"  {i}. {event_type.value}")
    
    print("\nComandos:")
    print("  s - Ver status atual")
    print("  exit - Sair")
    print()
    
    while True:
        try:
            choice = input(f"{Color.BOLD}Escolha um evento (1-9) ou comando: {Color.END}").strip()
            
            if choice.lower() == "exit":
                break
            elif choice.lower() == "s":
                await simulator.print_status()
            elif choice.isdigit():
                event_num = int(choice)
                if 1 <= event_num <= len(EventType):
                    event_type = list(EventType)[event_num - 1]
                    actor_id = input("Actor ID (default: SIM001): ").strip() or "SIM001"
                    details = input("Detalhes (opcional): ").strip() or ""
                    
                    await simulator.send_event(event_type, actor_id, details=details)
                    await simulator.print_status()
                else:
                    print(f"{Color.RED}Opção inválida{Color.END}")
            else:
                print(f"{Color.RED}Comando não reconhecido{Color.END}")
                
        except KeyboardInterrupt:
            break
    
    simulator.print_stats()

async def main():
    """Função principal"""
    import sys
    
    simulator = Simulator()
    
    # Checks argument for mode
    if len(sys.argv) > 1 and sys.argv[1] == "interactive":
        if await simulator.login():
            await interactive_mode(simulator)
    else:
        await simulator.run_all_scenarios()

if __name__ == "__main__":
    asyncio.run(main())
