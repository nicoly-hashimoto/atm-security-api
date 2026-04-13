#!/usr/bin/env python
"""
Teste completo dos sistemas de proteção:
1. Brute Force Protection
2. Unauthorized Access Protection
"""

import requests
import json
import time
from datetime import datetime

BASE_URL = "http://127.0.0.1:8000"

def print_section(title):
    print(f"\n{'='*70}")
    print(f"  {title}")
    print(f"{'='*70}\n")

def print_success(msg):
    print(f"✅ {msg}")

def print_warning(msg):
    print(f"⚠️  {msg}")

def print_error(msg):
    print(f"❌ {msg}")

def print_info(msg):
    print(f"ℹ️  {msg}")

print_section("TESTE COMPLETO - SISTEMA DE PROTEÇÃO ATM")

# ============================================================================
# TESTE 1: BRUTE FORCE PROTECTION
# ============================================================================
print_section("TESTE 1: PROTEÇÃO CONTRA BRUTE FORCE")

print_info("Testando múltiplas tentativas de login com senha errada...")
print("Usuário: admin")
print("Senha errada: wrongpassword\n")

failed_attempts = 0
token = None

for i in range(1, 6):
    try:
        response = requests.post(
            f"{BASE_URL}/auth/login",
            json={"username": "admin", "password": "wrongpassword"},
            timeout=5
        )
        
        if response.status_code == 401:
            failed_attempts += 1
            print(f"  Tentativa {i}: Status 401 - Falha de autenticação ✓")
        elif response.status_code == 429:
            print_error(f"  Tentativa {i}: Status 429 - IP BLOQUEADO (Rate limit)")
            break
        elif response.status_code == 403:
            print_error(f"  Tentativa {i}: Status 403 - CONTA BLOQUEADA (Brute force protection)")
            break
        else:
            print(f"  Tentativa {i}: Status {response.status_code}")
            
    except Exception as e:
        print_error(f"  Tentativa {i}: {str(e)}")

time.sleep(1)

# Verificar status de brute force
print("\n📍 Verificando status de Brute Force Protection...")
try:
    bf_response = requests.get(f"{BASE_URL}/api/brute-force-status", timeout=5)
    bf_data = bf_response.json()
    
    print(f"\n  Total de tentativas falhadas: {bf_data.get('total_failed_attempts', 0)}")
    print(f"  Nível de ameaça: {bf_data.get('threat_level', 'UNKNOWN')}")
    print(f"  Contas bloqueadas: {len(bf_data.get('locked_accounts', []))}")
    print(f"  IPs suspeitos: {len(bf_data.get('suspicious_ips', []))}")
    
    if bf_data.get('locked_accounts'):
        print("\n  🚫 CONTAS BLOQUEADAS:")
        for account in bf_data['locked_accounts']:
            print(f"    - {account.get('username')}: '{account.get('locked_until')}' ({account.get('failed_attempts')} tentativas)")
    
    if bf_data.get('suspicious_ips'):
        print("\n  ⚠️  IPs SUSPEITOS:")
        for ip in bf_data['suspicious_ips']:
            print(f"    - {ip.get('ip')}: {ip.get('failed_attempts')} tentativas, ameaça: {ip.get('threat_level')}")
            
except Exception as e:
    print_error(f"Erro ao buscar brute force status: {str(e)}")

# ============================================================================
# TESTE 2: UNAUTHORIZED ACCESS PROTECTION
# ============================================================================
print_section("TESTE 2: PROTEÇÃO CONTRA ACESSO NÃO AUTORIZADO")

print_info("Fazendo login como 'viewer' (permissão insuficiente para abrir cofre)...")

try:
    login_response = requests.post(
        f"{BASE_URL}/auth/login",
        json={"username": "viewer", "password": "viewer123"},
        timeout=5
    )
    
    if login_response.status_code == 200:
        token = login_response.json()['access_token']
        print_success("Login realizado com sucesso")
        print(f"Token obtido: {token[:20]}...\n")
    else:
        print_error(f"Falha no login: Status {login_response.status_code}")
        token = None
        
except Exception as e:
    print_error(f"Erro ao fazer login: {str(e)}")

if token:
    headers = {"Authorization": f"Bearer {token}"}
    
    print_info("Tentando abrir o cofre 3x com usuário 'viewer' (sem permissão)...\n")
    
    for i in range(1, 4):
        try:
            event_response = requests.post(
                f"{BASE_URL}/events",
                json={
                    "event_type": "SAFE_DOOR_OPENED",
                    "actor_id": "viewer",
                    "details": f"Tentativa {i} de abrir cofre sem autorização"
                },
                headers=headers,
                timeout=5
            )
            
            if event_response.status_code == 200:
                print(f"  Tentativa {i}: Status 200 - Aceito (não deveria!)")
            elif event_response.status_code == 403:
                print(f"  Tentativa {i}: Status 403 - BLOQUEADO ✓")
                error_detail = event_response.json().get('detail', 'Sem detalhes')
                print(f"      Razão: {error_detail}")
            else:
                print(f"  Tentativa {i}: Status {event_response.status_code}")
                
        except Exception as e:
            print_error(f"  Tentativa {i}: {str(e)}")
    
    time.sleep(1)
    
    # Verificar status de unauthorized access
    print("\n📍 Verificando status de Unauthorized Access Protection...")
    try:
        ua_response = requests.get(f"{BASE_URL}/api/unauthorized-access-status", timeout=5)
        ua_data = ua_response.json()
        
        print(f"\n  Total de tentativas não autorizadas: {ua_data.get('total_unauthorized_attempts', 0)}")
        print(f"  Nível de ameaça: {ua_data.get('threat_level', 'UNKNOWN')}")
        print(f"  IPs bloqueados: {len(ua_data.get('blocked_ips', []))}")
        print(f"  IPs suspeitos: {len(ua_data.get('suspicious_attempts', []))}")
        
        if ua_data.get('maintenance_window'):
            mw = ua_data['maintenance_window']
            status = "ATIVA" if mw.get('is_active') else "INATIVA"
            print(f"  Janela de manutenção: {mw.get('start_hour')}:00 - {mw.get('end_hour')}:00 ({status})")
        
        if ua_data.get('blocked_ips'):
            print("\n  🚫 IPs BLOQUEADOS:")
            for ip_block in ua_data['blocked_ips']:
                print(f"    - {ip_block.get('ip')}: Bloqueado por {ip_block.get('blocked_until')} ({ip_block.get('failed_attempts')} tentativas)")
        
        if ua_data.get('suspicious_attempts'):
            print("\n  ⚠️  IPs SUSPEITOS:")
            for susp in ua_data['suspicious_attempts']:
                print(f"    - {susp.get('ip')}: {susp.get('failed_attempts')} tentativas")
                if susp.get('attempted_actions'):
                    print(f"      Ações: {', '.join(susp['attempted_actions'][:3])}")
                    
    except Exception as e:
        print_error(f"Erro ao buscar unauthorized access status: {str(e)}")

# ============================================================================
# TESTE 3: VERIFICAR ALERTS E LOGS
# ============================================================================
print_section("TESTE 3: VERIFICAR ALERTS E LOGS DO SISTEMA")

try:
    alerts_response = requests.get(f"{BASE_URL}/alerts", timeout=5)
    alerts_data = alerts_response.json()
    
    print(f"Total de alertas no sistema: {len(alerts_data)}\n")
    
    # Mostrar últimos 5 alertas
    for alert in alerts_data[-5:]:
        severity_icon = {
            "CRITICAL": "🔴",
            "HIGH": "🟠",
            "MEDIUM": "🟡",
            "LOW": "🟢"
        }.get(alert.get('severity'), "⚪")
        
        print(f"{severity_icon} [{alert.get('severity')}] {alert.get('title')}")
        print(f"   {alert.get('description')}")
        print()
        
except Exception as e:
    print_error(f"Erro ao buscar alertas: {str(e)}")

# ============================================================================
# RESUMO GERAL
# ============================================================================
print_section("RESUMO DO TESTE")

print("""
✓ Testes de Brute Force Protection:
  - Múltiplas tentativas de login com senha errada
  - Verificação de bloqueio progressivo
  - Status de contas e IPs bloqueados

✓ Testes de Unauthorized Access Protection:
  - Tentativas de abrir cofre sem permissão
  - Verificação de bloqueio por IP
  - Monitoramento de IPs suspeitos

✓ Integração de Alertas:
  - Eventos críticos registrados
  - Logs do sistema atualizados
  - Dashboard alimentado com dados em tempo real

🔍 Próximos passos:
  - Monitorar o dashboard para visualizar todos os eventos
  - Verificar auto-atualização a cada 3 segundos
  - Confirmar que proteções estão ativas
""")

print(f"\n⏰ Teste concluído em: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
print(f"📊 Acesse o dashboard: {BASE_URL}\n")
