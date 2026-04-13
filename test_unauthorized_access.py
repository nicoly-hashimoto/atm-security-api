#!/usr/bin/env python
"""Test unauthorized access protection"""

import requests
import json
import time

print('=== Testando Proteção de Acesso Não Autorizado ===\n')

# Primeiro, fazer login para obter token
auth_data = {'username': 'viewer', 'password': 'viewer123'}
login_resp = requests.post('http://127.0.0.1:8000/auth/login', json=auth_data)
token = login_resp.json()['access_token']
headers = {'Authorization': f'Bearer {token}'}

print('✓ Login realizado como: viewer')
print('✓ Token obtido\n')

# Tentar abrir o cofre com permissão insuficiente (viewer não tem permissão)
print('📍 Tentando abrir cofre 3x com usuário viewer (sem permissão)...')
for i in range(3):
    event = {
        'event_type': 'SAFE_DOOR_OPENED',
        'actor_id': 'viewer',
        'details': f'Tentativa {i+1} de abrir cofre sem autorização'
    }
    resp = requests.post('http://127.0.0.1:8000/events', json=event, headers=headers)
    print(f'  Tentativa {i+1}: Status {resp.status_code}')
    if resp.status_code != 200:
        try:
            print(f'    → {resp.json()}')
        except:
            print(f'    → {resp.text}')

print('\n⏳ Aguardando 1 segundo...\n')
time.sleep(1)

# Verificar status de acesso não autorizado
print('🔍 Status de Acesso Não Autorizado:')
status_resp = requests.get('http://127.0.0.1:8000/api/unauthorized-access-status')
status = status_resp.json()

print(f'  Total de tentativas: {status["total_unauthorized_attempts"]}')
print(f'  Nível de ameaça: {status["threat_level"]}')
print(f'  IPs bloqueados: {len(status["blocked_ips"])}')
print(f'  IPs suspeitos: {len(status["suspicious_attempts"])}')

if status['blocked_ips']:
    print('\n  🚫 IPs BLOQUEADOS:')
    for ip_block in status['blocked_ips']:
        print(f'    - {ip_block["ip"]}: {ip_block["failed_attempts"]} tentativas, bloqueado por {ip_block["blocked_until"]}')

if status['suspicious_attempts']:
    print('\n  ⚠️  IPs SUSPEITOS:')
    for susp in status['suspicious_attempts']:
        print(f'    - {susp["ip"]}: {susp["failed_attempts"]} tentativas')

print('\n✅ Teste concluído!')
