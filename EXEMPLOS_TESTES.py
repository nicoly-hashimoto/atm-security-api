"""
EXEMPLOS PRÁTICOS - Como usar a API com testes

Este arquivo mostra exemplos reais de fluxos de autenticação e autorização.
"""

# ============================================================================
# EXEMPLO 1: Login e obter token
# ============================================================================

import requests

API_URL = "http://127.0.0.1:8000"

# Fazer login como operator
login_response = requests.post(
    f"{API_URL}/auth/login",
    json={
        "username": "operator",
        "password": "admin123"
    }
)

if login_response.status_code == 200:
    token = login_response.json()["access_token"]
    print(f"✓ Login bem-sucedido!")
    print(f"  Token: {token[:20]}...")
else:
    print(f"✗ Login falhado: {login_response.status_code}")
    print(f"  Erro: {login_response.json()['detail']}")


# ============================================================================
# EXEMPLO 2: Usar token para acessar endpoint protegido
# ============================================================================

headers = {"Authorization": f"Bearer {token}"}

# Obter informações do operador
profile_response = requests.get(
    f"{API_URL}/auth/me",
    headers=headers
)

if profile_response.status_code == 200:
    profile = profile_response.json()
    print(f"\n✓ Perfil do operador:")
    print(f"  Username: {profile['username']}")
    print(f"  Nome: {profile['name']}")
    print(f"  Role: {profile['role']}")
    print(f"  Permissões: {', '.join(profile['permissions'])}")
else:
    print(f"\n✗ Erro ao obter perfil: {profile_response.status_code}")


# ============================================================================
# EXEMPLO 3: Enviar evento (requer permissão events:write)
# ============================================================================

# Operator TEM permissão events:write
event_data = {
    "event_type": "card_inserted",
    "actor_id": "card-001",
    "details": "Cartão inserido normalmente"
}

event_response = requests.post(
    f"{API_URL}/events",
    json=event_data,
    headers=headers
)

if event_response.status_code == 200:
    result = event_response.json()
    print(f"\n✓ Evento processado!")
    print(f"  Evento: {result['processed_event']['event_type']}")
    print(f"  Alertas gerados: {len(result['generated_alerts'])}")
else:
    print(f"\n✗ Erro ao processar evento: {event_response.status_code}")


# ============================================================================
# EXEMPLO 4: Tentar ação sem permissão
# ============================================================================

# Fazer login como viewer (SEM permissão events:write)
viewer_response = requests.post(
    f"{API_URL}/auth/login",
    json={
        "username": "viewer",
        "password": "viewer123"
    }
)

viewer_token = viewer_response.json()["access_token"]
viewer_headers = {"Authorization": f"Bearer {viewer_token}"}

# Tentar enviar evento (será rejeitado)
denied_response = requests.post(
    f"{API_URL}/events",
    json=event_data,
    headers=viewer_headers
)

if denied_response.status_code == 403:
    print(f"\n✓ Proteção funcionando!")
    print(f"  Status: Viewer bloqueado de enviar eventos")
    print(f"  Erro: {denied_response.json()['detail']}")
else:
    print(f"\n✗ ERRO: Viewer conseguiu enviar evento!")


# ============================================================================
# EXEMPLO 5: Reset do motor (apenas admin)
# ============================================================================

# Fazer login como admin
admin_response = requests.post(
    f"{API_URL}/auth/login",
    json={
        "username": "admin",
        "password": "superadmin123"
    }
)

admin_token = admin_response.json()["access_token"]
admin_headers = {"Authorization": f"Bearer {admin_token}"}

# Admin PODE fazer reset
reset_response = requests.post(
    f"{API_URL}/reset",
    headers=admin_headers
)

if reset_response.status_code == 200:
    state = reset_response.json()
    print(f"\n✓ Engine reset bem-sucedido!")
    print(f"  PIN failures: {state['pin_failures']}")
    print(f"  Network online: {state['network_online']}")
    print(f"  Maintenance mode: {state['maintenance_mode']}")
else:
    print(f"\n✗ Erro ao fazer reset: {reset_response.status_code}")


# ============================================================================
# EXEMPLO 6: Criar novo operador (apenas admin)
# ============================================================================

new_user_data = {
    "username": "supervisor",
    "password": "pass123456",
    "name": "Supervisor de Segurança",
    "role": "operator"
}

create_response = requests.post(
    f"{API_URL}/admin/users",
    json=new_user_data,
    headers=admin_headers
)

if create_response.status_code == 201:
    new_user = create_response.json()
    print(f"\n✓ Novo operador criado!")
    print(f"  Username: {new_user['username']}")
    print(f"  Nome: {new_user['name']}")
    print(f"  Role: {new_user['role']}")
    print(f"  Permissões: {', '.join(new_user['permissions'])}")
else:
    print(f"\n✗ Erro ao criar operador: {create_response.status_code}")
    print(f"  Detalhes: {create_response.json()}")


# ============================================================================
# EXEMPLO 7: Fluxo completo de testes com pytest
# ============================================================================

"""
Para rodar todos esses testes automaticamente:

  pytest test_api.py -v

Para rodar apenas testes de autenticação:

  pytest test_api.py::TestAuthentication -v

Para rodar com mais detalhes quando algo falha:

  pytest test_api.py -vv --tb=long

Para gerar relatório HTML de cobertura:

  pytest test_api.py --cov=. --cov-report=html
"""

# ============================================================================
# RESUMO DE FLUXOS
# ============================================================================

"""
FLUXO 1: Viewer (apenas leitura)
├─ Login como viewer/viewer123
├─ GET /auth/me → OK
├─ GET /snapshot → OK
├─ POST /events → NEGADO (403 sem permissão)
└─ POST /reset → NEGADO (403 sem permissão)

FLUXO 2: Operator (leitura + envio de eventos)
├─ Login como operator/admin123
├─ GET /auth/me → OK
├─ GET /snapshot → OK
├─ POST /events → OK
├─ POST /reset → NEGADO (403 sem permissão)
└─ GET /admin/users → NEGADO (403 sem permissão)

FLUXO 3: Admin (acesso total)
├─ Login como admin/superadmin123
├─ GET /auth/me → OK
├─ GET /snapshot → OK
├─ POST /events → OK
├─ POST /reset → OK
├─ GET /admin/users → OK
├─ POST /admin/users → OK
└─ PUT /admin/users/{username} → OK

FLUXO 4: Sem autenticação
├─ GET / (dashboard) → OK (público)
├─ GET /health → OK (público)
├─ GET /snapshot → OK (público - para compatibilidade)
├─ POST /events (SEM token) → NEGADO (401, token obrigatório)
├─ POST /reset (SEM token) → NEGADO (401, token obrigatório)
└─ GET /auth/me (SEM token) → NEGADO (401, credenciais ausentes)

GARANTIAS:
✓ Token expirado = 401 Unauthorized
✓ Token inválido = 401 Unauthorized
✓ Token correto mas sem permissão = 403 Forbidden
✓ Sem token em endpoint protegido = 401 Unauthorized
✓ Viewer não pode escalar privs
✓ Operator não pode fazer reset
✓ Admin tem acesso total
"""

print("\n" + "="*60)
print("Exemplos executados com sucesso!")
print("="*60)
