# Guia de Testes - ATM Security API

Este documento descreve como executar e entender a suite de testes automatizados da API.

## Quick Start

### 1. Instalar dependências

```powershell
pip install -r requirements.txt
```

### 2. Executar todos os testes

```powershell
pytest
```

### 3. Ver resultado resumido

```powershell
34 passed in 6.14s ✓
```

## Estrutura dos Testes

### Organização por Classes

Os testes estão organizados em 6 classes temáticas:

#### 1. **TestPublicEndpoints** (2 testes)
Endpoints públicos que não requerem autenticação.

```python
✓ GET /health              # Health check
✓ GET /                    # Dashboard HTML
```

**O que testa:**
- Endpoints acessíveis sem token
- Resposta correta do servidor

#### 2. **TestAuthentication** (6 testes)
Login, validação de credenciais e geração de tokens JWT.

```python
✓ Login de viewer
✓ Login de operator
✓ Login de admin
✓ Rejeição de username inválido
✓ Rejeição de password inválido
✓ Estrutura do token JWT
```

**O que testa:**
- Credenciais corretas geram token válido
- Credenciais incorretas são rejeitadas com 401
- Token inclui nome, role, permissões e expiração

#### 3. **TestProtectedEndpoints** (6 testes)
Endpoints que requerem ou não autenticação.

```python
✓ GET /auth/me SEM token         → 401
✓ GET /auth/me COM token         → 200
✓ GET /auth/me COM token inválido → 401
✓ GET /snapshot SEM token        → 200 (público)
✓ GET /state SEM token           → 200 (público)
✓ GET /alerts SEM token          → 200 (público)
```

**O que testa:**
- Rejeição de requisições sem autenticação
- Aceitação de tokens válidos
- Rejeição de tokens inválidos

#### 4. **TestAuthorizationByRole** (10 testes)
Validação de permissões por role (viewer, operator, admin).

```python
✓ Viewer NÃO pode POST /events           → 403
✓ Operator PODE POST /events             → 200
✓ Admin PODE POST /events                → 200
✓ Viewer NÃO pode POST /reset            → 403
✓ Operator NÃO pode POST /reset          → 403
✓ Admin PODE POST /reset                 → 200
✓ Viewer NÃO pode GET /admin/users       → 403
✓ Admin PODE GET /admin/users            → 200
✓ Operator NÃO pode POST /admin/users    → 403
✓ Admin PODE POST /admin/users           → 201
```

**O que testa:**
- Cada role tem apenas as permissões corretas
- Endpoints sensíveis rejeitam usuarios sem permissão
- Admin tem acesso total

#### 5. **TestTokenValidation** (3 testes)
Rejeição de tokens malformados.

```python
✓ Token com formato inválido     → 401
✓ Sem prefixo "Bearer"           → 401
✓ Com esquema "Basic" em vez de "Bearer" → 401
```

**O que testa:**
- Implementação correta de validação JWT
- Headers HTTP corretos

#### 6. **TestEventProcessing** (3 testes)
Processamento de eventos e geração de alertas.

```python
✓ Evento de cartão inserido é processado
✓ Evento de PIN falhado é processado
✓ Múltiplas falhas de PIN geram alerta
```

**O que testa:**
- Motor de segurança funciona
- Alertas são gerados quando apropriado

#### 7. **TestOperatorManagement** (4 testes)
Gerenciamento de operadores pelo admin.

```python
✓ GET /auth/me retorna perfil correto
✓ Admin pode listar todos operadores
✓ Admin pode alterar password de outro usuário
✓ Admin pode alterar role de outro usuário
```

**O que testa:**
- Gestão de usuários funciona
- Mudanças de permissão são refletidas

## Executando Testes Específicos

### Apenas uma classe de testes

```powershell
# Testes de autenticação
pytest test_api.py::TestAuthentication -v

# Testes de autorização
pytest test_api.py::TestAuthorizationByRole -v

# Testes de eventos
pytest test_api.py::TestEventProcessing -v
```

### Apenas um teste

```powershell
pytest test_api.py::TestAuthentication::test_login_viewer_success -v
```

### Com padrão de nome

```powershell
# Todos os testes que contenham "login"
pytest -k "login" -v

# Todos menos testes de autenticação
pytest -k "not authentication" -v
```

## Relatórios

### Saída curta

```powershell
pytest --tb=no
```

### Saída detalhada com traceback

```powershell
pytest -vv --tb=long
```

### Parar no primeiro erro

```powershell
pytest -x
```

### Mostrar prints de debug

```powershell
pytest -s
```

### Gerar relatório HTML de cobertura

```powershell
pip install pytest-cov
pytest --cov=. --cov-report=html
# Abrir htmlcov/index.html no navegador
```

## Garantias de Segurança

A suite de testes valida:

✓ **Autenticação obrigatória**: Endpoints sensíveis exigem token
✓ **Autorização por role**: Cada role tem permissões específicas
✓ **Validação de token**: Tokens inválidos são rejeitados
✓ **Consistência de dados**: Estado é mantido corretamente
✓ **Fluxos de negócio**: Alertas são gerados apropriadamente
✓ **Gestão de acesso**: Admin controla quem pode fazer o quê

## Fixtures Disponíveis

Os testes usam fixtures para facilitar o setup:

```python
# Cliente HTTP para fazer requisições
client = TestClient(app)

# Tokens pré-autenticados
viewer_token = "eyJ0eXAiOiJKV1QiLCJhbGc..."
operator_token = "eyJ0eXAiOiJKV1QiLCJhbGc..."
admin_token = "eyJ0eXAiOiJKV1QiLCJhbGc..."
```

## Adicionando Novos Testes

### Template básico

```python
def test_novo_endpoint(self, client):
    """Descrição clara do que testa."""
    # Arrange
    response = client.get("/algum-endpoint")
    
    # Assert
    assert response.status_code == 200
    assert "campo_esperado" in response.json()
```

### Com autenticação

```python
def test_endpoint_autenticado(self, client, admin_token):
    """Testa endpoint que requer admin."""
    response = client.post(
        "/algum-endpoint",
        json={"dados": "aqui"},
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    
    assert response.status_code == 200
```

## Troubleshooting

### "pytest: command not found"

```powershell
pip install pytest
```

### Testes falhando

```powershell
# Executar com mais detalhes
pytest -vv --tb=long

# Ver exatamente qual assertion falhou
pytest -x  # Para no primeiro erro
```

### Erro "ModuleNotFoundError: No module named 'api'"

```powershell
# Garantir que está no diretório correto
cd c:\Users\nicol\OneDrive\Área de Trabalho\atm_security_api
pytest
```

## Integração Contínua

Para adicionar em um pipeline CI/CD:

```yaml
# Exemplo para GitHub Actions
- name: Run Tests
  run: pytest --tb=short -v
```

## Summary

- **34 testes** cobrindo autenticação, autorização e lógica
- **100% dos requisitos de segurança** validados
- Todos os testes passam em < 7 segundos
- Pronto para integração contínua
