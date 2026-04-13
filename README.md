# Sistema de Seguranca para Caixa Eletronico

Este projeto e um prototipo defensivo de monitoramento para caixa eletronico.
Ele foi pensado para detectar comportamentos suspeitos, riscos operacionais e
violacoes fisicas do terminal.

## Objetivo

O sistema observa eventos do ATM e gera alertas quando identifica situacoes
como:

- varias tentativas de PIN incorreto
- abertura indevida do cofre
- vibracao intensa no terminal
- perda de conexao com a central
- uso de manutencao fora de horario autorizado

## Componentes

- `ATMSecurityEngine`: motor principal que processa eventos
- `ATMState`: estado atual do terminal
- `SecurityRule`: regras defensivas de deteccao
- `SecurityAlert`: alertas gerados pelo sistema

## Eventos monitorados

- autenticacao de cartao
- validacao de PIN
- abertura de painel/cofre
- vibracao ou impacto
- perda e retorno de rede
- entrada em modo de manutencao
- abastecimento de dinheiro

## Como executar o simulador

```powershell
python atm_security.py
```

## Como executar a API

Instale as dependencias:

```powershell
pip install -r requirements.txt
```

Suba a API:

```powershell
uvicorn api:app --reload
```

Documentacao interativa:

- `http://127.0.0.1:8000/`
- `http://127.0.0.1:8000/docs`
- `http://127.0.0.1:8000/redoc`

## Endpoints principais

- `GET /`
- `GET /health`
- `POST /auth/login`
- `GET /auth/me`
- `GET /admin/users`
- `POST /admin/users`
- `PUT /admin/users/{username}`
- `GET /snapshot`
- `GET /state`
- `GET /alerts`
- `GET /events/recent`
- `POST /events`
- `POST /reset`

## Dashboard web em tempo real

O projeto agora inclui um dashboard HTML servido pela propria FastAPI.

- mostra o nivel de risco atual
- acompanha alertas e eventos recentes
- exibe o estado operacional do ATM
- atualiza automaticamente a cada 2 segundos
- permite simular eventos direto pela interface

## Autenticacao de operadores

As acoes sensiveis da API agora exigem autenticacao por token Bearer:

- `POST /events`
- `POST /reset`
- `GET /auth/me`

Credenciais padrao do ambiente local:

- `viewer` / `viewer123`
- `operator` / `admin123`
- `admin` / `superadmin123`

Perfis padrao:

- `viewer`: apenas monitoramento e leitura do dashboard
- `operator`: monitoramento e envio de eventos
- `admin`: monitoramento, envio de eventos e reset do motor

Permissoes atuais:

- `dashboard:view`
- `events:write`
- `engine:reset`
- `users:manage`

## Tela de gestao de usuarios

O dashboard agora possui uma area administrativa para perfis `admin`:

- listar operadores cadastrados
- criar novos usuarios com perfil
- alterar nome, papel e senha

Os usuarios criados neste prototipo ficam em memoria e sao perdidos se a aplicacao reiniciar.

Variaveis de ambiente suportadas:

- `ATM_AUTH_SECRET`
- `ATM_TOKEN_TTL_MINUTES`
- `ATM_OPERATOR_USERNAME`
- `ATM_OPERATOR_PASSWORD`
- `ATM_OPERATOR_NAME`
- `ATM_VIEWER_USERNAME`
- `ATM_VIEWER_PASSWORD`
- `ATM_VIEWER_NAME`
- `ATM_ADMIN_USERNAME`
- `ATM_ADMIN_PASSWORD`
- `ATM_ADMIN_NAME`
- `ATM_OPERATOR_SALT`

Exemplo de login:

```json
{
  "username": "operator",
  "password": "admin123"
}
```

O dashboard usa esse login para liberar simulacao de eventos e reset do motor.

## Testes Automáticos

A aplicação possui uma suite completa de testes para validar autenticação, autorização e lógica de negócio.

### Instalação de dependências para testes

```powershell
pip install -r requirements.txt
```

### Executar todos os testes

```powershell
pytest
```

### Executar com saída detalhada

```powershell
pytest -v
```

### Executar apenas testes de autenticação

```powershell
pytest -k "Authentication"
```

### Executar com cobertura de código

```powershell
pip install pytest-cov
pytest --cov=. --cov-report=html
```

### Estrutura dos testes

Os testes estão organizados em classes temáticas:

- **TestPublicEndpoints**: Endpoints públicos que não requerem autenticação
- **TestAuthentication**: Login, validação de credenciais e geração de tokens
- **TestProtectedEndpoints**: Endpoints que requerem autenticação
- **TestAuthorizationByRole**: Validação de permissões por perfil (viewer, operator, admin)
- **TestTokenValidation**: Validação e rejeição de tokens inválidos
- **TestEventProcessing**: Processamento de eventos e geração de alertas
- **TestOperatorManagement**: Gestão de operadores e permissões

### Requisitos garantidos pelos testes

✓ Todos os endpoints sensíveis requerem autenticação por token Bearer
✓ Diferentes roles têm diferentes permissões
✓ Viewer: apenas visualização
✓ Operator: visualização + envio de eventos
✓ Admin: acesso total + gestão de usuários
✓ Tokens inválidos são rejeitados
✓ Eventos são processados e geram alertas quando necessário
✓ Operadores podem ser criados e modificados apenas por admin

## Deploy online no Render

O repositorio inclui configuracao pronta para deploy com Blueprint em `render.yaml`.

Arquivos usados no deploy:

- `render.yaml`
- `.python-version`

Passos no Render:

1. Acesse `https://dashboard.render.com/`
2. Clique em `New +`
3. Escolha `Blueprint`
4. Conecte o repositorio `atm-security-api`
5. Confirme o servico `atm-security-api`
6. Aguarde o build e o primeiro deploy

Configuracao aplicada:

- build command: `pip install -r requirements.txt`
- start command: `uvicorn api:app --host 0.0.0.0 --port $PORT`
- health check: `/health`
- auto deploy a cada push na branch principal

### Exemplo de evento

```json
{
  "event_type": "pin_failed",
  "timestamp": "2026-04-06T14:03:00",
  "actor_id": "card-001",
  "details": "PIN incorreto"
}
```

## Proximos passos

- integrar com API real de monitoramento
- salvar alertas em banco de dados
- enviar notificacoes para central de seguranca
- adicionar biometria, camera e analise de fraude