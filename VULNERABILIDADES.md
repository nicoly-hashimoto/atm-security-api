# ANÁLISE DE VULNERABILIDADES - ATM Security API

## 🔴 CRÍTICO (Risco Imediato)

### 1. Sem HTTPS/TLS
**Risco:** Credenciais e dados em plaintext na rede
```
❌ http://127.0.0.1:8000
✓ https://127.0.0.1:8000
```
**Impacto:** Man-in-the-Middle attack - interceptar tokens e senhas

### 2. Sem Rate Limiting
**Risco:** Força bruta fácil contra login
```
❌ Sem limite - qualquer um pode tentar infinitas senhas
✓ Max 5 tentativas por minuto por IP
```
**Impacto:** Hacker consegue descobrir password com scripts

### 3. Dados Apenas em Memória
**Risco:** Todos os eventos/alertas são perdidos ao reiniciar
```
❌ ATMState() - tudo em RAM
✓ Banco de dados persistente
```
**Impacto:** Perda total de histórico de auditoria

### 4. Sem Auditoria/Logging
**Risco:** Nenhuma rastreabilidade de quem fez o quê
```
❌ Nenhum log de ações do admin
✓ TODO: Log completo de todas as ações
```
**Impacto:** Impossível investigar fraudes internas

### 5. CORS Desprotegido
**Risco:** Qualquer website pode acessar a API
```
❌ Sem CORS = aceita qualquer origem
✓ CORS apenas para domínios autorizados
```
**Impacto:** XSS de site malicioso acessa tokens da vítima

### 6. Sem Proteção contra CSRF
**Risco:** Forma falsificada em outro site executa ações
```
❌ Sem CSRF tokens
✓ Validação de CSRF token
```
**Impacto:** Usuário clica link malicioso que envia POST mal-intencionado

---

## 🟠 ALTO (Exploração Provável)

### 7. Dashboard Público
**Risco:** GET / é `response_class=HTMLResponse` - public
```
❌ Qualquer um vê o dashboard sem login
✓ Dashboard requer autenticação
```
**Impacto:** Vaza informações do sistema para qualquer pessoa

### 8. Sem Timeout de Sessão
**Risco:** Token válido para sempre (120 min é longo!)
```
❌ Token válido por 120 minutos
✓ 15-30 minutos + refresh token
```
**Impacto:** Token roubado funciona por 2 horas

### 9. Senhas Padrão em .env
**Risco:** Credenciais default fáceis de descobrir
```
❌ ATM_ADMIN_PASSWORD = "superadmin123"
✓ Força exigência de mudança na primeira execução
```
**Impacto:** Qualquer um sabe senhas default

### 10. Salt Fixo para Todas Senhas
**Risco:** Rainbow tables funcionam para todos os hashes
```
❌ OPERATOR_SALT = "atm-operator-salt" (fixo)
✓ Salt único por senha (bcrypt automático)
```
**Impacto:** Hacker com acesso ao código quebra todos os hashes

### 11. Sem Validação de Entrada
**Risco:** Injeções de código/SQL possíveis
```
❌ Sem validação de actor_id, details
✓ Validação de comprimento, padrões
```
**Impacto:** XSS no dashboard via evento malicioso

### 12. Hash Fraco (PBKDF2)
**Risco:** Senhas podem ser bruteadas
```
❌ PBKDF2 com apenas 120k iterações
✓ Usar bcrypt ou argon2 com custos altos
```
**Impacto:** GPU attack quebra senhas em horas

---

## 🟡 MÉDIO (Exploração Possível)

### 13. Sem Proteção contra Downtime
**Risco:** Falha da API == sem monitoramento
```
❌ Sem health checks persistentes
✓ Alertas quando API fica offline
```
**Impacto:** Fraude ocorre enquanto sistema está down

### 14. JWT Sem Expiração Configurável
**Risco:** Tokens mortos não são verificados
```
❌ Sem mecanismo de revocation
✓ Blacklist de tokens revogados
```
**Impacto:** Token roubado não pode ser revogado

### 15. Logs Malformados
**Risco:** Sem histórico estruturado
```
❌ Apenas print() para logs
✓ JSON estruturado em arquivo/DB
```
**Impacto:** Auditar é quase impossível

### 16. Sem Backup
**Risco:** Dados não têm backup
```
❌ Sem backup automático
✓ Backup diário de alertas/eventos
```
**Impacto:** Perda de dados de segurança críticos

### 17. Endpoint do Operador Aberto
**Risco:** POST /admin/users sem validação suficiente
```
❌ Criar usuário com qualquer role
✓ Validação de role e validação dupla
```
**Impacto:** Admin cria conta com super-poderes

---

## 🔵 BAIXO (Boas Práticas)

### 18. Sem Content-Security-Policy
**Risco:** XSS no dashboard
```
❌ Sem CSP header
✓ CSP header restritivo
```

### 19. Sem Secret Rotation
**Risco:** AUTH_SECRET nunca muda
```
❌ Mesmo secret desde deploy
✓ Rotação periódica de secrets
```

### 20. Sem Validação de HTTPS em Produção
**Risco:** Redirecionamento para HTTP
```
❌ Força HTTPS apenas em produção
✓ Sempre HTTPS + HSTS
```

---

## RESUMO DE RISCOS

| Severidade | Qtd | Exemplos |
|-----------|-----|----------|
| 🔴 CRÍTICO | 6 | CORS, HTTPS, Rate Limiting, Logging, Auditoria |
| 🟠 ALTO | 6 | CSRF, Dashboard público, Timeout, Senhas default |
| 🟡 MÉDIO | 5 | Validação, Backup, Revogação de tokens |
| 🔵 BAIXO | 3 | CSP, Secret rotation, HSTS |

**Total: 20 vulnerabilidades encontradas**

---

## PLANO DE AÇÃO (Prioridade)

### Fase 1: CRÍTICO (fazer imediatamente)
- [ ] Adicionar Rate Limiting (5 tentativas/min)
- [ ] Adicionar logging completo de ações
- [ ] Implementar CORS restritivo
- [ ] Proteger dashboard com autenticação
- [ ] Adicionar HTTPS/TLS

### Fase 2: ALTO (fazer em seguida)
- [ ] CSRF tokens
- [ ] Timeout de sessão (30 min)
- [ ] Rotação de senhas obrigatória
- [ ] Usar bcrypt em vez de PBKDF2
- [ ] Validação rigorosa de entrada

### Fase 3: MÉDIO (depois)
- [ ] Banco de dados para persistência
- [ ] Blacklist de tokens revogados
- [ ] Sistema de backup automático
- [ ] Endpoints de revogação de sessão

### Fase 4: BAIXO (melhorias)
- [ ] CSP headers
- [ ] Secret rotation automática
- [ ] HSTS header
- [ ] Rate limit por usuário também
