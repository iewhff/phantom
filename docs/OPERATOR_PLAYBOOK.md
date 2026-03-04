# PHANTOM AI - Operator Playbook

**Versão:** 1.0
**Data:** 2026-02-13
**Audiência:** Operadores de scan PHANTOM

---

## Sumário

Este documento define os procedimentos operacionais para executar scans de segurança com o PHANTOM AI de forma segura, profissional e legalmente defensável.

---

## 1. Checklist Pré-Scan

### 1.1 Documentação Obrigatória

- [ ] **RoE (Rules of Engagement) assinado**
  - Staging: `legal/ROE_STAGING.md`
  - Production: `legal/ROE_PRODUCTION.md`
  - Verificar: escopo, janela horária, contactos

- [ ] **Escopo confirmado com cliente**
  - Lista de IPs/URLs autorizada por escrito
  - Sistemas excluídos documentados
  - Limites de teste claros

- [ ] **Contactos de emergência registados**
  - Contacto técnico cliente (24/7)
  - Contacto management cliente
  - Número de backup

### 1.2 Verificações Técnicas

- [ ] **Ambiente identificado**
  ```bash
  # Confirmar ambiente
  phantom info --target https://target.com
  # Deve mostrar: [STAGING] ou [PRODUCTION]
  ```

- [ ] **Backup verificado** (se produção)
  - Cliente confirmou backup < 24h
  - Procedimento de rollback documentado
  - Tempo estimado de rollback: ___ min

- [ ] **Janela de manutenção** (se produção)
  - Horário: ___:___ - ___:___
  - Aprovador: _______________
  - Ticket/Referência: _______________

### 1.3 Configuração do Scanner

- [ ] **Safety level configurado**
  ```bash
  # Staging - standard é OK
  phantom scan --safety-level standard

  # Production - SEMPRE começar com cautious
  phantom scan --safety-level cautious
  ```

- [ ] **Scope guard ativo**
  ```bash
  phantom scan --scope "*.client.com" --scope "api.client.com"
  # NUNCA usar --no-scope-check
  ```

- [ ] **Audit logger iniciado**
  ```bash
  phantom scan --audit-log ./audit/scan_$(date +%Y%m%d).log
  ```

---

## 2. Durante o Scan

### 2.1 Monitorização Contínua

```bash
# Terminal 1: Scan em execução
phantom scan https://target.com --verbose

# Terminal 2: Monitorização de logs
tail -f ./audit/scan_*.log | grep -E "(ERROR|WARNING|CRITICAL)"

# Terminal 3: Monitorização de requests
phantom stats --live
```

### 2.2 Indicadores de Alerta

| Indicador | Threshold | Ação |
|-----------|-----------|------|
| Taxa de erro | >10% | Reduzir rate limit |
| Tempo de resposta | >5s média | Pausar e investigar |
| 5xx responses | >20 seguidos | PARAR scan |
| Rate limiting | >50% requests | Pausar 10 min |
| WAF blocking | Detectado | Informar cliente |

### 2.3 Comandos de Controlo

```bash
# Pausar scan (mantém estado)
Ctrl+Z ou phantom pause

# Retomar scan
phantom resume

# PARAR imediatamente (kill-switch)
Ctrl+C duas vezes OU phantom stop --force

# Verificar estado
phantom status
```

---

## 3. QUANDO PARAR IMEDIATAMENTE

### 3.1 Situações de Paragem Automática

O scanner PARA automaticamente se:
- Circuit breaker dispara (>5 erros/min)
- Kill-switch activado
- Scope violation detectada
- OOM (out of memory)

### 3.2 Situações de Paragem Manual

**PARAR IMEDIATAMENTE se:**

1. **Cliente reporta indisponibilidade**
   ```bash
   phantom stop --force
   # Depois: Contactar cliente IMEDIATAMENTE
   ```

2. **Acesso a dados inesperados**
   - Dados de outros clientes
   - Dados financeiros/saúde não autorizados
   - Credenciais de produção

3. **Resposta inesperada**
   - Página de banco em vez de alvo
   - Redirects para domínios externos
   - Certificados SSL de terceiros

4. **Evidência de comprometimento existente**
   - Backdoors detectados
   - Malware em respostas
   - Comportamento anómalo do servidor

### 3.3 Procedimento de Paragem

```
1. STOP: phantom stop --force
2. LOG: Anotar timestamp e último request
3. CALL: Contactar cliente em <5 minutos
4. DOC: Criar incident report em 24h
5. WAIT: Não retomar sem aprovação explícita
```

---

## 4. QUANDO ESCALAR PARA CLIENTE

### 4.1 Escalar Imediatamente (Telefone)

- Vulnerabilidade CRÍTICA descoberta
- Possível comprometimento já existente
- Acesso a dados sensíveis inesperados
- Qualquer dúvida sobre escopo

### 4.2 Escalar Mesmo Dia (Email + Chat)

- Vulnerabilidade HIGH descoberta
- WAF blocking significativo (>30%)
- Rate limiting constante
- Comportamento anómalo

### 4.3 Template de Comunicação

```
ASSUNTO: [PHANTOM] Alerta de Segurança - [Severidade]

Prezado [Nome],

Durante o teste de segurança em curso, detectámos:

TIPO: [Descrição breve]
SEVERIDADE: [CRITICAL/HIGH/MEDIUM]
SISTEMA AFETADO: [URL/IP]
TIMESTAMP: [YYYY-MM-DD HH:MM UTC]

AÇÃO RECOMENDADA:
[Descrição da ação]

PRÓXIMOS PASSOS:
□ Aguardamos confirmação para continuar/parar
□ Relatório detalhado a seguir

Contacte-nos: [Telefone]

Cumprimentos,
[Nome do Operador]
PHANTOM AI Security
```

---

## 5. Pós-Scan

### 5.1 Checklist de Conclusão

- [ ] **Scan terminado com sucesso**
  ```bash
  phantom stats --final
  # Verificar: errors=0, coverage>80%
  ```

- [ ] **Relatórios gerados**
  ```bash
  phantom report --format client --output ./reports/
  phantom report --format hackerone --output ./reports/  # se aplicável
  ```

- [ ] **Evidências redactadas**
  ```bash
  # Verificar que PII foi removida
  grep -r "password\|email\|@" ./reports/*.md
  # Deve retornar vazio ou [REDACTED]
  ```

- [ ] **Audit trail completo**
  ```bash
  phantom audit export --output ./audit/final_audit.md
  ```

- [ ] **Sessão de debriefing agendada**
  - Data: ___/___/______
  - Participantes: _______________

### 5.2 Entregáveis Standard

1. **Relatório Executivo** (para management)
   - Sumário de 1-2 páginas
   - Gráfico de severidades
   - Impacto de negócio
   - Recomendações prioritárias

2. **Relatório Técnico** (para IT)
   - Todas as vulnerabilidades
   - Evidências (redactadas)
   - PoC para reprodução
   - Passos de remediação

3. **Audit Trail** (para compliance)
   - Timestamps de início/fim
   - Escopo testado
   - Métodos utilizados
   - Hash de integridade

---

## 6. Resposta a Incidentes

### 6.1 Incidente: Scan Causou Indisponibilidade

```
IMEDIATO (0-5 min):
1. STOP: phantom stop --force
2. CALL: Cliente via número de emergência
3. LOG: Anotar: "Indisponibilidade reportada às HH:MM"

CURTO PRAZO (5-30 min):
4. WAIT: Não tentar "corrigir" - deixar cliente fazer rollback
5. ASSIST: Fornecer logs se solicitado
6. DOC: Começar incident report

MÉDIO PRAZO (30 min - 4h):
7. REPORT: Entregar incident report preliminar
8. REVIEW: Análise de causa raiz
9. LEARN: Documentar lições aprendidas
```

### 6.2 Incidente: Dados Sensíveis Descobertos

```
IMEDIATO:
1. STOP: Parar extração adicional
2. LOG: Documentar o que foi acedido (sem copiar dados)
3. CALL: Informar cliente imediatamente

CURTO PRAZO:
4. SECURE: Eliminar dados extraídos de forma segura
5. DOC: Documentar para compliance
6. LEGAL: Avaliar obrigações de notificação (GDPR, etc.)
```

### 6.3 Incidente: Comprometimento Pré-Existente

```
IMEDIATO:
1. STOP: Parar scan (não contaminar evidências)
2. LOG: Documentar indicadores de comprometimento
3. CALL: Informar cliente URGENTE

IMPORTANTE:
- NÃO tentar "limpar" o sistema
- NÃO interagir mais com backdoors
- PRESERVAR todas as evidências
- Recomendar equipa de incident response dedicada
```

---

## 7. Templates de Documentação

### 7.1 Incident Report Template

```markdown
# Incident Report

**ID:** INC-YYYYMMDD-001
**Data:** YYYY-MM-DD HH:MM UTC
**Operador:** [Nome]
**Cliente:** [Nome Cliente]

## Sumário
[1-2 frases descrevendo o incidente]

## Timeline
- HH:MM - [Evento 1]
- HH:MM - [Evento 2]
- HH:MM - [Resolução]

## Causa Raiz
[Análise da causa]

## Impacto
- Duração: X minutos
- Sistemas afetados: [Lista]
- Dados expostos: [Nenhum / Descrição]

## Ações Tomadas
1. [Ação 1]
2. [Ação 2]

## Lições Aprendidas
- [Lição 1]
- [Lição 2]

## Prevenção Futura
- [Medida 1]
- [Medida 2]
```

### 7.2 Handoff Template (Mudança de Operador)

```markdown
# Scan Handoff

**De:** [Operador Anterior]
**Para:** [Novo Operador]
**Data:** YYYY-MM-DD HH:MM

## Estado Atual
- Progresso: X% completo
- Fase actual: [Recon/Active/Report]
- Findings até agora: X (CRIT: X, HIGH: X)

## Pendente
- [ ] [Tarefa 1]
- [ ] [Tarefa 2]

## Notas Importantes
- [Nota 1]
- [Nota 2]

## Contactos
- Cliente: [Nome, Tel]
- Backup: [Nome, Tel]
```

---

## 8. Contactos de Suporte

### Suporte PHANTOM

- **Email:** support@phantom.ai
- **Emergência:** [Telefone interno]
- **Documentação:** https://docs.phantom.ai

### Escalation Path

1. **Nível 1:** Operador responsável
2. **Nível 2:** Team Lead / Senior Operator
3. **Nível 3:** CTO / Management

---

## 9. Glossário

| Termo | Definição |
|-------|-----------|
| **RoE** | Rules of Engagement - Contrato de autorização |
| **Kill-switch** | Paragem de emergência de todos os requests |
| **Circuit breaker** | Auto-stop após erros consecutivos |
| **Scope guard** | Validação de URL contra escopo autorizado |
| **Redaction** | Remoção de PII de relatórios |
| **FP** | False Positive - Vulnerabilidade mal detectada |
| **PoC** | Proof of Concept - Demonstração da vulnerabilidade |

---

## 10. Atualizações

| Versão | Data | Autor | Mudanças |
|--------|------|-------|----------|
| 1.0 | 2026-02-13 | PHANTOM AI | Versão inicial |

---

*Este documento deve ser lido por todos os operadores antes de executar scans em clientes.*
*Dúvidas: Contactar Team Lead antes de iniciar.*
