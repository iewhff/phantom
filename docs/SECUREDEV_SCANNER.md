# 🔐 SecureDev Security Scanner

## Visão Geral

O SecureDev Scanner implementa o **SecureDev Security Scan Checklist** com uma **árvore de decisão inteligente** que adapta automaticamente os testes baseado no tipo de backend detectado.

## Como Funciona - Árvore de Decisão

```
┌─────────────────────────────────────────────────────────┐
│              FASE 0: Backend Detection                   │
│                     (OBRIGATÓRIO)                        │
└─────────────────────┬───────────────────────────────────┘
                      │
         ┌────────────┼────────────┬─────────────┐
         ▼            ▼            ▼             ▼
    ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐
    │SUPABASE │  │FIREBASE │  │GRAPHQL  │  │REST API │
    └────┬────┘  └────┬────┘  └────┬────┘  └────┬────┘
         │            │            │             │
    ┌────┴────┐  ┌────┴────┐  ┌────┴────┐  ┌────┴────┐
    │FASE 2-6 │  │  F1-F4  │  │  C2,C3  │  │  C1-C4  │
    │FASE 20  │  │         │  │         │  │         │
    └─────────┘  └─────────┘  └─────────┘  └─────────┘
                      │
                      ▼
        ┌─────────────────────────────────┐
        │     FASES COMUNS (TODOS)        │
        │  7, 10, 12, 15, 19              │
        │  Token, Third-Party, JS, Tools  │
        └─────────────────────────────────┘
```

## Uso

### Via CLI

```bash
# Scan completo com decisão automática
pentest securedev https://myapp.vercel.app

# Salvar relatório em JSON
pentest securedev https://example.com -f json -o reports/

# Scan de app Supabase específico
pentest securedev https://abcdef.supabase.co
```

### Via Python

```python
import asyncio
from scanning.securedev_orchestrator import run_securedev_scan

async def main():
    result = await run_securedev_scan("https://myapp.com")
    
    print(f"Backend: {result.backend_type.name}")
    print(f"Findings: {result.total_findings}")
    print(f"Critical: {result.total_critical}")
    
    # Ver fases executadas
    for phase in result.phases:
        print(f"  {phase.phase_id}: {phase.phase_name} - {phase.status.name}")

asyncio.run(main())
```

## Fases Implementadas

### FASE 0 - Backend Detection (OBRIGATÓRIO)
Detecta automaticamente o tipo de backend:
- **Supabase**: URL `*.supabase.co`, anon key JWT, service_role key
- **Firebase**: Config object, `*.firebaseapp.com`, `*.firebaseio.com`
- **GraphQL**: Endpoint `/graphql`, introspection
- **REST API**: Default se nenhum dos acima

### Fases Supabase (2-6, 20)
| Fase | Descrição | Testes |
|------|-----------|--------|
| 2 | RLS Bypass | Read/Write sem auth, horizontal escalation |
| 3 | Storage | Bucket listing, upload sem auth, path traversal |
| 4 | Edge Functions | Enumeration, auth bypass, injection |
| 5 | Realtime | Channel access, broadcast sem auth |
| 6 | Auth Config | Email enum, password policy, OAuth |
| 20 | Dashboard | Exposição do dashboard Supabase |

### Fases Firebase (F1-F4)
| Fase | Descrição | Testes |
|------|-----------|--------|
| F1 | Auth | Anonymous auth, email enum, weak passwords |
| F2 | Firestore | Rules testing, public collections |
| F3 | RTDB | Realtime Database rules, public paths |
| F4 | Storage | Bucket listing, uploads sem auth |

### Fases Comuns (Todos os backends)
| Fase | Descrição |
|------|-----------|
| 7 | Token Analysis - JWT, session tokens |
| 10 | Third-Party Keys - Stripe, Sentry, AWS, etc |
| 12 | JS Bundle Analysis |
| 15 | External Tools - nmap, nuclei, sqlmap |
| 19 | SSL/TLS Testing |

## Descoberta de Chaves Third-Party (FASE 10)

Detecta e valida automaticamente:

| Serviço | Tipo | Severidade |
|---------|------|------------|
| Stripe | `sk_live_*`, `sk_test_*` | 🔴 CRITICAL |
| Stripe | `pk_live_*`, `pk_test_*` | 🟡 MEDIUM |
| AWS | `AKIA...` (Access Key) | 🔴 CRITICAL |
| SendGrid | `SG....` | 🔴 CRITICAL |
| Twilio | `AC...` (SID) | 🟠 HIGH |
| GitHub | `ghp_*`, `gho_*` | 🔴 CRITICAL |
| Sentry | DSN URL | 🟡 MEDIUM |
| PostHog | `phc_*` | 🟡 MEDIUM |
| MongoDB | `mongodb+srv://user:pass@...` | 🔴 CRITICAL |
| PostgreSQL | `postgres://user:pass@...` | 🔴 CRITICAL |

## Integração com Ferramentas Externas (FASE 15)

O scanner detecta e integra automaticamente:

```bash
# Verificar ferramentas disponíveis
which nmap nuclei subfinder sqlmap ffuf

# Ferramentas suportadas:
# ✅ nmap - Port scanning, service detection
# ✅ nuclei - Vulnerability templates
# ✅ sqlmap - SQL injection automation
# ❓ subfinder - Subdomain enumeration
# ❓ ffuf - Fuzzing
```

### Instalar ferramentas em falta:

```bash
# Nuclei
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Subfinder
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# ffuf
go install github.com/ffuf/ffuf/v2@latest
```

## Exemplo de Relatório JSON

```json
{
  "target": "https://myapp.vercel.app",
  "backend_type": "SUPABASE",
  "summary": {
    "total_findings": 12,
    "critical": 2,
    "high": 3,
    "phases_run": 8,
    "phases_skipped": 4
  },
  "phases": [
    {
      "id": "0",
      "name": "Backend Detection",
      "status": "COMPLETED",
      "findings": 1,
      "duration_sec": 2.3
    },
    {
      "id": "2",
      "name": "Supabase RLS Bypass",
      "status": "COMPLETED",
      "findings": 3,
      "critical": 1
    }
  ],
  "backend_config": {
    "type": "supabase",
    "project_ref": "abcdefghij",
    "has_service_role": false
  }
}
```

## Estrutura dos Módulos

```
scanning/
├── securedev_orchestrator.py    # Orquestrador principal
└── modules/
    ├── backend_detector.py      # FASE 0 - Detecção de backend
    ├── supabase_scanner.py      # FASES 2-6, 20 - Supabase
    ├── firebase_scanner.py      # F1-F4 - Firebase
    └── third_party_scanner.py   # FASE 10 - Chaves terceiros
```

## Extensão

### Adicionar nova fase:

```python
# Em securedev_orchestrator.py

async def _phase_XX_custom(self, target: str, **kwargs) -> dict:
    """FASE XX: Custom testing."""
    logger.info("🔍 FASE XX: Custom Testing")
    
    # Implementar lógica
    findings = []
    
    return {"findings": findings}

# Registrar no __init__
self._phases["XX"] = self._phase_XX_custom
```

### Adicionar novo padrão de chave:

```python
# Em third_party_scanner.py, adicionar ao KEY_PATTERNS:

"my_service_key": {
    "pattern": re.compile(r'myservice_[A-Za-z0-9]{32}'),
    "severity": KeySeverity.HIGH,
    "description": "My Service API key",
}
```

## Notas de Segurança

⚠️ **IMPORTANTE**: 
- Obtenha sempre autorização antes de testar
- O scanner faz requisições reais aos serviços
- Chaves validadas são confirmadas como funcionais
- service_role keys expostas são vulnerabilidades CRÍTICAS

## Roadmap

- [ ] Integração Playwright para análise JS dinâmica
- [ ] Suporte a WebSocket realtime testing
- [ ] GraphQL introspection automática
- [ ] Rate limiting detection
- [ ] CORS misconfiguration testing
- [ ] Cache poisoning tests
