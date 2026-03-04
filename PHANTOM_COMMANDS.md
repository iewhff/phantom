# PHANTOM AI — Referência Completa de Comandos

**Versão:** 3.0.0
**Última atualização:** 2026-02-05

---

## Índice

1. [Arquitetura de Segurança](#arquitetura-de-segurança)
2. [Variáveis de Ambiente](#variáveis-de-ambiente)
3. [Opções Globais](#opções-globais)
4. [Comandos de Scan](#comandos-de-scan)
   - [scan](#scan)
   - [quick](#quick)
   - [full](#full)
   - [bounty](#bounty)
   - [client](#client)
5. [Comandos de Reconhecimento](#comandos-de-reconhecimento)
   - [recon](#recon)
   - [waf-detect](#waf-detect)
6. [Comandos de Relatório](#comandos-de-relatório)
   - [report](#report)
   - [hackerone-report](#hackerone-report)
   - [chain](#chain)
   - [impact](#impact)
   - [compliance](#compliance)
7. [Comandos de Gestão](#comandos-de-gestão)
   - [status](#status)
   - [list](#list)
   - [resume](#resume)
   - [validate](#validate)
   - [authorize](#authorize)
   - [modules](#modules)
   - [presets](#presets)
8. [Comandos de Sistema](#comandos-de-sistema)
   - [health](#health)
   - [version](#version)
   - [update-kb](#update-kb)
9. [Comandos GDPR](#comandos-gdpr)
10. [Combinações Práticas por Cenário](#combinações-práticas-por-cenário)
11. [Tabela de Módulos por Safety Level](#tabela-de-módulos-por-safety-level)

---

## Arquitetura de Segurança

O PHANTOM tem 3 camadas de proteção independentes:

| Camada | Controlo | O que faz |
|--------|----------|-----------|
| **1. Module Safety Levels** | `--safe-mode` no CLI | Bloqueia módulos acima do nível pedido |
| **2. Aggressive Gate** | `PHANTOM_ALLOW_AGGRESSIVE` | Impede modo `aggressive` sem autorização explícita |
| **3. HTTP Safety Client** | `PHANTOM_UNRESTRICTED` | Bloqueia métodos destrutivos e payloads perigosos a nível HTTP |

### Hierarquia de Safety Modes

```
passive → safe → cautious → standard → aggressive → unrestricted
  (0)      (1)     (2)        (3)         (4)           (5)
```

| Modo | Métodos HTTP | Payloads | Uso típico |
|------|-------------|----------|------------|
| `passive` | GET, HEAD | Nenhum | Observação pura, WAF detection |
| `safe` | GET, HEAD, OPTIONS | Nenhum | Bug bounty sem autorização de teste ativo |
| `cautious` | GET, HEAD, OPTIONS, POST (seguro) | Injeções básicas | Bug bounty com autorização |
| `standard` | Todos exceto padrões destrutivos | Ativos mas não destrutivos | Pentests autorizados |
| `aggressive` | Todos | Destrutivos (smuggling, cache) | Labs, CTF, pentests com contrato |
| `unrestricted` | TODOS sem filtro | TODOS sem filtro | Labs controlados (PortSwigger, etc.) |

---

## Variáveis de Ambiente

### Segurança

| Variável | Valores | Propósito |
|----------|---------|-----------|
| `PHANTOM_ALLOW_AGGRESSIVE` | `authorized`, `1`, `true`, `yes` | Desbloqueia modo `aggressive` |
| `PHANTOM_UNRESTRICTED` | `i-understand-the-risks` (exato) | Remove TODAS as proteções HTTP |
| `PHANTOM_SAFE_MODE` | `passive`\|`safe`\|`cautious`\|`standard`\|`aggressive` | Define safety level do HTTP client |

### Configuração

| Variável | Valores | Propósito |
|----------|---------|-----------|
| `PHANTOM_CUSTOM_HEADERS` | JSON string | Headers injetados em TODOS os requests |
| `PHANTOM_VALIDATION_DEBUG` | `0` ou `1` | Output detalhado do validation pipeline |
| `PHANTOM_ENABLE_GLOBAL_SAFETY` | `1`, `true`, `yes` | Substitui httpx.AsyncClient globalmente |

### Scoping de variáveis (inline, apenas para um processo)

```bash
# NÃO usar export — limita ao processo atual
PHANTOM_ALLOW_AGGRESSIVE=authorized PHANTOM_UNRESTRICTED=i-understand-the-risks \
  phantom full https://target.example.com --safe-mode aggressive
```

---

## Opções Globais

Disponíveis em qualquer comando:

```bash
phantom [--verbose|-v] [--debug] [--no-banner] <comando> ...
```

| Opção | Descrição |
|-------|-----------|
| `--verbose`, `-v` | Output detalhado |
| `--debug` | Logging de debug (muito verboso) |
| `--no-banner` | Não mostra o banner ASCII |

---

## Comandos de Scan

### scan

**O comando principal.** Scan configurável com controlo total de módulos, safety, rate, e output.

```bash
phantom scan <target> [opções]
```

| Opção | Tipo | Default | Descrição |
|-------|------|---------|-----------|
| `--output`, `-o` | PATH | auto | Diretório de output |
| `--format`, `-f` | `pdf\|html\|json\|md\|sarif` | `html` | Formato do relatório |
| `--modules`, `-m` | STRING | todos | Módulos (comma-separated ou categoria) |
| `--safe-mode`, `-s` | `passive\|safe\|cautious\|standard\|aggressive` | `safe` | Nível de segurança |
| `--rate`, `-r` | FLOAT | `2.0` | Requests por segundo |
| `--concurrent`, `-c` | INT | `3` | Módulos em paralelo |
| `--scope` | STRING (múltiplo) | — | Domínios adicionais in-scope |
| `--exclude` | STRING (múltiplo) | — | Excluir módulos específicos |
| `--preset` | STRING | — | Carregar preset de bug bounty |
| `--no-recon` | flag | — | Saltar fase de reconhecimento |
| `--no-tools` | flag | — | Saltar integração com ferramentas Linux |
| `--no-chain` | flag | — | Saltar análise de vulnerability chaining |
| `--no-ai` | flag | — | Saltar validação AI |
| `--no-auth` | flag | — | Saltar verificação de autorização |
| `--timeout` | INT | — | Timeout global em segundos |
| `--compliance` | `pci-dss\|hipaa\|gdpr\|nist\|owasp\|all` (múltiplo) | — | Frameworks de compliance |

**Exemplos:**

```bash
# Scan básico (safe mode, 2 req/s)
phantom scan https://example.com

# Scan com módulos específicos
phantom scan https://example.com -m cors,headers,ssl

# Scan com compliance PCI-DSS
phantom scan https://example.com --compliance pci-dss --compliance owasp -f pdf

# Scan standard com mais velocidade
phantom scan https://example.com -s standard -r 10 -c 5

# Scan com scope expandido
phantom scan https://api.example.com --scope cdn.example.com --scope admin.example.com
```

---

### quick

**Scan rápido** — executa apenas 5 módulos essenciais em modo `safe`.

```bash
phantom quick <target> [opções]
```

| Opção | Tipo | Default | Descrição |
|-------|------|---------|-----------|
| `--output`, `-o` | PATH | auto | Diretório de output |
| `--format`, `-f` | `html\|json\|md` | `html` | Formato do relatório |

**Quando usar:** Verificação rápida de um endpoint, triagem inicial, verificar se um alvo está acessível.

```bash
# Check rápido
phantom quick https://api.example.com

# Check rápido com output JSON
phantom quick https://api.example.com -f json
```

---

### full

**Scan completo** — executa todos os 75+ módulos disponíveis ao nível de safety escolhido.

```bash
phantom full <target> [opções]
```

| Opção | Tipo | Default | Descrição |
|-------|------|---------|-----------|
| `--output`, `-o` | PATH | auto | Diretório de output |
| `--format`, `-f` | `pdf\|html\|json\|md\|sarif` | `html` | Formato do relatório |
| `--safe-mode`, `-s` | `safe\|cautious\|standard` | `safe` | Nível de segurança |

**Nota:** O `full` limita o `--safe-mode` a `standard` no máximo. Para `aggressive`, usar `scan`.

**Quando usar:** Auditoria completa de um alvo, gerar relatório abrangente.

```bash
# Full scan em safe mode (só módulos passivos/safe)
phantom full https://example.com

# Full scan com injeções ativas
phantom full https://example.com -s cautious

# Full scan standard com relatório PDF
phantom full https://example.com -s standard -f pdf
```

---

### bounty

**Scan otimizado para bug bounty** — gera automaticamente relatórios HackerOne, estima bounties, adiciona headers de identificação.

```bash
phantom bounty <target> [opções]
```

| Opção | Tipo | Default | Descrição |
|-------|------|---------|-----------|
| `--output`, `-o` | PATH | auto | Diretório de output |
| `--format`, `-f` | `html\|json\|md` | `html` | Formato do relatório |
| `--platform` | `hackerone\|bugcrowd\|intigriti\|other` | `other` | Plataforma de bug bounty |
| `--program-tier` | `entry\|standard\|premium\|enterprise\|top_tier` | `standard` | Tier do programa (para estimativa de bounty) |
| `--rate`, `-r` | FLOAT | `3.0` | Requests por segundo |
| `--estimate` / `--no-estimate` | flag | `True` | Mostrar estimativas de bounty |
| `--header`, `-H` | STRING (múltiplo) | — | Headers customizados |
| `--username`, `-u` | STRING | — | Username (gera `X-Bug-Bounty: user-program`) |
| `--program`, `-p` | STRING | — | Nome do programa (sufixo do header) |
| `--modules`, `-m` | STRING | — | Módulos específicos (comma-separated) |
| `--hackerone-report` / `--no-hackerone-report` | flag | `True` | Gerar relatórios HackerOne |

**Quando usar:** Bug bounty hunting. Gera relatórios prontos para submeter no HackerOne/Bugcrowd.

```bash
# Bounty scan padrão
phantom bounty https://api.example.com --platform hackerone -u myuser --rate 5

# Twilio bug bounty (com header correto)
phantom bounty https://api.twilio.com --platform hackerone --program twilio -u youruser --rate 5

# Bounty scan com módulos específicos
phantom bounty https://api.example.com -m cors,headers -u myuser --program myprogram

# Bounty scan enterprise tier (estimativas mais altas)
phantom bounty https://api.bigcorp.com --platform hackerone --program-tier enterprise -u myuser --rate 3

# Bounty scan sem estimativas
phantom bounty https://api.example.com --no-estimate --platform bugcrowd -u myuser

# Com headers customizados
phantom bounty https://api.example.com -H "Authorization: Bearer token123" -H "X-Research: security" -u myuser
```

**Output gerado automaticamente:**
- `evidence/<domain>/report_<id>_<date>/hackerone_report.md` — Relatório pronto para HackerOne
- `evidence/<domain>/report_<id>_<date>/report_data.json` — Dados estruturados
- `evidence/<domain>/report_<id>_<date>/poc.html` — PoC interativo (para CORS/XSS/CSRF)

---

### client

**Engagement profissional** — scan completo com branding de cliente, IDs de engagement, e compliance mapping.

```bash
phantom client <target> [opções]
```

| Opção | Tipo | Default | Descrição |
|-------|------|---------|-----------|
| `--output`, `-o` | PATH | auto | Diretório de output |
| `--format`, `-f` | `pdf\|html\|json\|md` | `html` | Formato do relatório |
| `--client-name` | STRING | — | Nome da organização cliente |
| `--engagement-id` | STRING | — | Identificador do engagement |
| `--safe-mode`, `-s` | `safe\|cautious\|standard\|aggressive` | `standard` | Nível de segurança |
| `--rate`, `-r` | FLOAT | `10.0` | Requests por segundo |
| `--concurrent`, `-c` | INT | `5` | Módulos em paralelo |
| `--subdomains` / `--no-subdomains` | flag | `True` | Enumeração de subdomínios |
| `--compliance` | `pci-dss\|hipaa\|gdpr\|nist\|owasp\|all` (múltiplo) | — | Frameworks de compliance |

**Quando usar:** Pentests profissionais com contrato assinado, relatórios para cliente.

```bash
# Pentest standard para cliente
phantom client https://app.cliente.com --client-name "ACME Corp" --engagement-id "PT-2026-001"

# Pentest com compliance PCI-DSS (ex: e-commerce)
phantom client https://payments.cliente.com --client-name "ACME Corp" \
  --compliance pci-dss --compliance owasp -s standard -f pdf

# Pentest aggressive (com autorização)
PHANTOM_ALLOW_AGGRESSIVE=authorized \
  phantom client https://app.cliente.com --client-name "ACME Corp" -s aggressive

# Sem enumeração de subdomínios
phantom client https://api.cliente.com --no-subdomains --client-name "ACME Corp"
```

---

## Comandos de Reconhecimento

### recon

**Reconhecimento passivo** — sem testes ativos. Enumera subdomínios, tecnologias, endpoints, parâmetros, WAF.

```bash
phantom recon <target> [opções]
```

| Opção | Tipo | Default | Descrição |
|-------|------|---------|-----------|
| `--output`, `-o` | PATH | — | Ficheiro de output |
| `--subdomains` / `--no-subdomains` | flag | `True` | Enumerar subdomínios |
| `--technologies` / `--no-technologies` | flag | `True` | Fingerprint de tecnologias |
| `--endpoints` / `--no-endpoints` | flag | `True` | Descobrir endpoints |
| `--parameters` / `--no-parameters` | flag | `True` | Descobrir parâmetros |
| `--waf` / `--no-waf` | flag | `True` | Detetar WAF |

**Quando usar:** Fase inicial antes de qualquer teste ativo, mapeamento de superfície de ataque, investigação.

```bash
# Recon completo
phantom recon example.com

# Recon só subdomínios e tecnologias
phantom recon example.com --no-endpoints --no-parameters

# Recon com output em ficheiro
phantom recon example.com -o recon_results.json

# Recon rápido (só WAF)
phantom recon example.com --no-subdomains --no-technologies --no-endpoints --no-parameters
```

---

### waf-detect

**Deteção de WAF** com estratégias de bypass.

```bash
phantom waf-detect <target> [opções]
```

| Opção | Tipo | Default | Descrição |
|-------|------|---------|-----------|
| `--bypass` / `--no-bypass` | flag | `True` | Mostrar estratégias de bypass |

**Quando usar:** Antes de um scan ativo para adaptar payloads ao WAF presente.

```bash
# Detetar WAF com estratégias de bypass
phantom waf-detect https://api.example.com

# Só detetar, sem bypass suggestions
phantom waf-detect https://api.example.com --no-bypass
```

---

## Comandos de Relatório

### report

**Gerar relatório** a partir de um scan anterior.

```bash
phantom report <scan_id> [opções]
```

| Opção | Tipo | Default | Descrição |
|-------|------|---------|-----------|
| `--output`, `-o` | PATH | — | Caminho do ficheiro de output |
| `--format`, `-f` | `pdf\|html\|json\|md\|sarif` | `html` | Formato do relatório |
| `--compliance` | `pci-dss\|hipaa\|gdpr\|nist\|owasp\|all` (múltiplo) | — | Incluir compliance mapping |
| `--bounty` / `--no-bounty` | flag | `False` | Incluir estimativas de bounty |

```bash
# Relatório HTML padrão
phantom report PHANTOM_20260205

# Relatório PDF com compliance
phantom report PHANTOM_20260205 -f pdf --compliance all

# Relatório SARIF (para integração CI/CD)
phantom report PHANTOM_20260205 -f sarif -o results.sarif

# Relatório com estimativas de bounty
phantom report PHANTOM_20260205 --bounty -f md
```

---

### hackerone-report

**Gerar relatórios HackerOne** a partir de um scan anterior. Produz markdown pronto para colar na plataforma.

```bash
phantom hackerone-report <scan_id> [opções]
```

| Opção | Tipo | Default | Descrição |
|-------|------|---------|-----------|
| `--output`, `-o` | PATH | — | Diretório de output |
| `--finding-id`, `-f` | STRING | — | ID de finding específico (senão, todos MEDIUM+) |
| `--all-severities` | flag | — | Incluir findings LOW e INFO |
| `--bounty-header` | STRING | — | Valor do header X-Bug-Bounty |

```bash
# Gerar relatórios para todos os findings MEDIUM+
phantom hackerone-report PHANTOM_20260205

# Relatório para um finding específico
phantom hackerone-report PHANTOM_20260205 -f CORS-001

# Incluir todas as severidades
phantom hackerone-report PHANTOM_20260205 --all-severities

# Com header de bounty
phantom hackerone-report PHANTOM_20260205 --bounty-header "youruser-twilio"

# Output customizado
phantom hackerone-report PHANTOM_20260205 -o ./my_reports
```

---

### chain

**Análise de vulnerability chaining** — visualiza como vulnerabilidades se combinam em cadeias de ataque.

```bash
phantom chain <scan_id> [opções]
```

| Opção | Tipo | Default | Descrição |
|-------|------|---------|-----------|
| `--output`, `-o` | PATH | — | Ficheiro de output |
| `--format`, `-f` | `svg\|html\|dot\|mermaid\|json` | `html` | Formato de visualização |

```bash
# Visualização HTML interativa
phantom chain PHANTOM_20260205

# Exportar como SVG
phantom chain PHANTOM_20260205 -f svg -o chain.svg

# Formato Mermaid (para markdown/docs)
phantom chain PHANTOM_20260205 -f mermaid -o chain.md

# Formato DOT (para Graphviz)
phantom chain PHANTOM_20260205 -f dot -o chain.dot
```

---

### impact

**Avaliação de impacto** — análise de impacto contextualizada por indústria.

```bash
phantom impact <scan_id> [opções]
```

| Opção | Tipo | Default | Descrição |
|-------|------|---------|-----------|
| `--industry` | `finance\|healthcare\|technology\|retail\|government\|other` | `other` | Contexto da indústria |

```bash
# Avaliação genérica
phantom impact PHANTOM_20260205

# Avaliação para setor financeiro (penalidades PCI-DSS)
phantom impact PHANTOM_20260205 --industry finance

# Avaliação para healthcare (HIPAA)
phantom impact PHANTOM_20260205 --industry healthcare
```

---

### compliance

**Mapeamento de compliance** — mapeia findings para frameworks regulatórios.

```bash
phantom compliance <scan_id> [opções]
```

| Opção | Tipo | Default | Descrição |
|-------|------|---------|-----------|
| `--framework`, `-f` | `cwe\|owasp\|pci-dss\|nist\|hipaa\|gdpr\|all` (múltiplo) | `all` | Frameworks |
| `--output`, `-o` | PATH | — | Ficheiro de relatório |

```bash
# Todos os frameworks
phantom compliance PHANTOM_20260205

# Apenas PCI-DSS e OWASP
phantom compliance PHANTOM_20260205 -f pci-dss -f owasp

# Exportar para ficheiro
phantom compliance PHANTOM_20260205 -f all -o compliance_report.json
```

---

## Comandos de Gestão

### status

**Ver estado** de um scan (em curso ou concluído).

```bash
phantom status [scan_id]
```

Se `scan_id` for omitido, mostra o scan mais recente.

---

### list

**Listar scans** anteriores.

```bash
phantom list [opções]
```

| Opção | Tipo | Default | Descrição |
|-------|------|---------|-----------|
| `--limit`, `-n` | INT | `20` | Número de scans a mostrar |

```bash
phantom list
phantom list -n 50
```

---

### resume

**Retomar scan** interrompido.

```bash
phantom resume <scan_id>
```

---

### validate

**Re-validar findings** — corre o validation pipeline novamente.

```bash
phantom validate [finding_id] [opções]
```

| Opção | Tipo | Default | Descrição |
|-------|------|---------|-----------|
| `--scan-id` | STRING | — | Scan ID de onde validar findings |

```bash
# Validar todos os findings de um scan
phantom validate --scan-id PHANTOM_20260205

# Validar um finding específico
phantom validate CORS-001
```

---

### authorize

**Autorizar alvo** — marca um domínio como autorizado para testing.

```bash
phantom authorize <target>
```

```bash
phantom authorize https://api.example.com
```

---

### modules

**Listar módulos** disponíveis, opcionalmente filtrados por categoria.

```bash
phantom modules [opções]
```

| Opção | Tipo | Default | Descrição |
|-------|------|---------|-----------|
| `--category`, `-c` | STRING | — | Filtrar por categoria |

```bash
# Todos os módulos
phantom modules

# Apenas módulos de injeção
phantom modules -c injection
```

---

### presets

**Gerir presets** de configuração para bug bounty programs.

```bash
phantom presets [opções]
```

| Opção | Tipo | Default | Descrição |
|-------|------|---------|-----------|
| `--list`, `-l` | flag | — | Listar presets disponíveis |
| `--show`, `-s` | STRING | — | Mostrar detalhes de um preset |
| `--create`, `-c` | STRING | — | Criar novo preset |

```bash
phantom presets --list
phantom presets --show twilio
phantom presets --create my-program
```

---

## Comandos de Sistema

### health

**Health check** — verifica estado de todos os componentes do PHANTOM.

```bash
phantom health
```

---

### version

**Mostrar versão.**

```bash
phantom version
```

---

### update-kb

**Atualizar knowledge base** de segurança.

```bash
phantom update-kb [opções]
```

| Opção | Tipo | Default | Descrição |
|-------|------|---------|-----------|
| `--source` | `all\|cve\|exploitdb\|payloads\|hacktricks` | `all` | Fonte a atualizar |

```bash
# Atualizar tudo
phantom update-kb

# Só CVEs
phantom update-kb --source cve

# Só payloads
phantom update-kb --source payloads
```

---

## Comandos GDPR

Grupo de comandos para conformidade GDPR — gestão de dados pessoais recolhidos durante scans.

### gdpr status

Estado atual do armazenamento de dados pessoais.

```bash
phantom gdpr status
```

### gdpr cleanup

Limpeza de dados pessoais expirados.

```bash
phantom gdpr cleanup [--dry-run]
```

### gdpr access

Direito de acesso — pesquisar dados pessoais armazenados.

```bash
phantom gdpr access [--email EMAIL] [--ip IP] [--identifier ID]
```

### gdpr erasure

Direito ao esquecimento — apagar dados pessoais.

```bash
phantom gdpr erasure [--email EMAIL] [--ip IP] [--identifier ID] [--confirm]
```

Sem `--confirm`, funciona em modo dry-run.

### gdpr export

Portabilidade de dados — exportar dados pessoais.

```bash
phantom gdpr export [--email EMAIL] [--ip IP] [--identifier ID] [-o OUTPUT]
```

### gdpr inventory

Inventário de dados pessoais armazenados.

```bash
phantom gdpr inventory
```

### gdpr report

Relatório GDPR completo.

```bash
phantom gdpr report [-o OUTPUT]
```

---

## Combinações Práticas por Cenário

### Cenário 1: Bug Bounty (HackerOne/Bugcrowd)

```bash
# Scan padrão para bug bounty
phantom bounty https://api.target.com \
  --platform hackerone \
  --program targetname \
  -u myusername \
  --rate 5

# Só CORS check
phantom bounty https://api.target.com \
  --platform hackerone \
  -m cors \
  -u myusername \
  --program targetname \
  --rate 5

# Relatório de scan anterior
phantom hackerone-report PHANTOM_20260205 -f CORS-001
```

### Cenário 2: PortSwigger Labs / CTF (Tudo Desbloqueado)

```bash
# Inline — todas as proteções desligadas, só para este processo
PHANTOM_ALLOW_AGGRESSIVE=authorized \
PHANTOM_UNRESTRICTED=i-understand-the-risks \
  phantom full https://labid.web-security-academy.net --safe-mode aggressive

# Ou com scan e módulos específicos
PHANTOM_ALLOW_AGGRESSIVE=authorized \
PHANTOM_UNRESTRICTED=i-understand-the-risks \
  phantom scan https://labid.web-security-academy.net \
    -s aggressive -m smuggling,cache -r 10 -c 5
```

### Cenário 3: Pentest Profissional (Com Contrato)

```bash
# Standard — testes ativos sem destruição
phantom client https://app.cliente.com \
  --client-name "ACME Corp" \
  --engagement-id "PT-2026-001" \
  -s standard \
  --compliance pci-dss --compliance owasp \
  -f pdf

# Aggressive — com autorização explícita do cliente
PHANTOM_ALLOW_AGGRESSIVE=authorized \
  phantom client https://app.cliente.com \
    --client-name "ACME Corp" \
    --engagement-id "PT-2026-001" \
    -s aggressive \
    --compliance all \
    -f pdf
```
### Cenário 4: Reconhecimento Inicial (Sem Testes)

```bash
# Recon completo
phantom recon target.com

# Só WAF detection
phantom waf-detect https://api.target.com

# Quick check (5 módulos safe)
phantom quick https://api.target.com -f json
```

### Cenário 5: Relatórios Pós-Scan

```bash
# Ver scans anteriores
phantom list

# Estado de um scan
phantom status PHANTOM_20260205

# Gerar relatório PDF com compliance
phantom report PHANTOM_20260205 -f pdf --compliance all

# Relatório HackerOne
phantom hackerone-report PHANTOM_20260205

# Visualização de chains
phantom chain PHANTOM_20260205 -f html

# Avaliação de impacto para fintech
phantom impact PHANTOM_20260205 --industry finance
```

### Cenário 6: Scan em Batch (Múltiplos Alvos)

```bash
# Sequencial com pausa entre alvos
for target in \
  "https://api.target1.com" \
  "https://api.target2.com" \
  "https://app.target3.com"; do
  echo "=== Scanning: $target ==="
  phantom bounty "$target" --platform hackerone -u myuser --rate 5
  sleep 10
done

# Ou um por um com &&
phantom bounty https://api.t1.com --platform hackerone -u me --rate 5 && \
phantom bounty https://api.t2.com --platform hackerone -u me --rate 5
```

### Cenário 7: Scan Focado em Módulos Específicos

```bash
# Só headers e SSL
phantom scan https://example.com -m headers,ssl

# Só injeções SQL
phantom scan https://example.com -m sqli -s cautious

# Tudo exceto módulos lentos
phantom scan https://example.com --exclude subdomain --exclude ports

# Com preset guardado
phantom scan https://example.com --preset my-program
```

---

## Tabela de Módulos por Safety Level

### Passive (Level 0) — Interação mínima

| Módulo | Descrição |
|--------|-----------|
| `waf` | Deteção de Web Application Firewall |
| `cdn` | Deteção de CDN |
| `ip_geolocate` | Geolocalização de IP |

### Safe (Level 1) — Apenas leitura

| Módulo | Descrição |
|--------|-----------|
| `headers` | Análise de security headers |
| `ssl` | Verificação de certificados SSL/TLS |
| `cors` | Verificação de CORS misconfiguration |
| `directory` | Enumeração de diretórios |
| `sensitive_file` | Deteção de ficheiros sensíveis |
| `info_disclosure` | Information disclosure |
| `cms` | Deteção de CMS |
| `tech` | Fingerprinting de tecnologias |
| `subdomain` | Enumeração de subdomínios |
| `ports` | Port scanning |
| `cloud` | Cloud misconfiguration |
| `k8s` | Kubernetes exposure |
| `docker` | Docker exposure |
| `firebase` | Firebase misconfiguration |
| `supabase` | Supabase misconfiguration |
| `appwrite` | Appwrite misconfiguration |

### Cautious (Level 2) — Payloads ativos via HTTP standard

| Módulo | Descrição |
|--------|-----------|
| `sqli` | SQL Injection |
| `xss` | Cross-Site Scripting (reflected) |
| `dom_xss` | DOM-based XSS |
| `cmdi` | Command Injection |
| `lfi` | Local File Inclusion |
| `rfi` | Remote File Inclusion |
| `xxe` | XML External Entity |
| `ssti` | Server-Side Template Injection |
| `nosql` | NoSQL Injection |
| `ldap` | LDAP Injection |
| `xpath` | XPath Injection |
| `crlf` | CRLF Injection |
| `ssrf` | Server-Side Request Forgery |
| `idor` | Insecure Direct Object Reference |
| `auth` | Authentication testing |
| `authz` | Authorization testing |
| `jwt` | JWT vulnerabilities |
| `oauth` | OAuth vulnerabilities |
| `saml` | SAML vulnerabilities |
| `csrf` | Cross-Site Request Forgery |
| `clickjack` | Clickjacking |
| `mass_assign` | Mass Assignment |
| `proto_pollution` | Prototype Pollution |
| `deserialization` | Insecure Deserialization |
| `api` | API security testing |
| `graphql` | GraphQL testing |
| `grpc` | gRPC testing |
| `websocket` | WebSocket testing |

### Standard (Level 3) — Potencialmente disruptivo

| Módulo | Descrição |
|--------|-----------|
| `postexploit` | Post-exploitation checks |
| `dns_rebind` | DNS Rebinding |
| `race` | Race conditions |
| `business_logic` | Business logic flaws |
| `timing` | Timing attacks |
| `rls_bypass` | Rate limit bypass |

### Aggressive (Level 4) — Raw sockets, afeta outros utilizadores

| Módulo | Descrição |
|--------|-----------|
| `smuggling` | HTTP Request Smuggling |
| `cache` | Cache Poisoning |
| `cache_deception` | Web Cache Deception |

---

## Formatos de Output

| Formato | Extensão | Uso |
|---------|----------|-----|
| `html` | `.html` | Relatório visual interativo (default) |
| `pdf` | `.pdf` | Relatório para cliente/stakeholders |
| `json` | `.json` | Dados estruturados para automação |
| `md` | `.md` | Markdown (HackerOne, GitHub, docs) |
| `sarif` | `.sarif` | Static Analysis Results (CI/CD, GitHub Security) |
| `svg` | `.svg` | Visualização de chains (apenas `chain`) |
| `dot` | `.dot` | Graphviz DOT (apenas `chain`) |
| `mermaid` | `.mermaid` | Mermaid diagram (apenas `chain`) |

---

## Referência Rápida

| Quero... | Comando |
|----------|---------|
| Scan rápido | `phantom quick <url>` |
| Scan completo safe | `phantom full <url>` |
| Bug bounty HackerOne | `phantom bounty <url> --platform hackerone -u user --program prog --rate 5` |
| Pentest profissional | `phantom client <url> --client-name "X" -s standard` |
| Só reconhecimento | `phantom recon <domain>` |
| Detetar WAF | `phantom waf-detect <url>` |
| Lab/CTF (tudo ON) | `PHANTOM_ALLOW_AGGRESSIVE=authorized PHANTOM_UNRESTRICTED=i-understand-the-risks phantom full <url> -s aggressive` |
| Ver módulos | `phantom modules` |
| Ver scans | `phantom list` |
| Relatório PDF | `phantom report <id> -f pdf` |
| Relatório HackerOne | `phantom hackerone-report <id>` |
| Compliance PCI-DSS | `phantom compliance <id> -f pci-dss` |
| GDPR cleanup | `phantom gdpr cleanup` |




PHANTOM_NO_TOR=1 \
PHANTOM_NO_CIRCUIT_BREAKER=1 \
PHANTOM_ALLOW_AGGRESSIVE=authorized \
PHANTOM_UNRESTRICTED=i-understand-the-risks \
  phantom scan http://localhost:3000 --safe-mode aggressive -r 30 -c 10