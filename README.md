# PenteIA - Sistema de Coleta e Análise de Dados para IA de Segurança

Este projeto é uma suite completa de ferramentas Python para coleta automatizada, processamento e visualização de dados de vulnerabilidades de segurança em ambientes de teste controlados. Os dados coletados e processados são fundamentais para treinar modelos de inteligência artificial capazes de detectar e classificar vulnerabilidades em aplicações web.

![PenteIA Logo](https://via.placeholder.com/800x200/0078D7/FFFFFF?text=PenteIA+Security+Data+Suite)

## 🚀 Ambiente de Teste Recomendado

Para obter dados funcionais com vulnerabilidades reais, recomendamos fortemente o uso do DVWA (Damn Vulnerable Web Application) em um contêiner Docker:

```bash
# Instalar e executar DVWA usando o script fornecido
chmod +x setup_dvwa.sh
./setup_dvwa.sh
```

O DVWA estará disponível em http://localhost/DVWA/ com as seguintes credenciais:
- Usuário: `admin`
- Senha: `password`

Para parar o ambiente de teste:
```bash
docker stop dvwa
```

### Ambientes Alternativos

O coletor também suporta outros ambientes de teste populares. Confira os arquivos de configuração de exemplo em `exemplos/`:

- **OWASP WebGoat**: Ideal para vulnerabilidades mais complexas
  ```bash
  docker run -p 8080:8080 -p 9090:9090 webgoat/webgoat
  ```

- **OWASP Juice Shop**: Aplicação web moderna com vulnerabilidades realistas
  ```bash
  docker run -p 3000:3000 bkimminich/juice-shop
  ```

## ✨ Funcionalidades

### Coleta de Dados (data_collector.py)
- **Teste automatizado** de múltiplos payloads em diferentes URLs
- **Suporte a vários tipos de vulnerabilidades**:
  - SQL Injection (SQLi)
  - Cross-Site Scripting (XSS)
  - Cross-Site Request Forgery (CSRF)
  - Command Injection
  - NoSQL Injection
  - E outros tipos configuráveis
- **Autenticação integrada** para ambientes que requerem login
- **Detecção inteligente** de sucesso na exploração
- **Configuração flexível** via arquivo JSON
- **Execução paralela** para coleta eficiente (multi-threading)
- **Logging detalhado** das operações e resultados
- **Exportação de resultados** em formato CSV com diferentes níveis de detalhamento

### Processamento de Dados (data_processor.py)
- **Rotulagem automática** utilizando heurísticas avançadas
- **Análise estatística** para detecção de outliers
- **Geração de datasets** específicos por tipo de vulnerabilidade
- **Normalização e limpeza** de dados para treinamento de IA
- **Análise de correlação** entre variáveis numéricas
- **Detecção avançada** de padrões em respostas HTTP

### Visualização de Dados (visualizador.py)
- **Gráficos interativos** para análise de vulnerabilidades
- **Distribuição estatística** por tipo de payload
- **Métricas de taxa de sucesso** por categoria de ataque
- **Análise comparativa** entre diferentes conjuntos de dados
- **Exportação de visualizações** em formato PNG de alta resolução

## 📋 Requisitos

- Python 3.6 ou superior
- Docker (para ambientes de teste)
- Bibliotecas Python:
  - requests>=2.28.0
  - pandas>=1.4.0
  - urllib3>=1.26.12
  - numpy>=1.23.5
  - matplotlib>=3.6.2 (opcional, para visualizações)
  - seaborn>=0.12.1 (opcional, para visualizações avançadas)
  - scikit-learn>=1.2.0 (opcional, para análise avançada)
  - tqdm>=4.64.0 (para indicadores de progresso)
  - colorama>=0.4.5 (para saída colorida no terminal)

## 🔧 Instalação

```bash
# Clonar o repositório
git clone https://github.com/seu-usuario/penteia-data-collector.git
cd penteia-data-collector

# Instalar dependências
pip install -r requirements.txt

# Configurar ambiente de teste
./setup_dvwa.sh
```

## ⚙️ Configuração

O arquivo `config.json` permite configurar todos os aspectos da coleta de dados:

```json
{
    "urls_alvo": [
        "http://localhost/DVWA/vulnerabilities/sqli/?id=1&Submit=Submit"
    ],
    "payloads": {
        "sqli": [
            "' or 1=1--", 
            "1' UNION SELECT 1,2,3--"
        ]
    },
    "auth": {
        "type": "dvwa",
        "login_url": "http://localhost/DVWA/login.php",
        "username": "admin",
        "password": "password"
    }
}
```

Parametrização detalhada:

- **urls_alvo**: Lista de endpoints a serem testados
- **payloads**: Agrupados por categoria, contendo os vetores de ataque
- **auth**: Configurações de autenticação específicas para cada ambiente
- **headers**: Cabeçalhos HTTP personalizados
- **max_workers**: Número de threads paralelas (recomendado: 3-5)
- **timeout**: Tempo limite para cada requisição em segundos
- **delay_between_requests**: Intervalo entre requisições para evitar sobrecarga

## 🚦 Uso

### Coleta de Dados

```bash
# Executar a coleta com a configuração padrão
python data_collector.py

# Usando uma configuração específica
python data_collector.py --config exemplos/config_webgoat.json
```

### Processamento de Dados

```bash
# Processar o arquivo de dados mais recente
python data_processor.py

# Processar um arquivo específico
python data_processor.py resultados/raw_data_20230615_120000.csv

# Ajustar a sensibilidade da detecção (maior valor = mais detecções)
python data_processor.py --sensibilidade 2.0
```

### Visualização de Dados

```bash
# Visualizar o dataset de treinamento mais recente
python visualizador.py

# Visualizar um dataset específico
python visualizador.py dados_treinamento/training_sqli.csv
```

## 📊 Estrutura dos Resultados

Os resultados da coleta são salvos no diretório `resultados/` com timestamp:

1. **Dados completos** (`raw_data_YYYYMMDD_HHMMSS.csv`):
   - Contém todas as informações coletadas, incluindo conteúdo HTML das respostas

2. **Resumo** (`raw_data_YYYYMMDD_HHMMSS_resumo.csv`):
   - Versão condensada sem o HTML para análise rápida

3. **Sucessos** (`raw_data_YYYYMMDD_HHMMSS_sucessos.csv`):
   - Apenas os payloads que tiveram sucesso na exploração

## 🔍 Processamento dos Dados

O projeto inclui um processador de dados avançado para preparar datasets de treinamento para modelos de IA:

```bash
# Processar o arquivo de dados mais recente
python data_processor.py

# Processar um arquivo específico
python data_processor.py resultados/raw_data_20230615_120000.csv

# Ajustar a sensibilidade da detecção (maior valor = mais detecções)
python data_processor.py --sensibilidade 2.0

# Forçar o uso do arquivo completo, não o resumo
python data_processor.py --completo

# Desativar análise avançada (mais rápido, mas menos preciso)
python data_processor.py --simples

# Desativar geração de gráficos
python data_processor.py --sem-graficos
```

O processador aplica heurísticas avançadas e análise estatística para rotular os dados e gera:

1. **Dataset completo** (`dados_treinamento/training_data.csv`):
   - Contém as colunas `text`, `label`, `tipo_payload` e `payload`
   - Rótulos: 1 (vulnerável) e 0 (não vulnerável)

2. **Datasets específicos** por tipo de vulnerabilidade:
   - `dados_treinamento/training_sqli.csv` (SQL Injection)
   - `dados_treinamento/training_xss.csv` (Cross-Site Scripting)
   - `dados_treinamento/training_csrf.csv` (Cross-Site Request Forgery)
   - `dados_treinamento/training_cmd_injection.csv` (Command Injection)

3. **Estatísticas e visualizações**:
   - Arquivos JSON com estatísticas detalhadas
   - Gráficos de distribuição de vulnerabilidades
   - Análise de correlação entre variáveis
   - Tudo salvo em `dados_treinamento/estatisticas/`

### 📊 Detecção de Vulnerabilidades

O processador utiliza múltiplas técnicas para identificar vulnerabilidades:

- **Heurísticas por tipo**: Regras específicas para cada tipo de vulnerabilidade
- **Análise de conteúdo**: Busca por padrões e indicadores nas respostas
- **Detecção de outliers**: Identifica comportamentos anômalos estatisticamente
- **Análise de correlação**: Examina relações entre variáveis para identificar padrões
- **Análise de resposta HTTP**: Examina códigos de status, tempos de resposta e tamanhos
- **Análise de payload refletido**: Detecta quando o payload é retornado na resposta
- **Detecção de erros específicos**: Identifica mensagens de erro características de cada vulnerabilidade

A sensibilidade da detecção pode ser ajustada com o parâmetro `--sensibilidade`.

#### Matriz de Indicadores de Detecção

| Tipo de Vulnerabilidade | Indicadores Primários | Indicadores Secundários |
|-------------------------|------------------------|-------------------------|
| SQL Injection           | Erros SQL, múltiplos resultados | Tempo de resposta, padrões de dados |
| XSS                     | Payload refletido, tags HTML injetadas | Elementos JavaScript, eventos DOM |
| Command Injection       | Saída de comandos, listagem de arquivos | Padrões de permissão, conteúdo de sistema |
| CSRF                    | Confirmações de alteração, tokens | Mensagens de sucesso, redirecionamentos |
| NoSQL Injection         | Erros de banco, resultados inesperados | Tempo de resposta, quantidade de dados |

## 📈 Análise dos Dados

Os dados coletados podem ser usados para:

- Treinar modelos de IA para detectar vulnerabilidades
- Analisar padrões de resposta para diferentes tipos de ataques
- Gerar datasets para ferramentas de segurança automatizadas
- Criar casos de teste para verificação de segurança

## 🔄 Arquitetura do Sistema

O PenteIA é composto por três módulos principais que trabalham em conjunto:

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│  data_collector  │────>│  data_processor │────>│   visualizador   │
└─────────────────┘     └─────────────────┘     └─────────────────┘
        │                       │                       │
        ▼                       ▼                       ▼
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│  raw_data.csv   │────>│ training_data.csv│────>│   visualizações │
└─────────────────┘     └─────────────────┘     └─────────────────┘
```

1. **Coleta de Dados**: O módulo `data_collector.py` interage com aplicações vulneráveis, enviando payloads e coletando respostas.

2. **Processamento**: O módulo `data_processor.py` analisa os dados brutos, aplica heurísticas para rotulagem e gera datasets estruturados para treinamento.

3. **Visualização**: O módulo `visualizador.py` cria representações visuais dos dados processados para facilitar a análise e interpretação.

Esta arquitetura modular permite que cada componente seja utilizado independentemente ou como parte do fluxo completo de trabalho.

## 🔒 Segurança

⚠️ **IMPORTANTE**: Este script deve ser executado APENAS em ambientes de teste controlados. Nunca use esta ferramenta contra sistemas de produção ou sites sem permissão explícita.

O uso indevido desta ferramenta pode violar leis de segurança cibernética e resultar em penalidades legais.

## 🤝 Contribuição

Contribuições são bem-vindas! Para contribuir:

1. Faça um fork do projeto
2. Crie uma nova branch (`git checkout -b feature/nova-funcionalidade`)
3. Faça commit das suas alterações (`git commit -m 'Adiciona nova funcionalidade'`)
4. Envie para o branch (`git push origin feature/nova-funcionalidade`)
5. Abra um Pull Request

## 📜 Licença

Este projeto está licenciado sob a Licença MIT - veja o arquivo LICENSE para detalhes.

## 📞 Contato

Para dúvidas, sugestões ou colaborações, entre em contato através do GitHub.

---

<p align="center">
  Desenvolvido com ❤️ para a comunidade de segurança e IA<br>
  <b>PenteIA v2.0</b> - Sistema de Coleta e Análise de Dados para Segurança<br>
  © 2023-2025 Todos os direitos reservados
</p>
