# PenteIA - Coletor de Dados para IA de Segurança

Este projeto consiste em um script Python avançado para coleta automatizada de dados de vulnerabilidades de segurança em ambientes de teste controlados. Os dados coletados são fundamentais para treinar modelos de inteligência artificial capazes de detectar e classificar vulnerabilidades em aplicações web.

![PenteIA Logo](https://via.placeholder.com/800x200/0078D7/FFFFFF?text=PenteIA+Data+Collector)

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

- **Teste automatizado** de múltiplos payloads em diferentes URLs
- **Suporte a vários tipos de vulnerabilidades**:
  - SQL Injection (SQLi)
  - Cross-Site Scripting (XSS)
  - Cross-Site Request Forgery (CSRF)
  - Command Injection
  - E outros tipos configuráveis
- **Autenticação integrada** para ambientes que requerem login
- **Detecção inteligente** de sucesso na exploração
- **Configuração flexível** via arquivo JSON
- **Execução paralela** para coleta eficiente
- **Logging detalhado** das operações e resultados
- **Exportação de resultados** em formato CSV com diferentes níveis de detalhamento

## 📋 Requisitos

- Python 3.6 ou superior
- Docker (para ambientes de teste)
- Bibliotecas Python:
  - requests
  - pandas
  - urllib3

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

```bash
# Executar a coleta com a configuração padrão
python data_collector.py

# Usando uma configuração específica
python data_collector.py --config exemplos/config_webgoat.json
```

## 📊 Estrutura dos Resultados

Os resultados da coleta são salvos no diretório `resultados/` com timestamp:

1. **Dados completos** (`raw_data_YYYYMMDD_HHMMSS.csv`):
   - Contém todas as informações coletadas, incluindo conteúdo HTML das respostas

2. **Resumo** (`raw_data_YYYYMMDD_HHMMSS_resumo.csv`):
   - Versão condensada sem o HTML para análise rápida

3. **Sucessos** (`raw_data_YYYYMMDD_HHMMSS_sucessos.csv`):
   - Apenas os payloads que tiveram sucesso na exploração

## 📈 Análise dos Dados

Os dados coletados podem ser usados para:

- Treinar modelos de IA para detectar vulnerabilidades
- Analisar padrões de resposta para diferentes tipos de ataques
- Gerar datasets para ferramentas de segurança automatizadas
- Criar casos de teste para verificação de segurança

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
