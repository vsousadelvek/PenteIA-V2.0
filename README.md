# Coletor de Dados para IA de Segurança

Este projeto consiste em um script Python para coleta de dados de vulnerabilidades de segurança em um ambiente de teste local. Esses dados são utilizados para treinar modelos de IA para detecção de vulnerabilidades.

## Funcionalidades

- Teste automatizado de múltiplos payloads em diferentes URLs
- Suporte a vários tipos de vulnerabilidades (SQL Injection, XSS, CSRF, etc.)
- Configuração flexível via arquivo JSON
- Execução paralela para maior eficiência
- Logging detalhado das operações
- Exportação de resultados em formato CSV

## Requisitos

- Python 3.6 ou superior
- Bibliotecas: requests, pandas

## Instalação

```bash
pip install -r requirements.txt
```

## Configuração

Edite o arquivo `config.json` para configurar:

- URLs alvo para teste
- Payloads por categoria de vulnerabilidade
- Headers HTTP personalizados
- Número máximo de workers para execução paralela
- Timeout das requisições
- Arquivo de saída
- Delay entre requisições

## Uso

```bash
python data_collector.py
```

## Estrutura dos Resultados

Os resultados são salvos em dois formatos:

1. **Dados completos**: Inclui todo o conteúdo HTML das respostas
2. **Resumo**: Versão compacta sem o HTML para análise rápida

## Segurança

**IMPORTANTE**: Este script deve ser executado apenas em ambientes de teste controlados. Não utilize em sistemas de produção ou em sites sem permissão explícita.

## Contribuição

Contribuições são bem-vindas! Sinta-se à vontade para abrir issues ou enviar pull requests com melhorias.
