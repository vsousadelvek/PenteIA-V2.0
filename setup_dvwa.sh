#!/bin/bash

echo "=== Script de configuração do DVWA para coleta de dados ==="
echo "Este script configura um ambiente Docker com DVWA para teste"

# Verifica se o Docker está instalado
if ! command -v docker &> /dev/null; then
    echo "Docker não encontrado. Por favor, instale o Docker primeiro."
    exit 1
fi

echo "Docker encontrado. Preparando ambiente DVWA..."

# Baixar e executar a imagem Docker do DVWA
echo "Baixando e iniciando o contêiner DVWA..."
docker run --rm -d -p 80:80 --name dvwa vulnerables/web-dvwa

echo "Aguardando o DVWA iniciar (30 segundos)..."
sleep 30

echo ""
echo "=== DVWA Configurado ==="
echo "Acesse http://localhost/DVWA/"
echo "Usuário: admin"
echo "Senha: password"
echo ""
echo "Use estas configurações no seu config.json"
echo "Execute 'docker stop dvwa' quando terminar de usar"
