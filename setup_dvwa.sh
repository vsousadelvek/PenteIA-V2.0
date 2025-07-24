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
#!/bin/bash

# Script para configurar o ambiente DVWA (Damn Vulnerable Web Application)
# para testes de segurança

echo "┌────────────────────────────────────────────────┐"
echo "│  PenteIA - Setup do Ambiente de Teste DVWA    │"
echo "└────────────────────────────────────────────────┘"
echo 

# Verificar se o Docker está instalado
if ! command -v docker &> /dev/null; then
    echo "[ERRO] Docker não encontrado. Por favor, instale o Docker primeiro."
    echo "Visite: https://docs.docker.com/get-docker/"
    exit 1
fi

# Verificar se o contêiner DVWA já está em execução
if docker ps | grep -q "dvwa"; then
    echo "[INFO] DVWA já está em execução. Reiniciando..."
    docker stop dvwa
    docker rm dvwa
fi

echo "[INFO] Baixando e iniciando o contêiner DVWA..."

# Baixar e executar o contêiner DVWA
docker run --name dvwa -d -p 80:80 vulnerables/web-dvwa

if [ $? -ne 0 ]; then
    echo "[ERRO] Falha ao iniciar o contêiner DVWA."
    exit 1
fi

echo "[INFO] Aguardando inicialização do serviço (15 segundos)..."
sleep 15

echo "[SUCESSO] DVWA iniciado com sucesso!"
echo 
echo "Acesse: http://localhost/DVWA/"
echo "Usuário: admin"
echo "Senha: password"
echo 
echo "Após o login, acesse Setup e clique em 'Create / Reset Database'"
echo "Em seguida, configure o nível de segurança (DVWA Security) para 'low'"
echo 
echo "Para parar o contêiner: docker stop dvwa"
echo "Para reiniciar: docker start dvwa"
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
