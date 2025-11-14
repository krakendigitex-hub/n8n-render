FROM n8nio/n8n:latest

# Define timezone (opcional)
ENV GENERIC_TIMEZONE="America/Sao_Paulo"

# Diretório de dados persistentes
VOLUME /home/node/.n8n
