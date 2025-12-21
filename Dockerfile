# Usa uma imagem Node.js leve (Alpine é otimizada para containers)
FROM node:20-alpine

# Define o diretório de trabalho dentro do contêiner
WORKDIR /usr/src/app

# Copia os arquivos de dependência
COPY package*.json ./

# Instala as dependências
RUN npm install

# Copia todo o código fonte (incluindo server.js, models/ e utils/)
COPY . .

# A porta interna que o Express escuta (definida no seu .env como 3001)
EXPOSE 3001

# Comando para iniciar o servidor
CMD [ "node", "app.js" ]