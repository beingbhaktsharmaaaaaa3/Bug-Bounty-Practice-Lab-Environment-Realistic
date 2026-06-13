FROM node:20-alpine

WORKDIR /app

# Install dependencies first (layer caching)
COPY package*.json ./
RUN npm install

# Copy source
COPY . .

# Create uploads directory
RUN mkdir -p public/uploads && chmod 777 public/uploads

# Intentional: Running as root (bad practice, realistic target)
# USER node

EXPOSE 3000

# Seed database on startup then run app
CMD ["sh", "-c", "sleep 5 && node database/seed.js && node server.js"]
