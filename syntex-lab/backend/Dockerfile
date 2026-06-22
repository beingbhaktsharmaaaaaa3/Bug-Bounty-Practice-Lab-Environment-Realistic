FROM node:20-alpine

WORKDIR /app

# Install dependencies
COPY package*.json ./
RUN npm install --omit=dev

# Copy source
COPY . .

# Uploads directory
RUN mkdir -p public/uploads && chmod 777 public/uploads

EXPOSE 3000

# Wait for DB → seed → start
CMD ["sh", "-c", "sleep 8 && node database/seed.js && node server.js"]
