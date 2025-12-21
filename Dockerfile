FROM node:20-alpine

WORKDIR /app

COPY package.json package-lock.json* ./
RUN npm install --omit=dev

COPY agent.js ./

ENV NODE_ENV=production
CMD ["node", "agent.js"]
