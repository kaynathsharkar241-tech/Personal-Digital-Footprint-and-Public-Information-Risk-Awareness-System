FROM node:26.13.1-bookworm AS node-runtime

FROM python:3.13-slim-bookworm

COPY --from=node-runtime /usr/local/bin/node /usr/local/bin/node
COPY --from=node-runtime /usr/local/lib/node_modules /usr/local/lib/node_modules

RUN ln -s /usr/local/lib/node_modules/npm/bin/npm-cli.js /usr/local/bin/npm \
    && ln -s /usr/local/lib/node_modules/npm/bin/npx-cli.js /usr/local/bin/npx

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       libglib2.0-0 libgomp1 libstdc++6 ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY python-ai/requirements-v2.txt /tmp/requirements.txt

RUN python -m pip install --no-cache-dir \
    -r /tmp/requirements.txt

COPY package.json package-lock.json ./

RUN npm ci

COPY . .

RUN npm run lint \
    && npm run build \
    && python python-ai/test_face_engine.py

ENV NODE_ENV=production
ENV FACE_PYTHON_PATH=/usr/local/bin/python
ENV PYTHONUNBUFFERED=1
ENV PORT=10000

EXPOSE 10000

CMD ["npm", "start"]
