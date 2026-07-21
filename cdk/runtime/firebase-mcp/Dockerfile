# Stage 1: Build the esbuild bundle of firebase-tools MCP
FROM public.ecr.aws/docker/library/node:22-bookworm-slim AS builder

WORKDIR /build

# Install firebase-tools and esbuild
RUN npm install firebase-tools@latest esbuild --no-save

# Bundle firebase-tools MCP entry point into a single CJS file
RUN npx esbuild node_modules/firebase-tools/lib/mcp/index.js \
  --bundle --platform=node --format=cjs \
  --outfile=firebase-mcp-bundle.cjs \
  --external:re2 --external:ssh2 --external:cpu-features \
  --external:encoding --external:dtrace-provider --external:@mapbox \
  --minify

# Copy templates (firebase-tools reads them at runtime via __dirname/../templates)
RUN cp -r node_modules/firebase-tools/templates ./templates

# Copy schema (firebase-tools reads firebase-config.json via __dirname/../schema)
RUN cp -r node_modules/firebase-tools/schema ./schema

# Stage 2: Minimal runtime image
FROM public.ecr.aws/docker/library/node:22-alpine

WORKDIR /app

# Install MCP SDK (bridge's transport layer)
COPY package.json ./
RUN npm install --omit=dev && npm cache clean --force

# Copy esbuild bundle — __dirname will be /app, so templates go to /templates (../templates)
COPY --from=builder /build/firebase-mcp-bundle.cjs ./

# Templates must be at ../templates relative to the bundle file's __dirname (/app)
COPY --from=builder /build/templates /templates

# Schema must be at ../schema relative to the bundle file's __dirname (/app)
COPY --from=builder /build/schema /schema

# Copy the server entry point
COPY server.mjs ./

ENV PORT=8000
EXPOSE 8000

CMD ["node", "server.mjs"]
