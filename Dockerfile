# PEGASUS — zkVerify Agent Games agent
# Node 20 slim, non-root, no secrets baked in. Secrets arrive as
# environment variables at deploy/run time only.
FROM node:20-slim

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci --omit=dev --no-audit --no-fund && npm cache clean --force

COPY src/ ./src/
COPY scripts/ ./scripts/

# Circuit artifacts: the .wasm/.zkey binaries are NOT committed to the repo.
# The image downloads them from the official Agent Games site at build time
# (URLs from https://agentgames.zkverify.io/api/circuit-info) and verifies
# SHA256 before use; the build fails if any hash mismatches.
COPY circuits/*.vk.json ./circuits/
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && cd circuits \
 && curl -fsSL -o gatekeeper.wasm https://agentgames.zkverify.io/circuits/gatekeeper.wasm \
 && curl -fsSL -o gatekeeper_final.zkey https://agentgames.zkverify.io/circuits/gatekeeper_final.zkey \
 && curl -fsSL -o vfy-policy.wasm https://agentgames.zkverify.io/circuits/vfy-policy.wasm \
 && curl -fsSL -o vfy-policy_final.zkey https://agentgames.zkverify.io/circuits/vfy-policy_final.zkey \
 && echo "be00aefe3c8ba910951a242f50e55937bf82a0375ad4b69c2ef10629ab92764f  gatekeeper.wasm" | sha256sum -c - \
 && echo "adfe95a439a7063a82a4967ef026d2dd6857a4d02c63b3caf63dac02e01af80d  gatekeeper_final.zkey" | sha256sum -c - \
 && echo "bc0998250d2baf75b89deef5306867ffa7085a08d4f7d2caf0dd63a060b134d2  vfy-policy.wasm" | sha256sum -c - \
 && echo "f9666a1655279ef27f7fee6d535ac8aa9e39286ac40ff6279fea87c21ab6ce41  vfy-policy_final.zkey" | sha256sum -c -

# Writable data dir for the persistent seen-set (overridden by the Fly
# volume mount in production; harmless fallback for local runs).
RUN mkdir -p /app/data && chown -R node:node /app

USER node

ENV NODE_ENV=production
ENV PORT=8080
ENV SEEN_SET_PATH=/app/data/seen-set.json

EXPOSE 8080

CMD ["node", "src/index.js"]
