FROM node:22.23-alpine@sha256:c610fcdfb1d5b4740dd70c284ed3cb16bb857e0f7166196e36a5501df7a3aa32 AS deps
WORKDIR /app/web
COPY web/package.json web/package-lock.json* ./
RUN npm ci --ignore-scripts

FROM node:22.23-alpine@sha256:c610fcdfb1d5b4740dd70c284ed3cb16bb857e0f7166196e36a5501df7a3aa32 AS build
WORKDIR /app/web
COPY --from=deps /app/web/node_modules ./node_modules
COPY web .
ENV NEXT_TELEMETRY_DISABLED=1
RUN npm run build

FROM gcr.io/distroless/nodejs22-debian13:nonroot@sha256:ec2313763dd43931543bd03830466e0c409ce73a487e8d46f10db72d3b816c1c AS runtime
WORKDIR /app
ENV NODE_ENV=production NEXT_TELEMETRY_DISABLED=1 HOSTNAME=0.0.0.0
LABEL org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.source="https://github.com/y4rvin/CreMore" \
      org.opencontainers.image.vendor="CreMore contributors"
COPY --from=build /app/web/.next/standalone ./
COPY --from=build /app/web/public ./web/public
COPY --from=build /app/web/.next/static ./web/.next/static
# The :nonroot base already runs as 65532; stating it keeps the image non-root
# even if the base tag changes.
USER 65532:65532
EXPOSE 3000
CMD ["web/server.js"]
