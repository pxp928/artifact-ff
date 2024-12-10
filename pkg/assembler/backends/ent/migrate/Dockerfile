FROM arigaio/atlas:latest-alpine@sha256:cfb1fa76fb3835afe67a6d39b1c92886406b1265a5e66dc16d792652157eb09f

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
