FROM arigaio/atlas:latest-alpine@sha256:617998b4c04b9e8fddc51c9e3f5c51bb1d5512b8fdc80c8baf8fa04417fb28c4

WORKDIR /app

# Copy the migration files
COPY migrations ./migrations

# Copy the atlas migration script and make it executable
COPY atlas.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
