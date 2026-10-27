# syntax=docker/dockerfile:1
FROM debian:12.8@sha256:0000000000000000000000000000000000000000000000000000000000000000 AS build
RUN apt-get update \
    && apt-get install -y curl git=1:2.39.5-0+deb12u1 \
    && rm -rf /var/lib/apt/lists/*
COPY .env /src/.env
COPY .env.example /src/.env.example
CMD ["make", "build"]
CMD ["make", "test"]

FROM alpine:3.20.3@sha256:1111111111111111111111111111111111111111111111111111111111111111
RUN --mount=type=secret,id=npm_token,env=NPM_TOKEN apk add --no-cache nodejs npm=10.9.1-r0
COPY --from=build /src/app /app
USER 10001:10001
HEALTHCHECK CMD ["/app/healthcheck"]
ENTRYPOINT ["/app/run"]
