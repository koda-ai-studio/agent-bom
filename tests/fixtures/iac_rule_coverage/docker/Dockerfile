FROM ubuntu:latest
ARG API_TOKEN
ENV DB_PASSWORD=changeme
COPY --chown=0:0 app/ /app/
COPY . .
COPY --chmod=0777 run.sh /run.sh
RUN chmod 777 /app
EXPOSE 22
EXPOSE 8000-9000
RUN sudo apt-get install -y curl
RUN curl -fsSL https://example.com/install.sh | sh
RUN pip install requests
WORKDIR app
SHELL ["/bin/bash", "-c"]
RUN --network=host curl -fsS https://example.com
USER root
HEALTHCHECK CMD true
