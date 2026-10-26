# Generates the numbering plan the DSLAM serves in local and CI deployments
FROM python:3.13-slim-bookworm

RUN apt update && apt install -y iproute2

COPY --chmod=555 init.py /usr/local/bin/game-init

CMD ["game-init", "/plan/numbering-plan.yaml"]
