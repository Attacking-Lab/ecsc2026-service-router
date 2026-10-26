FROM python:3.13-slim-bookworm AS builder

RUN apt update && apt install -y build-essential
COPY tools /tools
WORKDIR /tools
RUN make -B

FROM python:3.13-slim-bookworm

RUN apt update && apt install -y git

COPY --from=docker.io/astral/uv:latest /uv /uvx /bin

WORKDIR /app

RUN --mount=type=cache,target=/root/.cache/uv \
	--mount=type=bind,source=uv.lock,target=uv.lock \
	--mount=type=bind,source=pyproject.toml,target=pyproject.toml \
	uv sync --frozen --exact --compile-bytecode --no-install-project --no-dev

COPY --from=builder /tools /tools

COPY uv.lock pyproject.toml main.py gunicorn.conf.py ./
COPY patmy/ ./patmy/
COPY service/ ./service/
COPY zephyr.elf ./

CMD ["uv", "run", "--no-sync", "gunicorn", "-c", "gunicorn.conf.py", "main:app"]
