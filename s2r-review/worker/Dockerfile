FROM python:3.11-slim
RUN apt-get update && apt-get install -y --no-install-recommends iproute2 nftables ca-certificates \
    && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir tree-sitter==0.25.2 tree-sitter-javascript==0.25.0 \
    tree-sitter-typescript==0.23.2 tree-sitter-java==0.23.5 tree-sitter-php==0.24.1
RUN groupadd -g 1000 sandbox && useradd -u 1000 -g sandbox -m -d /sandbox sandbox \
    && mkdir -p /app /input /output /protected /source /blocked \
    && printf 'OUTSIDE_SCOPE_TEST_DATA_ONLY\n' > /protected/canary.txt \
    && printf 'READ_ONLY_TEST_DATA_ONLY\n' > /input/canary.txt \
    && chmod 755 /protected /input && chmod 644 /protected/canary.txt /input/canary.txt \
    && chown -R sandbox:sandbox /input /output
COPY agent.py source_mount.py ai_source.py ast_context.py tree_context.py script_agent.py patch_agent.py verify.py /app/
ENV PYTHONDONTWRITEBYTECODE=1
WORKDIR /output
USER sandbox
CMD ["/bin/sleep", "infinity"]
