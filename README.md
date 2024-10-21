# Openrelik worker for analyzing configuration files.

## Supported Configuration Analyzers
* SSH Daemon - artifact:SshConfigFile
* Jupyter Notebook - artifact:JupyterConfigFile
* Jenkins - filename:config.xml

## Installation
Add the below configuration to the OpenRelik `docker-compose.yml` file.

```
openrelik-worker-config-analyzer:
    container_name: openrelik-worker-config-analyzer
    image: ghcr.io/openrelik/openrelik-worker-config-analyzer:${OPENRELIK_WORKER_CONFIG_ANALYZER_VERSION:-latest}
    restart: always
    environment:
      - REDIS_URL=redis://openrelik-redis:6379
      - OPENRELIK_PYDEBUG=0
    volumes:
      - ./data:/usr/share/openrelik/data
    command: "celery --app=src.app worker --task-events --concurrency=4 --loglevel=INFO -Q openrelik-worker-config-analyzer"
    # ports:
      # - 5678:5678 # For debugging purposes.
```