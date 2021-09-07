# ADSyncer sample Docker image

## Build & test

```bash
docker build -t adsyncer .
docker run --rm -e AZURE_TENANT_ID=x -e AZURE_CLIENT_ID=y adsyncer
```
