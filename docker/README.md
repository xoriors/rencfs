# Publish to Docker Hub

**One time:**

```bash
docker login
```

**Every time:**

```bash
docker buildx build --sbom=true --provenance=true -f Dockerfile -t xorio42/rencfs ..
docker tag xorio42/rencfs:latest xorio42/rencfs:latest
docker push xorio42/rencfs:latest
```

**Access it** https://hub.docker.com/r/xorio42/rencfs
