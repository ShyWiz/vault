# WIP: vault - ECR token secrets engine plugin

A plugin for Hashicorp Vault that provides the ability to generate ECR token to private registries through the vault interface.

## Capabilities

- Specifying read only access or write access to a configured vault role
- Ability to request ttl for token up to 12 hours

## Dev testing code snippets

```sh
go build -o ./plugins/vault-plugin-secrets-ecr cmd/ecr/main.go && \
kill -9 $(ps -ef | grep -m 1 "vault server -dev" | awk '{$NF=" "; print $2}') || true && \
vault server -dev -dev-plugin-dir=$(pwd)/plugins -dev-root-token-id=root &
```

```sh
vault login root && \
vault secrets enable -path=ecr vault-plugin-secrets-ecr && \
vault write ecr/config/root access_key=<PLACEHOLDER> secret_key=<PLACEHOLDER> region=us-east-1 && \
vault write ecr/roles/test registry_permission=read && \
vault read ecr/creds/test ttl=1m
```
