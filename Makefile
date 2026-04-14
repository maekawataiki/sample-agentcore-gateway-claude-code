.PHONY: deploy destroy synth test sync-targets sync-github sync-notion delete-targets

STACK := GatewayStack
REGION := us-east-1

# ── Full deploy: CDK + MCP targets ──

deploy: deploy-cdk sync-targets

deploy-cdk:
	cd cdk && pnpm exec cdk deploy --all --require-approval never

sync-targets: sync-github sync-notion

sync-github:
	@echo "==> Syncing GitHub MCP target..."
	python3 bin/sync-mcp-targets.py create github || true

sync-notion:
	@echo "==> Syncing Notion MCP target..."
	python3 bin/sync-mcp-targets.py create notion || true

# ── Status ──

status:
	python3 bin/sync-mcp-targets.py list

# ── Destroy: delete targets first, then CDK ──

destroy: delete-targets destroy-cdk

delete-targets:
	python3 bin/sync-mcp-targets.py delete github || true
	python3 bin/sync-mcp-targets.py delete notion || true

destroy-cdk:
	cd cdk && pnpm exec cdk destroy $(STACK) --force

# ── Dev shortcuts ──

synth:
	cd cdk && pnpm exec cdk synth $(STACK) --quiet

test:
	cd cdk && pnpm exec jest

build-frontend:
	cd frontend && pnpm run build
