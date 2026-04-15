.PHONY: install deploy deploy-all destroy synth diff test sync-targets status dev

install:
	pnpm install

deploy:
	pnpm deploy

deploy-all:
	pnpm deploy:all
	$(MAKE) sync-targets

destroy:
	python3 bin/sync-mcp-targets.py delete github || true
	python3 bin/sync-mcp-targets.py delete notion || true
	pnpm destroy

synth:
	pnpm synth

diff:
	pnpm diff

test:
	pnpm test

sync-targets:
	pnpm sync-targets

status:
	pnpm status

dev:
	pnpm dev:frontend
