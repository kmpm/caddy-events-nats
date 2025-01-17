# SPDX-FileCopyrightText: NONE
#
# SPDX-License-Identifier: CC0-1.0

FILES_CC0 = go.sum go.mod Caddyfile .gitignore .markdownlint.yaml contrib/*.*
FILES_APACHE = README.md Makefile *.go 

.PHONY: build tools reuse annotate audit tidy run validate adapt fmt module pre-commit no-dirty

build:
	xcaddy build --with github.com/kmpm/caddy-events-nats@latest

tools:
	@echo "installing tools"
	go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest
	-pipx install reuse

reuse:
	reuse lint

annotate:
	@echo "annotating code"
	reuse annotate --copyright "NONE" --year "" --license "CC0-1.0" --skip-unrecognised --skip-existing $(FILES_CC0)
	reuse annotate --copyright "Peter Magnusson"  --license "Apache-2.0" --skip-unrecognised --skip-existing $(FILES_APACHE)

audit:
	@echo "running audit checks"
	go mod verify
	go vet ./...
	go list -m all
	go run honnef.co/go/tools/cmd/staticcheck@latest -checks=all,-ST1000 ./...
	go run golang.org/x/vuln/cmd/govulncheck@latest ./...

tidy:
	@echo "formatting code"
	go fmt ./...
	@echo "tidying up go modules"
	go mod tidy -v
	

run:
	xcaddy run 

validate:
	xcaddy validate

adapt:
	xcaddy adapt  | jq > Caddyfile.json

fmt:
	caddy fmt --overwrite Caddyfile

module:
	xcaddy list-modules | grep 'events.handlers'

pre-commit: audit fmt tidy reuse 
	@echo "precommit checks passed"

no-dirty:
	git diff --exit-code