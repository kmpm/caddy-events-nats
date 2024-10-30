# SPDX-FileCopyrightText: NONE
#
# SPDX-License-Identifier: CC0-1.0

export XCADDY_SETCAP=1
build:
	xcaddy build

tools:
	@echo "installing tools"
	go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest
	-pipx install reuse

reuse:
	reuse lint

annotate:
	@echo "annotating code"
	reuse annotate --copyright "NONE" --year "" --license "CC0-1.0" --skip-unrecognised --skip-existing go.sum Caddyfile .gitignore
	reuse annotate --copyright "Peter Magnusson"  --license "Apache-2.0" --skip-unrecognised --skip-existing README.md *.go Makefile

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

adapt:
	xcaddy adapt  | jq > Caddyfile.json

fmt:
	caddy fmt --overwrite Caddyfile

module:
	xcaddy list-modules | grep 'events.handlers'

precommit: audit tidy reuse
	@echo "precommit checks passed"