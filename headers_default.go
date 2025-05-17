// SPDX-FileCopyrightText: 2025 Peter Magnusson <me@kmpm.se>
//
// SPDX-License-Identifier: Apache-2.0
//go:build !caddyevents_headers

package caddynats

import (
	"github.com/caddyserver/caddy/v2"
	"github.com/nats-io/nats.go"
)

func addHeaders(h *nats.Header, ce caddy.CloudEvent) {
	// NOOP
}
