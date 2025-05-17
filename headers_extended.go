// SPDX-FileCopyrightText: 2025 Peter Magnusson <me@kmpm.se>
//
// SPDX-License-Identifier: Apache-2.0
//go:build caddyevents_headers

package caddynats

import (
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/nats-io/nats.go"
)

func addHeaders(h *nats.Header, ce caddy.CloudEvent) {
	h.Add("X-CloudEvent-ID", ce.ID)
	h.Add("X-CloudEvent-Time", ce.Time.Format(time.RFC3339))
}
