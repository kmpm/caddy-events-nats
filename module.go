// SPDX-FileCopyrightText: 2024 Peter Magnusson <me@kmpm.se>
//
// SPDX-License-Identifier: Apache-2.0

package caddynats

import (
	"context"
	"encoding/json"
	"fmt"
	"text/template"

	"bytes"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyevents"
	"github.com/nats-io/nats.go"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(NatsHandler{})
}

type NatsHandler struct {
	logger        *zap.Logger
	clientOptions []nats.Option
	nc            *nats.Conn
	t             *template.Template
	connected     bool
	ServerURL     string `json:"url,omitempty"`
	Subject       string `json:"subject,omitempty"`
	Username      string `json:"username,omitempty"`
	Password      string `json:"password,omitempty"`
	Token         string `json:"token,omitempty"`
	NKeyFile      string `json:"nkey_file,omitempty"`
}

func (NatsHandler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "events.handlers.nats",
		New: func() caddy.Module { return new(NatsHandler) },
	}
}

func (h *NatsHandler) Provision(ctx caddy.Context) error {
	h.logger = ctx.Logger(h)
	h.t = template.New(h.Subject)

	nc, err := nats.Connect(h.ServerURL, h.clientOptions...)
	if err != nil {
		return err
	}
	h.nc = nc
	//TODO: set client handlers
	nc.SetErrorHandler(func(conn *nats.Conn, sub *nats.Subscription, err error) {
		h.logger.Error("nats error", zap.Error(err))
	})
	nc.SetDisconnectHandler(func(conn *nats.Conn) {
		h.logger.Info("nats disconnected")
		h.connected = false
	})
	nc.SetReconnectHandler(func(conn *nats.Conn) {
		h.logger.Info("nats reconnected")
		h.connected = true
	})
	nc.SetClosedHandler(func(conn *nats.Conn) {
		h.logger.Info("nats closed")
		h.connected = false
	})
	nc.SetDisconnectErrHandler(func(conn *nats.Conn, err error) {
		h.logger.Error("nats disconnect error", zap.Error(err))
	})

	return nil
}

func (h *NatsHandler) Handle(ctx context.Context, event caddyevents.Event) error {
	if !h.connected {
		return fmt.Errorf("nats not connected")
	}
	ce := event.CloudEvent()
	h.logger.Debug("handling event", zap.String("event", ce.ID), zap.String("source", ce.Source))
	data, err := json.Marshal(ce)
	if err != nil {
		return fmt.Errorf("failed to marshal event: %w", err)
	}
	var result bytes.Buffer
	err = h.t.Execute(&result, ce)
	if err != nil {
		return fmt.Errorf("failed to execute template: %w", err)
	}
	m := &nats.Msg{
		Subject: result.String(),
		Data:    data,
	}
	header := make(nats.Header)
	header.Add("Content-Type", "application/json")
	// header.Add("X-CloudEvent-ID", event.ID)
	// header.Add("X-Timestamp", event.)
	m.Header = header

	err = h.nc.PublishMsg(m)
	if err != nil {
		return fmt.Errorf("failed to publish event: %w", err)
	}

	return nil
}

func (h *NatsHandler) Validate() error {
	if h.ServerURL == "" {
		return fmt.Errorf("server url is required")
	}
	if h.Subject == "" {
		return fmt.Errorf("subject is required")
	}
	//TODO: validate subject format

	if h.NKeyFile != "" {
		opt, err := nats.NkeyOptionFromSeed(h.NKeyFile)
		if err != nil {
			return err
		}
		if h.Username != "" {
			return fmt.Errorf("username and nkey_file are mutually exclusive")
		}
		h.clientOptions = append(h.clientOptions, opt)
	}
	if h.Username != "" {
		if h.Password == "" && h.Token == "" {
			return fmt.Errorf("password or token is required")
		}
		if h.Password != "" && h.Token != "" {
			return fmt.Errorf("password and token are mutually exclusive")
		}
		if h.Password != "" {
			h.clientOptions = append(h.clientOptions, nats.UserInfo(h.Username, h.Password))
		}
		if h.Token != "" {
			h.clientOptions = append(h.clientOptions, nats.Token(h.Token))
		}
	}
	return nil
}

func (h *NatsHandler) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	if !d.Next() {
		return d.Err("expected token")
	}
	for d.NextBlock(0) {
		switch d.Val() {
		case "server_url":
			if !d.Args(&h.ServerURL) {
				return d.ArgErr()
			}
		case "subject":
			if !d.Args(&h.Subject) {
				return d.ArgErr()
			}
		case "username":
			if !d.Args(&h.Username) {
				return d.ArgErr()
			}
		case "password":
			if !d.Args(&h.Password) {
				return d.ArgErr()
			}
		case "token":
			if !d.Args(&h.Token) {
				return d.ArgErr()
			}
		case "nkey_file":
			if !d.Args(&h.NKeyFile) {
				return d.ArgErr()
			}
		default:
			return d.Errf("unknown property '%s'", d.Val())
		}
	}
	return nil

}

var (
	_ caddyfile.Unmarshaler = (*NatsHandler)(nil)
	_ caddy.Provisioner     = (*NatsHandler)(nil)
	_ caddyevents.Handler   = (*NatsHandler)(nil)
	_ caddy.Validator       = (*NatsHandler)(nil)
)
