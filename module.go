// SPDX-FileCopyrightText: 2024 Peter Magnusson <me@kmpm.se>
//
// SPDX-License-Identifier: Apache-2.0

package caddynats

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"text/template"

	"bytes"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyevents"
	"github.com/nats-io/nats.go"
	"go.uber.org/zap"
)

const (
	minCredsSize = 800
)

func init() {
	caddy.RegisterModule(NatsHandler{})
}

type NatsHandler struct {
	logger *zap.Logger

	nc            *nats.Conn
	t             *template.Template
	connected     bool
	firstConneted bool
	natsOptions   []nats.Option
	mustPublish   bool
	MustPublish   string `json:"must_publish,omitempty"`
	ServerURL     string `json:"server_url,omitempty"`
	Subject       string `json:"subject,omitempty"`
	AuthUser      string `json:"auth_user,omitempty"`
	AuthPassword  string `json:"auth_password,omitempty"`
	AuthToken     string `json:"auth_token,omitempty"`
	AuthNKey      string `json:"auth_nkey,omitempty"`
	AuthCreds     string `json:"auth_creds,omitempty"`
}

func (NatsHandler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "events.handlers.nats",
		New: func() caddy.Module { return new(NatsHandler) },
	}
}

func (h *NatsHandler) Provision(ctx caddy.Context) error {
	var err error
	h.logger = ctx.Logger(h)
	h.logger.Debug("provisioning nats handler")
	h.validate()

	opts := make([]nats.Option, 0)

	if h.AuthNKey != "" {
		opt, err := nats.NkeyOptionFromSeed(h.AuthNKey)
		if err != nil {
			return fmt.Errorf("failed to read nkey from file: %w", err)
		}
		opts = append(opts, opt)
	}
	if h.AuthPassword != "" {
		opts = append(opts, nats.UserInfo(h.AuthUser, h.AuthPassword))
	}
	if h.AuthToken != "" {
		opts = append(opts, nats.Token(h.AuthToken))
	}
	if h.AuthCreds != "" {
		opts = append(opts, nats.UserCredentials(h.AuthCreds))
	}
	h.natsOptions = opts

	if strings.Contains(h.Subject, "{{") {
		t := template.New("subject")
		h.t, err = t.Parse(h.Subject)
		if err != nil {
			return fmt.Errorf("failed to parse template: %w", err)
		}
	} else {
		h.t = nil
	}

	if h.MustPublish == "on" {
		h.mustPublish = true
	} else if h.MustPublish == "off" || h.MustPublish == "" {
		h.mustPublish = false
	}

	err = h.connect()
	if err != nil {
		return fmt.Errorf("failed to connect to nats: %w", err)
	}

	h.logger.Debug("nats handler provisioned")

	return nil
}

func (h *NatsHandler) connect() error {
	if h.firstConneted {
		return nil
	}

	nc, err := nats.Connect(h.ServerURL, h.natsOptions...)
	if err != nil {
		return err
	}
	h.logger.Info("nats client connected to server", zap.String("server", nc.ConnectedAddr()))
	h.firstConneted = true
	//TODO: set client handlers
	nc.SetErrorHandler(func(conn *nats.Conn, sub *nats.Subscription, err error) {
		h.logger.Error("nats error", zap.Error(err), zap.Bool("connected", h.connected))
	})
	nc.SetDisconnectHandler(func(conn *nats.Conn) {
		h.connected = false
		h.logger.Warn("nats disconnected", zap.Bool("connected", h.connected))

	})
	nc.SetReconnectHandler(func(conn *nats.Conn) {
		h.connected = true
		h.logger.Info("nats reconnected", zap.Bool("connected", h.connected), zap.String("server", conn.ConnectedAddr()))

	})
	nc.SetClosedHandler(func(conn *nats.Conn) {
		h.connected = false
		h.logger.Info("nats closed", zap.Bool("connected", h.connected))
	})
	nc.SetDisconnectErrHandler(func(conn *nats.Conn, err error) {
		h.connected = false
		h.logger.Error("nats disconnect error", zap.Error(err), zap.Bool("connected", h.connected))
	})
	h.nc = nc
	h.connected = true
	return nil
}

func (h *NatsHandler) Cleanup() error {
	h.logger.Debug("cleaning up nats handler")
	if h.nc != nil {
		h.nc.Close()
		h.connected = false
		h.nc = nil
	}
	return nil
}

func (h *NatsHandler) Handle(ctx context.Context, event caddyevents.Event) error {
	if !h.connected {
		if h.mustPublish {
			return fmt.Errorf("nats not connected")
		}
		h.logger.Warn("nats not connected")
		return nil
	}
	ce := event.CloudEvent()
	h.logger.Debug("handling event", zap.String("event", ce.ID), zap.String("source", ce.Source))
	data, err := json.Marshal(ce)
	if err != nil {
		if h.mustPublish {
			return fmt.Errorf("failed to marshal event: %w", err)
		} else {
			h.logger.Warn("failed to marshal event", zap.Error(err))
		}
	}
	subj := h.Subject
	if h.t != nil {
		var result bytes.Buffer
		err = h.t.Execute(&result, ce)
		if err != nil {
			if h.mustPublish {
				return fmt.Errorf("failed to execute template: %w", err)
			}
			h.logger.Warn("failed to execute template", zap.Error(err))
		}
		subj = result.String()
	}
	m := &nats.Msg{
		Subject: subj,
		Data:    data,
	}
	header := make(nats.Header)
	header.Add("Content-Type", "application/json")
	// header.Add("X-CloudEvent-ID", event.ID)
	// header.Add("X-Timestamp", event.)
	m.Header = header

	err = h.nc.PublishMsg(m)
	if err != nil {
		if h.mustPublish {
			return fmt.Errorf("failed to publish event: %w", err)
		} else {
			h.logger.Warn("failed to publish event", zap.Error(err))
		}
	}

	return nil
}

// Validate ensures the handler is properly configured.
func (h *NatsHandler) validate() error {
	h.logger.Debug("validating nats handler")

	if h.ServerURL == "" {
		return fmt.Errorf("server url is required")
	}
	if h.Subject == "" {
		return fmt.Errorf("subject is required")
	}
	t := template.New("subject")
	if _, err := t.Parse(h.Subject); err != nil {
		return fmt.Errorf("failed to parse subject template: %w", err)
	}

	if h.MustPublish != "" {
		//can only be 'on', 'off' or empty
		if h.MustPublish != "on" && h.MustPublish != "off" {
			return fmt.Errorf("must_publish must be 'on' or 'off'")
		}
	}
	if h.AuthNKey != "" {
		//check if file exists
		if _, err := nats.NkeyOptionFromSeed(h.AuthNKey); err != nil {
			return fmt.Errorf("failed to read nkey from file: %w", err)
		}
		//check exclusivity
		if h.AuthUser != "" || h.AuthPassword != "" || h.AuthToken != "" {
			return fmt.Errorf("auth_nkey must be used exclusively")
		}
	}
	if h.AuthToken != "" {
		//check exclusivity
		if h.AuthUser != "" || h.AuthPassword != "" || h.AuthNKey != "" {
			return fmt.Errorf("auth_token must be used exclusively")
		}
	}
	if h.AuthUser != "" || h.AuthPassword != "" {
		if h.AuthUser == "" {
			return fmt.Errorf("auth_user is required when using auth_password")
		}
		if h.AuthPassword == "" {
			return fmt.Errorf("auth_password is required when using auth_user")
		}
		//check exclusivity
		if h.AuthToken != "" || h.AuthNKey != "" {
			return fmt.Errorf("auth_user and auth_password cannot be used with any other auth_ argument")
		}
	}
	if h.AuthCreds != "" {
		//check if file exists using stat
		if f, err := os.Stat(h.AuthCreds); err != nil {
			return fmt.Errorf("failed to read creds from file: %w", err)
		} else if f.IsDir() {
			return fmt.Errorf("creds path is a directory")
		} else if f.Size() < minCredsSize {
			return fmt.Errorf("creds file is too small to be a valid creds file")
		}
		//check exclusivity
		if h.AuthUser != "" || h.AuthPassword != "" || h.AuthToken != "" || h.AuthNKey != "" {
			return fmt.Errorf("auth_creds must be used exclusively")
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
		case "auth_user":
			if !d.Args(&h.AuthUser) {
				return d.ArgErr()
			}
		case "auth_password":
			if !d.Args(&h.AuthPassword) {
				return d.ArgErr()
			}
		case "auth_token":
			if !d.Args(&h.AuthToken) {
				return d.ArgErr()
			}
		case "auth_nkey":
			if !d.Args(&h.AuthNKey) {
				return d.ArgErr()
			}
		case "auth_creds":
			if !d.Args(&h.AuthCreds) {
				return d.ArgErr()
			}
		case "must_publish":
			if !d.Args(&h.MustPublish) {
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
	_ caddy.CleanerUpper    = (*NatsHandler)(nil)
)
