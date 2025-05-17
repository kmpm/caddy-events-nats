// SPDX-FileCopyrightText: 2024 Peter Magnusson <me@kmpm.se>
//
// SPDX-License-Identifier: Apache-2.0

package caddynats

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"text/template"

	"bytes"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyevents"
	"github.com/nats-io/nats.go"
	"github.com/synadia-io/orbit.go/natscontext"
	"go.uber.org/zap"
)

const (
	minCredsSize = 400
)

var verboseMode bool

func init() {
	caddy.RegisterModule(NatsHandler{})
}

type NatsHandler struct {
	logger *zap.Logger

	nc            *nats.Conn
	tmpl          *template.Template
	connected     bool
	firstConneted bool
	natsOptions   []nats.Option
	// mutex         sync.Mutex

	MustPublish  string `json:"must_publish,omitempty"`
	MustConnect  string `json:"must_connect,omitempty"`
	ServerURL    string `json:"server_url,omitempty"`
	NatsContext  string `json:"nats_context,omitempty"`
	Subject      string `json:"subject,omitempty"`
	AuthUser     string `json:"auth_user,omitempty"`
	AuthPassword string `json:"auth_password,omitempty"`
	AuthToken    string `json:"auth_token,omitempty"`
	AuthNKey     string `json:"auth_nkey,omitempty"`
	AuthCreds    string `json:"auth_creds,omitempty"`
}

func (h *NatsHandler) mustPublish() bool {
	return isTrue(h.MustPublish)
}

func (h *NatsHandler) mustConnect() bool {
	return isTrue(h.MustConnect)
}

func (NatsHandler) CaddyModule() caddy.ModuleInfo {
	fmt.Println("***** CaddyModule")
	return caddy.ModuleInfo{
		ID:  "events.handlers.nats",
		New: func() caddy.Module { return new(NatsHandler) },
	}
}

func (h *NatsHandler) Provision(ctx caddy.Context) error {
	var err error

	h.logger = ctx.Logger(h)
	if h.logger == nil {
		h.logger, err = zap.NewProduction()
		if err != nil {
			return fmt.Errorf("failed to create logger: %w", err)
		}
	}
	if verboseMode {
		h.logger.Debug("about to provision nats handler")
	}
	h.validate()

	opts := []nats.Option{
		nats.Name("caddy-nats"),
	}

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
		h.tmpl, err = t.Parse(h.Subject)
		if err != nil {
			return fmt.Errorf("failed to parse template: %w", err)
		}
	} else {
		h.tmpl = nil
	}

	err = h.connect()
	if err != nil {
		return fmt.Errorf("failed to connect to nats: %w", err)
	}
	if verboseMode {
		h.logger.Debug("nats handler provisioned")
	}
	return nil
}

func (h *NatsHandler) connect() error {
	if h.firstConneted {
		return nil
	}
	var nc *nats.Conn
	var err error
	if h.NatsContext != "" {
		nc, _, err = natscontext.Connect(h.NatsContext, h.natsOptions...)
	} else {
		nc, err = nats.Connect(h.ServerURL, h.natsOptions...)
	}
	if err != nil {
		if h.mustConnect() {
			return fmt.Errorf("failed to connect to nats: %w", err)
		}
		h.logger.Warn("failed to connect to nats", zap.Error(err))
		return nil
	}
	h.logger.Info("nats client connected to server", zap.String("server", nc.ConnectedAddr()))
	h.firstConneted = true
	//setup event handlers
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
	if verboseMode {
		h.logger.Debug("cleaning up nats handler")
	}
	if h.nc != nil {
		h.nc.Close()
		h.connected = false
		h.nc = nil
	}
	return nil
}

func (h *NatsHandler) Handle(ctx context.Context, event caddy.Event) error {

	h.logger.Debug("handling event",
		zap.String("event", event.Name()),
		zap.Bool("connected", h.connected),
		zap.Bool("has_nc", h.nc != nil),
		zap.Bool("has_origin", event.Origin() != nil),
	)

	if !h.connected {
		// if we are not connected and must_connect is not set
		// we can just log a warning and return
		h.logger.Warn("nats not connected")

		// try to reconnect
		// go func() {
		err := h.connect()
		if err != nil {
			h.logger.Error("failed to recconnect to nats", zap.Error(err))
		}
		// }()

		if h.mustPublish() {
			return fmt.Errorf("nats not connected")
		}
		h.logger.Warn("nats not connected")
		return nil
	}
	if h.nc == nil {
		if verboseMode {
			h.logger.Debug("nats client is nil")
		}
		if h.mustPublish() {
			return fmt.Errorf("nats client is nil")
		}
		return nil
	}

	if event.Origin() == nil {
		return errors.New("origin is nil, cannot create message for event")
	}
	ce := event.CloudEvent()
	if verboseMode {
		h.logger.Debug("cloudevent constructed", zap.Any("ce", ce))
	}

	data, err := json.Marshal(&ce)
	if err != nil {
		if h.mustPublish() {
			return fmt.Errorf("failed to marshal event: %w", err)
		} else {
			h.logger.Warn("failed to marshal event", zap.Error(err))
		}
	}
	subj := h.Subject
	preSubj := h.Subject
	if h.tmpl != nil {
		var result bytes.Buffer
		err = h.tmpl.Execute(&result, ce)
		if err != nil {
			if h.mustPublish() {
				return fmt.Errorf("failed to execute template: %w", err)
			}
			h.logger.Warn("failed to execute template", zap.Error(err))
		}
		subj = result.String()
	}
	if verboseMode && subj != preSubj {
		h.logger.Debug("subject changed", zap.String("old", preSubj), zap.String("new", subj))
	}
	m := &nats.Msg{
		Subject: subj,
		Data:    data,
	}
	header := make(nats.Header)
	header.Add("Content-Type", "application/json")
	addHeaders(&header, ce)

	m.Header = header

	err = h.nc.PublishMsg(m)
	if err != nil {
		if h.mustPublish() {
			return fmt.Errorf("failed to publish event: %w", err)
		} else {
			h.logger.Warn("failed to publish event", zap.Error(err))
		}
	}

	return nil
}

// Validate ensures the handler is properly configured.
func (h *NatsHandler) validate() error {
	if verboseMode {
		h.logger.Debug("validating nats handler")
	}
	if h.NatsContext != "" && h.ServerURL != "" {
		return fmt.Errorf("nats_context and server_url cannot be used together")
	}
	if h.ServerURL == "" && h.NatsContext == "" {
		return fmt.Errorf("server_url is required without nats_context")
	}
	if h.Subject == "" {
		return fmt.Errorf("subject is required")
	}
	t := template.New("subject")
	if _, err := t.Parse(h.Subject); err != nil {
		return fmt.Errorf("failed to parse subject as template: %w", err)
	}

	if h.MustPublish != "" {
		//can only be 'on', 'off' or empty
		if h.MustPublish != "yes" && h.MustPublish != "no" &&
			h.MustPublish != "on" && h.MustPublish != "off" {
			return fmt.Errorf("must_publish must be 'yes', 'no'")
		}
	}
	if h.MustConnect != "" {
		//can only be 'yes' or 'no' with the alternatives 'on', 'off' or empty
		if h.MustConnect != "yes" && h.MustConnect != "no" &&
			h.MustConnect != "on" && h.MustConnect != "off" {
			return fmt.Errorf("must_connect must be 'yes' 'no'")
		}
	}
	if isTrue(h.MustPublish) && !isTrue(h.MustConnect) {
		// if must_publish is true then must_connect implies
		// that the connection must be established
		h.MustConnect = "yes"
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
		case "nats_context":
			if !d.Args(&h.NatsContext) {
				return d.ArgErr()
			}
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
		case "must_connect":
			if !d.Args(&h.MustConnect) {
				return d.ArgErr()
			}

		default:
			return d.Errf("unknown property '%s'", d.Val())
		}
	}
	return nil

}

var (
	_ caddy.Module          = (*NatsHandler)(nil)
	_ caddy.Provisioner     = (*NatsHandler)(nil)
	_ caddy.CleanerUpper    = (*NatsHandler)(nil)
	_ caddyevents.Handler   = (*NatsHandler)(nil)
	_ caddyfile.Unmarshaler = (*NatsHandler)(nil)
)
