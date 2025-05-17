// SPDX-FileCopyrightText: 2025 Peter Magnusson <me@kmpm.se>
//
// SPDX-License-Identifier: Apache-2.0

package caddynats

import (
	"strings"
	"testing"
	"text/template"

	"github.com/nats-io/nats.go"
	"go.uber.org/zap"
)

func TestNatsHandler_validate(t *testing.T) {
	type fields struct {
		logger        *zap.Logger
		nc            *nats.Conn
		t             *template.Template
		connected     bool
		firstConneted bool
		natsOptions   []nats.Option
		MustPublish   string
		MustConnect   string
		ServerURL     string
		Subject       string
		AuthUser      string
		AuthPassword  string
		AuthToken     string
		AuthNKey      string
		AuthCreds     string
	}
	logger := zap.NewNop()

	tests := []struct {
		name            string
		fields          fields
		wantErr         bool
		wantErrContains string
	}{
		{"empty_no_server_url", fields{logger: logger},
			true, "server_url"},
		{"no_subject", fields{logger: logger, ServerURL: "nats://localhost:4222"},
			true, "subject"},
		{"bad_subject", fields{logger: logger, ServerURL: "nats://localhost:4222", Subject: "is{{.something}"},
			true, "failed to parse subject"},
		{"ok_subject", fields{logger: logger, ServerURL: "nats://localhost:4222", Subject: "is{{.something}}"},
			false, ""},
		{"bad_must_publish", fields{logger: logger, ServerURL: "nats://localhost:4222", Subject: "subject", MustPublish: "0"},
			true, "must_publish"},
		{"ok_must_publish", fields{logger: logger, ServerURL: "nats://localhost:4222", Subject: "subject", MustPublish: "yes"},
			false, ""},
		{"bad_must_connect", fields{logger: logger, ServerURL: "nats://localhost:4222", Subject: "subject", MustConnect: "0"},
			true, "must_connect"},
		{"ok_must_connect", fields{logger: logger, ServerURL: "nats://localhost:4222", Subject: "subject", MustConnect: "yes"},
			false, ""},
		{"bad_auth_password", fields{logger: logger, ServerURL: "nats://localhost:4222", Subject: "subject", AuthUser: "user", AuthPassword: ""},
			true, "auth_password is required"},
		{"bad_auth_user", fields{logger: logger, ServerURL: "nats://localhost:4222", Subject: "subject", AuthUser: "", AuthPassword: "something"},
			true, "auth_user is required"},
		{"ok_auth_user", fields{logger: logger, ServerURL: "nats://localhost:4222", Subject: "subject", AuthUser: "user", AuthPassword: "password"},
			false, ""},
		{"ok_auth_token", fields{logger: logger, ServerURL: "nats://localhost:4222", Subject: "subject", AuthToken: "token"},
			false, ""},
		{"ok_auth_nkey", fields{logger: logger, ServerURL: "nats://localhost:4222", Subject: "subject", AuthNKey: "./testdata/test-su.nk"},
			false, ""},
		{"ok_auth_creds", fields{logger: logger, ServerURL: "nats://localhost:4222", Subject: "subject", AuthCreds: "./testdata/some.creds"},
			false, ""},
		{"bad_auth_creds", fields{logger: logger, ServerURL: "nats://localhost:4222", Subject: "subject", AuthCreds: "no-such-file"},
			true, "failed to read creds"},
		{"bad_auth_nkey", fields{logger: logger, ServerURL: "nats://localhost:4222", Subject: "subject", AuthNKey: "no-such-file"},
			true, "failed to read nkey from file"},

		{"bad_user_combination", fields{logger: logger, ServerURL: "nats://localhost:4222", Subject: "subject", AuthUser: "user", AuthPassword: "password", AuthToken: "token"},
			true, "auth_token must be used exclusively"},
		// TODO: Add more test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := &NatsHandler{
				logger:        tt.fields.logger,
				nc:            tt.fields.nc,
				tmpl:          tt.fields.t,
				connected:     tt.fields.connected,
				firstConneted: tt.fields.firstConneted,
				natsOptions:   tt.fields.natsOptions,
				MustPublish:   tt.fields.MustPublish,
				MustConnect:   tt.fields.MustConnect,
				ServerURL:     tt.fields.ServerURL,
				Subject:       tt.fields.Subject,
				AuthUser:      tt.fields.AuthUser,
				AuthPassword:  tt.fields.AuthPassword,
				AuthToken:     tt.fields.AuthToken,
				AuthNKey:      tt.fields.AuthNKey,
				AuthCreds:     tt.fields.AuthCreds,
			}
			if err := h.validate(); (err != nil) != tt.wantErr {
				t.Errorf("NatsHandler.validate() error = %v, wantErr %v", err, tt.wantErr)
			} else if err != nil && !strings.Contains(err.Error(), tt.wantErrContains) {
				t.Errorf("NatsHandler.validate() error = %v, wantErrContains %v", err, tt.wantErrContains)
			}

			if h.mustPublish() && !h.mustConnect() {
				t.Errorf("NatsHandler.mustPublish implies mustConnect() want truthy, got %v", h.MustConnect)
			}
		})
	}
}

func TestNatsHandler_mustPublish(t *testing.T) {
	type fields struct {
		logger        *zap.Logger
		nc            *nats.Conn
		t             *template.Template
		connected     bool
		firstConneted bool
		natsOptions   []nats.Option
		MustPublish   string
		MustConnect   string
		ServerURL     string
		Subject       string
		AuthUser      string
		AuthPassword  string
		AuthToken     string
		AuthNKey      string
		AuthCreds     string
	}
	tests := []struct {
		name   string
		fields fields
		want   bool
	}{
		{"0", fields{logger: zap.NewNop(), MustPublish: "0"}, false},
		{"1", fields{logger: zap.NewNop(), MustPublish: "1"}, true},
		{"empty", fields{logger: zap.NewNop()}, false},
		{"false", fields{logger: zap.NewNop(), MustPublish: "false"}, false},
		{"jibberish", fields{logger: zap.NewNop(), MustPublish: "jibberish"}, false},
		{"no", fields{logger: zap.NewNop(), MustPublish: "no"}, false},
		{"off", fields{logger: zap.NewNop(), MustPublish: "off"}, false},
		{"on", fields{logger: zap.NewNop(), MustPublish: "on"}, true},
		{"true", fields{logger: zap.NewNop(), MustPublish: "true"}, true},
		{"yes", fields{logger: zap.NewNop(), MustPublish: "yes"}, true},
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := &NatsHandler{
				logger:        tt.fields.logger,
				nc:            tt.fields.nc,
				tmpl:          tt.fields.t,
				connected:     tt.fields.connected,
				firstConneted: tt.fields.firstConneted,
				natsOptions:   tt.fields.natsOptions,
				MustPublish:   tt.fields.MustPublish,
				MustConnect:   tt.fields.MustConnect,
				ServerURL:     tt.fields.ServerURL,
				Subject:       tt.fields.Subject,
				AuthUser:      tt.fields.AuthUser,
				AuthPassword:  tt.fields.AuthPassword,
				AuthToken:     tt.fields.AuthToken,
				AuthNKey:      tt.fields.AuthNKey,
				AuthCreds:     tt.fields.AuthCreds,
			}
			got := h.mustPublish()
			if got != tt.want {
				t.Errorf("NatsHandler.mustPublish() = %v, want %v", got, tt.want)
			}

		})
	}
}
