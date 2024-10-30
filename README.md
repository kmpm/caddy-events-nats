<!--
SPDX-FileCopyrightText: 2024 Peter Magnusson <me@kmpm.se>

SPDX-License-Identifier: Apache-2.0
-->

# Publish NATS messages on Caddy Events

This is the `events.handlers.nats` Caddy module.
It publishes messages to a NATS server for Caddy events.

__It is EXPERIMENTAL and subject to change__.
This module might never stabelize.

## CloudEvent

Each message payload is a json encoded CloudEvent stuct from [caddyevents](https://github.com/caddyserver/caddy/blob/master/modules/caddyevents/app.go)

```go
type CloudEvent struct {
	ID              string          `json:"id"`
	Source          string          `json:"source"`
	SpecVersion     string          `json:"specversion"`
	Type            string          `json:"type"`
	Time            time.Time       `json:"time"`
	DataContentType string          `json:"datacontenttype,omitempty"`
	Data            json.RawMessage `json:"data,omitempty"`
}
```

## Installation

Using [xcaddy](https://github.com/caddyserver/xcaddy) is the simplest method.

```shell
xcaddy build --with github.com/kmpm/caddy-events-nats
```

## Usage

Configure with Caddyfile or JSON.

_Note:_ On `caddy validate` the module gets provisioned fully. That has the
consequence that a connection to the NATS server is made and validation will fail
if connection cant be made.

### Arguments

| Argument      | Default  | Example |
|---------------|----------|-------------------------------------------------------|
| server_url    | ""       | "nats://cluster-host1:4222,nats://cluster-host2:4222" |
| subject       | ""       | "events.{{.Type}}"                                    |
| must_publish  | off      | on                                                    |
| auth_user     | ""       | myuser                                                |
| auth_password | ""       | "supersecret"                                         |
| auth_token    | ""       | "s3cr3t"                                              |
| auth_nkey     | ""       | "/etc/secrets/auth.nk"                                |
| auth_creds    | ""       | "./NGS-Default-CLI.creds"                             |

#### server_url

Required comma separated string with nats servers to connect to.

#### subject

Required [Go text template](https://pkg.go.dev/text/template) formated string
to use as message subject. Available attributes to use int the template are
the same as for [CloudEvent](#cloudevent).

#### must_publish

If set to `on` then the module with throw and error if...

- an event is triggered but the NATS client connection is lost
- the event data in form of a [CloudEvent](#cloudevent) can't be
  converted to JSON.
- if the subject template throws an error on execution'
- an error is thrown when publishing the message on the NATS connection.

If set to `off` it will just log a `WARN` on these events but not throw an error.

#### auth_user + auth_password

This is a strings for the username and passowrd to use when connecting to
the NATS server. Both must be provided to be used.

#### auth_token

This a string [authentication token](https://docs.nats.io/running-a-nats-service/configuration/securing_nats/auth_intro/tokens)
to use when connecting to the NATS Server.
Cannot be used with any other `auth_` parameter

#### auth_nkey

This is a string with the absolute path to a file containing a [NKey](https://docs.nats.io/running-a-nats-service/configuration/securing_nats/auth_intro/nkey_auth)
style token.
Cannot be used with any other `auth_` parameter.

#### auth_creds

A string containg the path to a [NATS Credentials](https://docs.nats.io/using-nats/developer/connecting/creds)
file. Cannot be used with any other `auth_` parameter.

### Caddyfile

```caddyfile
{
	events {
		on "*" nats {
			subject "caddy.events.{{.Source}}.{{.Type}}"
			server_url nats://localhost:4222
			
			# - tls server example -
			# server_url tls://connect.ngs.global

			# - user and password - 
			# auth_user local
			# auth_password "UVZ16q13zrQmsb7ef0k54x6RgXQvcSka"
			
			# - or token -
			# auth_token "s3cr3t"
			
			# - or nkey -
			# auth_nkey ./contrib/user.nk
			
			# - or creds file -
			# auth_creds ./NGS-Default-CLI.creds
		}
	}
}
```

### JSON

```json
{
  "apps": {
    "events": {
      "subscriptions": [
        {
          "events": [
            ""
          ],
          "handlers": [
            {
              "handler": "nats",
              "server_url": "nats://localhost:4222",
              "subject": "caddy.events.{{.Source}}.{{.Type}}"
            }
          ]
        }
      ]
    }
  }
}
```
