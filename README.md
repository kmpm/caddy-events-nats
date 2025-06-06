# Publish Caddy Event over NATS

This is the `events.handlers.nats` Caddy module.
It publishes messages to a NATS server for Caddy events.


__It is EXPERIMENTAL and subject to change__.
This module might never stabilize.

> [!NOTE]
> This is not an official repository of the
> [Caddy Web Server](https://github.com/caddyserver) organization.

## CloudEvent

Each message payload is a json encoded CloudEvent stuct from
[caddyevents](https://github.com/caddyserver/caddy/blob/master/modules/caddyevents/app.go)

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

See [cloudevents.io](https://cloudevents.io) for general information about the format.

## Installation

Using [xcaddy](https://github.com/caddyserver/xcaddy) is the simplest method.

```shell
xcaddy build --with github.com/kmpm/caddy-events-nats
```

## Usage

Configure with Caddyfile or JSON.
Possible events to capture is...

| Source | Type                | Notes |
|--------|---------------------|-------------|
| tls    | tls_get_certificate | Whenever cert is used. |
| tls    | cached_managed_cert | A cert is cached in memory. For example after caddy starts or a cert was obtained |
| tls    | cert_obtaining      | A cert is being created    |
| tls    | cert_obtained       | A cert was created         |

_Note:_ On `caddy validate` the module gets provisioned fully. That has the
consequence that a connection to the NATS server is made and validation will fail
if connection cant be made.

### Arguments

| Argument      | Default  | Example |
|---------------|----------|-------------------------------------------------------|
| server_url    | ""       | "nats://cluster-host1:4222,nats://cluster-host2:4222" |
| nats_context  | ""       | "nats_development"									   |
| subject       | ""       | "events.{{.Type}}"                                    |
| must_publish  | ""       | "yes"                                                 |
| must_connect  | ""       | "yes"                                                 |
| auth_user     | ""       | myuser                                                |
| auth_password | ""       | "supersecret"                                         |
| auth_token    | ""       | "s3cr3t"                                              |
| auth_nkey     | ""       | "/etc/secrets/auth.nk"                                |
| auth_creds    | ""       | "./NGS-Default-CLI.creds"                             |

#### server_url

Is comma separated string with nats servers to connect to.
It is required unless nats_context is set and cannot be used
together with nats_context.

#### nats_context

This is the name of the nats context to use for connection.
Cannot be used together with server_url.
Please note that it must be a context that is available for the 
user that is executing caddy.

#### subject

Required [Go text template](https://pkg.go.dev/text/template) formated string
to use as message subject. Available attributes to use int the template are
the same as for [CloudEvent](#cloudevent).

#### must_publish

If set to `yes` then the module with throw and error if...

- an event is triggered but the NATS client connection is lost
- the event data in form of a [CloudEvent](#cloudevent) can't be
  converted to JSON.
- if the subject template throws an error on execution'
- an error is thrown when publishing the message on the NATS connection.

If set to `no` or blank it will just log a `WARN` on these events but not throw an error.

#### must_connect

If set to `no` then it will not require connection to the nats server on
startup. If `must_publish` is enabled then `must_connect` will be set to `yes`.


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
