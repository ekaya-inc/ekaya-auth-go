# ekaya-auth-go

Shared Go package for the MCP OAuth facade used by Ekaya services.

The module currently exposes the `mcpoauth` package, which provides:

- OAuth authorization server discovery
- OAuth protected resource metadata
- Authorization code token exchange
- Dynamic client registration for public/native clients

## Package

```go
import "github.com/ekaya-inc/ekaya-auth-go/mcpoauth"
```

## What It Registers

`(*mcpoauth.Handler).RegisterRoutes` adds these endpoints to an `http.ServeMux`:

- `GET /.well-known/oauth-authorization-server`
- `GET /.well-known/oauth-authorization-server/{path...}`
- `GET /.well-known/oauth-protected-resource`
- `GET /.well-known/oauth-protected-resource/{path...}`
- `POST /mcp/oauth/token`
- `POST /mcp/{pid}/oauth/token`
- `POST /mcp/oauth/register`

## Basic Usage

```go
package main

import (
	"context"
	"log"
	"net/http"

	"github.com/ekaya-inc/ekaya-auth-go/mcpoauth"
)

func main() {
	handler := mcpoauth.New(mcpoauth.Config{
		BaseURLResolver: mcpoauth.StaticBaseURLResolver("https://mcp.ekaya.ai"),
		AuthURLResolver: mcpoauth.LookupAuthURLResolver(
			"https://auth.ekaya.ai",
			map[string]struct{}{
				"https://auth.ekaya.ai":     {},
				"https://auth.dev.ekaya.ai": {},
			},
			func(ctx context.Context, projectID string) (string, error) {
				return "", nil
			},
		),
		SupportedScopes:     []string{"project:access"},
		ClientID:            "ekaya-mcp",
		StrictProjectID:     true,
		AllowProjectIDQuery: true,
		AllowAuthURLQuery:   true,
	})

	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	log.Fatal(http.ListenAndServe(":8080", mux))
}
```

## Configuration Notes

`mcpoauth.Config` lets callers control the package without baking project-specific behavior into the shared module.

- `BaseURLResolver` resolves the public base URL used in generated metadata and local token endpoints.
- `AuthURLResolver` resolves the upstream authorization server for discovery and token exchange.
- `HTTPClient` is used for upstream token exchange. If unset, `http.Client{}` is used.
- `SupportedScopes` defaults to `project:access`.
- `ClientID` defaults to `ekaya-mcp`.
- `StrictProjectID` enforces UUID validation for project IDs.
- `AllowProjectIDQuery` allows `project_id` on discovery requests.
- `AllowAuthURLQuery` allows `auth_url` on discovery and token requests.
- `ProxyTokenResponse` forwards the upstream token response as-is instead of normalizing success responses.
- `NormalizedTokenType` defaults to `Bearer`.
- `NormalizedExpiresIn` overrides the upstream `expires_in` when set.
- `EchoRequestedTokenEndpointAuthMethod` mirrors the requested DCR auth method instead of always returning `none`.

## Helper APIs

- `StaticBaseURLResolver` returns a fixed base URL resolver.
- `RequestBaseURLResolver` derives the base URL from the current request.
- `AllowlistAuthURLResolver` enforces a default auth URL plus an allowlist.
- `LookupAuthURLResolver` adds project-specific auth URL lookup with allowlist validation.
- `ValidateRedirectURI` validates redirect URIs for dynamic client registration.

## Behavior

- Project-scoped discovery can be driven by path segments such as `/.well-known/oauth-authorization-server/mcp/{projectID}`.
- When enabled, discovery can also accept `project_id` and `auth_url` query parameters.
- Token exchange supports the `authorization_code` grant only.
- Dynamic client registration validates redirect URIs and returns public-client metadata.
