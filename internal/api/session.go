package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/generated"
)

const maxSessionRequestBytes = 1024

func (app *Application) sessionCreate(writer http.ResponseWriter, request *http.Request, _ authorization.ReadScope, _ map[string]string) {
	if app.config.Sessions == nil {
		app.failure(writer, "api.v1.session.create", apiFailure(generated.ErrorCodePrerequisiteBlocked, "browser-session"))
		return
	}
	app.serveSessionOperation(writer, request, "api.v1.session.create", app.config.Sessions.Create)
}

func (app *Application) sessionRenew(writer http.ResponseWriter, request *http.Request, _ authorization.ReadScope, _ map[string]string) {
	if app.config.Sessions == nil {
		app.failure(writer, "api.v1.session.renew", apiFailure(generated.ErrorCodePrerequisiteBlocked, "browser-session"))
		return
	}
	app.serveSessionOperation(writer, request, "api.v1.session.renew", app.config.Sessions.Renew)
}

func (app *Application) sessionLogout(writer http.ResponseWriter, request *http.Request, _ authorization.ReadScope, _ map[string]string) {
	if app.config.Sessions == nil {
		app.failure(writer, "api.v1.session.logout", apiFailure(generated.ErrorCodePrerequisiteBlocked, "browser-session"))
		return
	}
	app.serveSessionOperation(writer, request, "api.v1.session.logout", app.config.Sessions.Logout)
}

func (app *Application) serveSessionOperation(writer http.ResponseWriter, request *http.Request, operation string, call func(context.Context) (BrowserSessionResult, error)) {
	if request.Header.Get("Content-Type") != "application/json" {
		app.failure(writer, operation, apiFailure(generated.ErrorCodeInputInvalid, "content-type"))
		return
	}
	raw, err := io.ReadAll(io.LimitReader(request.Body, maxSessionRequestBytes+1))
	if err != nil || len(raw) > maxSessionRequestBytes {
		app.failure(writer, operation, apiFailure(generated.ErrorCodeInputInvalid, "request-body"))
		return
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var input generated.ApiBrowserSessionRequest
	if err := decoder.Decode(&input); err != nil || input.RequestVersion != "1.0.0" {
		app.failure(writer, operation, apiFailure(generated.ErrorCodeInputInvalid, "request-body"))
		return
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		app.failure(writer, operation, apiFailure(generated.ErrorCodeInputInvalid, "request-body"))
		return
	}
	result, err := call(request.Context())
	if err != nil {
		app.failure(writer, operation, err)
		return
	}
	if result.Cookie == nil || strings.TrimSpace(result.Data.PrincipalID) == "" {
		app.failure(writer, operation, apiFailure(generated.ErrorCodeIntegrityFailure, "browser-session"))
		return
	}
	http.SetCookie(writer, result.Cookie)
	health, err := app.Health(request.Context())
	if err != nil {
		app.failure(writer, operation, err)
		return
	}
	app.success(writer, operation, health.StateRevision, health.RecoveryEpoch, result.Data)
}
