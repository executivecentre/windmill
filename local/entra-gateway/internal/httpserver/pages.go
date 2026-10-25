package httpserver

import (
	"html/template"
	"net/http"

	"entra-gateway/internal/sync"
)

type page struct {
	Title   string
	Message string
	Retry   bool
}

var (
	pageExpired     = page{"Sign-in expired", "This sign-in attempt expired or was started in another browser window.", true}
	pageInvalid     = page{"Sign-in failed", "Microsoft Entra ID's answer could not be verified.", true}
	pageEntraError  = page{"Sign-in refused", "Microsoft Entra ID did not complete the sign-in.", true}
	pageUnavailable = page{"Sign-in unavailable", "Sign-in is temporarily unavailable. Try again in a minute.", true}
	pageError       = page{"Sign-in failed", "Something went wrong while signing you in. Try again, or contact your administrator.", true}
	pageLoggedOut   = page{"Signed out", "You are signed out of Windmill.", true}
)

var deniedMessages = map[string]string{
	sync.ReasonUserNotFound:      "Your account was not found in the directory.",
	sync.ReasonAccountDisabled:   "Your directory account is disabled.",
	sync.ReasonDomainNotAllowed:  "Your e-mail domain is not allowed to use this Windmill instance.",
	sync.ReasonNoAccess:          "You are not in any group that grants access to Windmill. Ask your administrator.",
	sync.ReasonEmailConflict:     "Your e-mail address is already linked to a different directory account. Contact your administrator.",
	sync.ReasonExistingAccount:   "A Windmill account with your e-mail address already exists. Contact your administrator.",
	sync.ReasonPrivilegedAccount: "This account has instance-level privileges and cannot sign in with single sign-on.",
	sync.ReasonDisabledByAdmin:   "Your Windmill account has been disabled by an administrator.",
	sync.ReasonLoginTypeChanged:  "Your Windmill account is not set up for single sign-on. Contact your administrator.",
}

func deniedPage(reason string) page {
	msg, ok := deniedMessages[reason]
	if !ok {
		msg = "You do not have access to this Windmill instance."
	}
	return page{Title: "Access denied", Message: msg}
}

var pageTemplate = template.Must(template.New("page").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{.Title}} · Windmill</title>
<style>body{font-family:system-ui,sans-serif;max-width:32rem;margin:4rem auto;padding:0 1rem;color:#1f2937}
h1{font-size:1.25rem}a{color:#2563eb}</style></head>
<body><h1>{{.Title}}</h1><p>{{.Message}}</p>{{if .Retry}}<p><a href="/sso/login">Sign in</a></p>{{end}}</body></html>
`))

func renderPage(w http.ResponseWriter, status int, p page) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_ = pageTemplate.Execute(w, p)
}
