# Error Pages Documentation

## Overview

This document describes the error page system implemented in the auth0-cas-server-go service. The system provides user-friendly HTML error pages with embedded CSS styling, while maintaining fallback support for plain text errors. The system differentiates between user-facing routes and CAS protocol routes.

## Architecture

1. **HTML Template** (`templates/error.html`): Responsive error page template with embedded CSS styling and conditional "Go Back" button
2. **Error Wrapper Functions** (`responses.go`): Template rendering with different behaviors for user vs callback routes
3. **CAS Protocol Error Handler**: Uses existing `outputFailure` function for XML/JSON responses

## Route Classification

### User-Facing Routes (with "Go Back" button)
- `/cas/login` - CAS login page
- `/cas/logout` - CAS logout page

### User-Facing Callbacks (without "Go Back" button)
- `/cas/oidc_callback` - OAuth2 callback handler

### CAS Protocol Routes (use `outputFailure`)
- `/cas/serviceValidate` - CAS service validation
- `/cas/p3/serviceValidate` - CAS protocol 3 service validation
- `/cas/proxyValidate` - CAS proxy validation
- `/cas/p3/proxyValidate` - CAS protocol 3 proxy validation
- `/cas/proxy` - CAS proxy ticket granting

## Build Process

The error template uses embedded CSS and requires no build process. The template is self-contained with all styling included inline.

### Dependencies

- **Go html/template**: Standard library package for template rendering

## Usage

### Error Rendering Functions

Different functions are used based on route type:

```go
// User-facing routes (shows "Go Back" button)
renderUserErrorPage(r.Context(), w, http.StatusBadRequest, "Service parameter is required")

// Callback routes (no "Go Back" button)
renderCallbackErrorPage(r.Context(), w, http.StatusBadRequest, "Invalid request")

// CAS protocol routes (use existing outputFailure for XML/JSON)
outputFailure(r.Context(), w, err, "INVALID_REQUEST", "service parameter is required", useJSON)
```

### Template Data Structure

```go
type ErrorPageData struct {
    StatusCode     int    // HTTP status code (e.g., 400, 500)
    Message        string // User-friendly error message
    ShowBackButton bool   // Whether to show the "Go Back" button
}
```

### Conditional Back Button

The template includes conditional logic for the back button:

```html
{{if .ShowBackButton}}
<button onclick="history.back()" class="back-button">
    <svg class="back-icon" ...>...</svg>
    Go Back
</button>
{{end}}
```

### Fallback Behavior

1. **Template Available**: Renders HTML error page with embedded styling
2. **Template Missing**: Falls back to plain text error response
3. **Template Error**: Logs error and continues with partial content
4. **CAS Protocol Routes**: Always use XML/JSON responses via `outputFailure`

### Template Modifications

The error template supports standard Go template syntax with conditional logic:

```html
<h1 class="error-title">Error {{.StatusCode}}</h1>
<p class="error-message">{{.Message}}</p>
{{if .ShowBackButton}}
<button onclick="history.back()" class="back-button">
    <svg class="back-icon" ...>...</svg>
    Go Back
</button>
{{end}}
```

### Adding New Routes

When adding new routes:

1. Determine if it's user-facing, callback, or CAS protocol
2. Use the appropriate error function:
   - `renderUserErrorPage()` for user-facing with back button
   - `renderCallbackErrorPage()` for user-facing without back button
   - `outputFailure()` for CAS protocol routes
