package headers

import (
	"bytes"
	"fmt"
	"github.com/Masterminds/sprig/v3"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"text/template"

	"github.com/traefik/traefik/v3/pkg/config/dynamic"
	"github.com/traefik/traefik/v3/pkg/middlewares"
	"github.com/vulcand/oxy/v2/forward"
)

// Header is a middleware that helps setup a few basic security features.
// A single headerOptions struct can be provided to configure which features should be enabled,
// and the ability to override a few of the default values.
type Header struct {
	next               http.Handler
	hasCustomHeaders   bool
	hasCorsHeaders     bool
	headers            *dynamic.Headers
	allowOriginRegexes []*regexp.Regexp

	headerTemplates *template.Template
}

func safeFuncMap() template.FuncMap {
	funcMap := sprig.TxtFuncMap()

	// Remove dangerous functions
	delete(funcMap, "env")       // Prevents environment variable access
	delete(funcMap, "expandenv") // Prevents expanding environment variables
	delete(funcMap, "exec")      // Prevents shell execution
	delete(funcMap, "get")       // Blocks fetching URLs (potential SSRF)
	delete(funcMap, "htpasswd")  // Prevents generating bcrypt password hashes
	delete(funcMap, "toYaml")    // Avoid leaking structured data
	delete(funcMap, "toJson")    // Avoid leaking structured data

	funcMap["header"] = func(key string, req *http.Request) string {
		if req == nil {
			return ""
		}

		return req.Header.Get(key)
	}
	return funcMap
}

// NewHeader constructs a new header instance from supplied frontend header struct.
func NewHeader(next http.Handler, cfg dynamic.Headers) (*Header, error) {
	hasCustomHeaders := cfg.HasCustomHeadersDefined()
	hasCorsHeaders := cfg.HasCorsHeadersDefined()

	regexes := make([]*regexp.Regexp, len(cfg.AccessControlAllowOriginListRegex))
	for i, str := range cfg.AccessControlAllowOriginListRegex {
		reg, err := regexp.Compile(str)
		if err != nil {
			return nil, fmt.Errorf("error occurred during origin parsing: %w", err)
		}
		regexes[i] = reg
	}
	tpl := template.New("").Funcs(safeFuncMap())
	if hasCustomHeaders {
		delims := cfg.HeadersTemplateDelim
		if delims == nil || len(delims) == 0 {
			delims = []string{"{{", "}}"}
		}
		tpl = tpl.Delims(delims[0], delims[1])
		for header, value := range cfg.CustomRequestHeaders {
			if strings.Contains(value, delims[0]) && strings.Contains(value, delims[1]) {
				value = strings.Trim(value, " \t\n\r")
				if _, err := tpl.New(http.CanonicalHeaderKey(header)).Parse(value); err != nil {
					continue
				}
			}
		}
	}
	if tpl.DefinedTemplates() == "" {
		tpl = nil
	}

	return &Header{
		next:               next,
		headers:            &cfg,
		hasCustomHeaders:   hasCustomHeaders,
		hasCorsHeaders:     hasCorsHeaders,
		allowOriginRegexes: regexes,
		headerTemplates:    tpl,
	}, nil
}

func (s *Header) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	// Handle Cors headers and preflight if configured.
	if isPreflight := s.processCorsHeaders(rw, req); isPreflight {
		rw.WriteHeader(http.StatusOK)
		return
	}

	if s.hasCustomHeaders {
		s.modifyCustomRequestHeaders(req)
	}

	// If there is a next, call it.
	if s.next != nil {
		s.next.ServeHTTP(middlewares.NewResponseModifier(rw, req, s.PostRequestModifyResponseHeaders), req)
	}
}

// modifyCustomRequestHeaders sets or deletes custom request headers.
func (s *Header) modifyCustomRequestHeaders(req *http.Request) {
	// Loop through Custom request headers
	for header, value := range s.headers.CustomRequestHeaders {
		switch {
		// Handling https://github.com/golang/go/commit/ecdbffd4ec68b509998792f120868fec319de59b.
		case value == "" && header == forward.XForwardedFor:
			req.Header[header] = nil

		case value == "":
			req.Header.Del(header)

		case strings.EqualFold(header, "Host"):
			req.Host = value

		default:
			if s.headerTemplates != nil && s.headerTemplates.DefinedTemplates() != "" {
				buf := new(bytes.Buffer)
				if headerTemplate := s.headerTemplates.Lookup(http.CanonicalHeaderKey(header)); headerTemplate != nil {
					if err := headerTemplate.Execute(buf, req); err != nil {
						value = err.Error()
					} else {
						value = buf.String()
					}
				}

			}
			req.Header.Set(header, value)
		}
	}
}

// PostRequestModifyResponseHeaders set or delete response headers.
// This method is called AFTER the response is generated from the backend
// and can merge/override headers from the backend response.
func (s *Header) PostRequestModifyResponseHeaders(res *http.Response) error {
	if res == nil || res.Request == nil {
		return nil
	}

	// Loop through Custom response headers
	for header, value := range s.headers.CustomResponseHeaders {
		if value == "" {
			res.Header.Del(header)
		} else {
			res.Header.Set(header, value)
		}
	}

	if res.Request != nil {
		originHeader := res.Request.Header.Get("Origin")
		allowed, match := s.isOriginAllowed(originHeader)

		if allowed {
			res.Header.Set("Access-Control-Allow-Origin", match)
		}
	}

	if s.headers.AccessControlAllowCredentials {
		res.Header.Set("Access-Control-Allow-Credentials", "true")
	}

	if len(s.headers.AccessControlExposeHeaders) > 0 {
		exposeHeaders := strings.Join(s.headers.AccessControlExposeHeaders, ",")
		res.Header.Set("Access-Control-Expose-Headers", exposeHeaders)
	}

	if !s.headers.AddVaryHeader {
		return nil
	}

	varyHeader := res.Header.Get("Vary")
	if varyHeader == "Origin" {
		return nil
	}

	if varyHeader != "" {
		varyHeader += ","
	}
	varyHeader += "Origin"

	res.Header.Set("Vary", varyHeader)
	return nil
}

// processCorsHeaders processes the incoming request,
// and returns if it is a preflight request.
// If not a preflight, it handles the preRequestModifyCorsResponseHeaders.
func (s *Header) processCorsHeaders(rw http.ResponseWriter, req *http.Request) bool {
	if !s.hasCorsHeaders {
		return false
	}

	reqAcMethod := req.Header.Get("Access-Control-Request-Method")
	originHeader := req.Header.Get("Origin")

	if reqAcMethod != "" && originHeader != "" && req.Method == http.MethodOptions {
		// If the request is an OPTIONS request with an Access-Control-Request-Method header,
		// and Origin headers, then it is a CORS preflight request,
		// and we need to build a custom response: https://www.w3.org/TR/cors/#preflight-request
		if s.headers.AccessControlAllowCredentials {
			rw.Header().Set("Access-Control-Allow-Credentials", "true")
		}

		allowHeaders := strings.Join(s.headers.AccessControlAllowHeaders, ",")
		if allowHeaders != "" {
			rw.Header().Set("Access-Control-Allow-Headers", allowHeaders)
		}

		allowMethods := strings.Join(s.headers.AccessControlAllowMethods, ",")
		if allowMethods != "" {
			rw.Header().Set("Access-Control-Allow-Methods", allowMethods)
		}

		allowed, match := s.isOriginAllowed(originHeader)
		if allowed {
			rw.Header().Set("Access-Control-Allow-Origin", match)
		}

		rw.Header().Set("Access-Control-Max-Age", strconv.Itoa(int(s.headers.AccessControlMaxAge)))
		return true
	}

	return false
}

func (s *Header) isOriginAllowed(origin string) (bool, string) {
	for _, item := range s.headers.AccessControlAllowOriginList {
		if item == "*" || item == origin {
			return true, item
		}
	}

	for _, regex := range s.allowOriginRegexes {
		if regex.MatchString(origin) {
			return true, origin
		}
	}

	return false, ""
}
