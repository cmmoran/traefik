package geoip

import (
	"context"
	"fmt"
	"github.com/rs/zerolog"
	"github.com/traefik/traefik/v3/pkg/config/dynamic"
	"github.com/traefik/traefik/v3/pkg/middlewares"
	"net"
	"net/http"
	"strings"
)

const (
	typeName = "GeoIP"
)

// TraefikGeoIP a traefik geoip plugin.
type TraefikGeoIP struct {
	next       http.Handler
	name       string
	excludeIPs []*net.IPNet
	lookup     LookupGeoIP
	debug      bool
	setRealIP  bool
	l          *zerolog.Logger
}

// New created a new TraefikGeoIP plugin.
func New(ctx context.Context, next http.Handler, cfg dynamic.GeoIP, name string) (http.Handler, error) {
	debug := cfg.Debug
	logger := middlewares.GetLogger(ctx, name, typeName)

	if debug {
		logger.Debug().Any("config", cfg).Msg("Creating middleware")
	}

	if len(cfg.DbPath) == 0 {
		logger.Error().Any("config", cfg).Msg("must define at least one db path")
		return nil, fmt.Errorf("must define at least one db path")
	}

	lookup, err := NewLookup(cfg.DbPath...)
	if err != nil {
		if debug {
			logger.Error().Err(err).Msg("error initializing lookup")
		}
		return nil, err
	}

	// Parse CIDRs and store them in a slice for exclusion.
	excludedIPs := make([]*net.IPNet, 0)
	for _, v := range cfg.ExcludeIPs {
		// Check if it is a single IP.
		if net.ParseIP(v) != nil {
			// Make the IP into a /32.
			v += "/32"
		}
		// Now parse the value as CIDR.
		_, excludedNet, err := net.ParseCIDR(v)
		if err != nil {
			// Ignore invalid CIDRs and continue.
			if debug {
				logger.Error().Err(err).Str("cidr", v).Str("name", name).Msgf("invalid CIDR")
			}
			continue
		}

		excludedIPs = append(excludedIPs, excludedNet)
	}

	return &TraefikGeoIP{
		next:       next,
		name:       name,
		excludeIPs: excludedIPs,
		lookup:     lookup,
		debug:      debug,
		setRealIP:  cfg.SetRealIP,
	}, nil
}

// isExcluded checks if the IP is in the exclude list.
func (mw *TraefikGeoIP) isExcluded(ip net.IP) bool {
	for _, exnet := range mw.excludeIPs {
		if exnet.Contains(ip) {
			return true
		}
	}

	return false
}

func (mw *TraefikGeoIP) getClientIP(req *http.Request) net.IP {
	logger := middlewares.GetLogger(req.Context(), mw.name, typeName)
	// Get first IP from X-Forwarded-For header if it exists.
	ipStr := ""
	if xff := req.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			ipStr = strings.TrimSpace(ips[0])
		}
	}

	// If X-Forwarded-For header is empty, get the remote IP.
	if ipStr == "" {
		ipStr = req.RemoteAddr
		host, _, err := net.SplitHostPort(ipStr)
		if err == nil {
			ipStr = host
		}
	}

	// Parse the IP.
	ip := net.ParseIP(ipStr)
	if ip == nil && mw.debug {
		logger.Warn().Str("ip", ipStr).Str("name", mw.name).Msg("unable to parse IP")
		return ip
	}

	// Only process IPs not in the exclude list.
	if mw.isExcluded(ip) {
		if mw.debug {
			logger.Debug().Str("ip", ipStr).Str("name", mw.name).Msg("IP excluded")
		}
		ip = nil
	}

	return ip
}

// processRequest processes the request and adds geo headers if the IP is in the database.
func (mw *TraefikGeoIP) processRequest(req *http.Request) *http.Request {
	logger := middlewares.GetLogger(req.Context(), mw.name, typeName)
	// Get the client IP.
	ip := mw.getClientIP(req)

	// If the IP is nil, return the request unchanged.
	if ip == nil {
		return req
	}

	// Set X-Real-Ip header because traefik sometimes messes with it.
	if mw.setRealIP {
		req.Header.Set("X-Real-Ip", ip.String())
	}

	// Lookup the IP.
	result, err := mw.lookup(ip)
	if err != nil {
		if mw.debug {
			logger.Error().Err(err).Any("ip", ip).Str("name", mw.name).Msg("error looking up IP")
		}
		return req
	}

	if mw.debug {
		logger.Debug().Any("ip", ip).Str("name", mw.name).Any("result", result).Msg("lookup result")
	}

	// Set the headers.
	setHeaders(req, result)

	return req
}

// ServeHTTP implements the middleware interface.
func (mw *TraefikGeoIP) ServeHTTP(reqWr http.ResponseWriter, req *http.Request) {
	req = mw.processRequest(req)

	mw.next.ServeHTTP(reqWr, req)
}

// SetHeaders Set geo headers.
func setHeaders(req *http.Request, result *Result) {
	if result.country != Unknown {
		req.Header.Set(CountryHeader, result.country)
	}
	if result.countryCode != Unknown {
		req.Header.Set(CountryCodeHeader, result.countryCode)
	}
	if result.region != Unknown {
		req.Header.Set(RegionHeader, result.region)
	}
	if result.city != Unknown {
		req.Header.Set(CityHeader, result.city)
	}
	if result.latitude != Unknown {
		req.Header.Set(LatitudeHeader, result.latitude)
	}
	if result.longitude != Unknown {
		req.Header.Set(LongitudeHeader, result.longitude)
	}
	if result.geohash != Unknown {
		req.Header.Set(GeohashHeader, result.geohash)
	}
	if result.systemNumber != Unknown {
		req.Header.Set(SystemNumber, result.systemNumber)
	}
	if result.systemOrganization != Unknown {
		req.Header.Set(SystemOrganization, result.systemOrganization)
	}
	if result.network != Unknown {
		req.Header.Set(Network, result.network)
	}
}
