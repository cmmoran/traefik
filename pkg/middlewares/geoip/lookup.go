package geoip //nolint:revive,stylecheck

import (
	"fmt"
	"net"
	"slices"
	"strconv"
	"strings"

	"github.com/IncSW/geoip2"
)

const (
	// Unknown constant for undefined data.
	Unknown = ""
	// CountryHeader country header name.
	CountryHeader = "Ip-Country"
	// CountryCodeHeader country code header name.
	CountryCodeHeader = "Ip-Country-Code"
	// RegionHeader region header name.
	RegionHeader = "Ip-Region"
	// CityHeader city header name.
	CityHeader = "Ip-City"
	// LatitudeHeader latitude header name.
	LatitudeHeader = "Ip-Latitude"
	// LongitudeHeader longitude header name.
	LongitudeHeader = "Ip-Longitude"
	// GeohashHeader geohash header name.
	GeohashHeader = "Ip-Geohash"
	// SystemNumber is the autonomous system number associated with the IP address.
	SystemNumber = "Asn-System-Number"
	// SystemOrganization is the organization associated with the registered autonomous system number for the IP address.
	SystemOrganization = "Asn-System-Org"
	// Network is the IPv4 or IPv6 network in CIDR format such as “2.21.92.0/29” or “2001:4b0::/80”. We offer a utility to convert this column to start/end IPs or start/end integers. See the conversion utility section for details.
	Network = "Asn-Network"
)

// Result in memory, this should have between 126 and 180 bytes. On average, consider 150 bytes.
type Result struct {
	country            string `mapstructure:"country,omitempty"`
	countryCode        string `mapstructure:"countryCode,omitempty"`
	region             string `mapstructure:"region,omitempty"`
	city               string `mapstructure:"city,omitempty"`
	latitude           string `mapstructure:"latitude,omitempty"`
	longitude          string `mapstructure:"longitude,omitempty"`
	geohash            string `mapstructure:"geohash,omitempty"`
	systemNumber       string `mapstructure:"systlscemNumber,omitempty"`
	systemOrganization string `mapstructure:"systemOrganization,omitempty"`
	network            string `mapstructure:"network,omitempty"`
}

// LookupGeoIP LookupGeoIP.
type LookupGeoIP func(ip net.IP) (*Result, error)

// newCityDBLookup Create a new CityDBLookup
func newCityDBLookup(rdr *geoip2.CityReader) LookupGeoIP {
	return func(ip net.IP) (*Result, error) {
		rec, err := rdr.Lookup(ip)
		if err != nil {
			return nil, fmt.Errorf("%w", err)
		}
		retval := Result{
			country:            Unknown,
			countryCode:        rec.Country.ISOCode,
			region:             Unknown,
			city:               Unknown,
			latitude:           strconv.FormatFloat(rec.Location.Latitude, 'f', -1, 64),
			longitude:          strconv.FormatFloat(rec.Location.Longitude, 'f', -1, 64),
			geohash:            EncodeGeoHash(rec.Location.Latitude, rec.Location.Longitude),
			systemNumber:       Unknown,
			systemOrganization: Unknown,
			network:            Unknown,
		}
		if country, ok := rec.Country.Names["en"]; ok {
			retval.country = country
		}
		if city, ok := rec.City.Names["en"]; ok {
			retval.city = city
		}
		if rec.Subdivisions != nil {
			retval.region = rec.Subdivisions[0].ISOCode
		}
		return &retval, nil
	}
}

// newCountryDBLookup Create a new CountryDBLookup.
func newCountryDBLookup(rdr *geoip2.CountryReader) LookupGeoIP {
	return func(ip net.IP) (*Result, error) {
		rec, err := rdr.Lookup(ip)
		if err != nil {
			return nil, fmt.Errorf("%w", err)
		}
		retval := Result{
			country:            Unknown,
			countryCode:        rec.Country.ISOCode,
			region:             Unknown,
			city:               Unknown,
			latitude:           Unknown,
			longitude:          Unknown,
			geohash:            Unknown,
			systemNumber:       Unknown,
			systemOrganization: Unknown,
			network:            Unknown,
		}
		if country, ok := rec.Country.Names["en"]; ok {
			retval.country = country
		}
		return &retval, nil
	}
}

// newAsnDBLookup create a new ASNDBLookup
func newAsnDBLookup(rdr *geoip2.ASNReader) LookupGeoIP {
	return func(ip net.IP) (*Result, error) {
		rec, err := rdr.Lookup(ip)
		if err != nil {
			return nil, fmt.Errorf("%w", err)
		}
		retval := Result{
			country:            Unknown,
			countryCode:        Unknown,
			region:             Unknown,
			city:               Unknown,
			latitude:           Unknown,
			longitude:          Unknown,
			geohash:            Unknown,
			systemNumber:       fmt.Sprintf("%d", rec.AutonomousSystemNumber),
			systemOrganization: rec.AutonomousSystemOrganization,
			network:            rec.Network,
		}
		return &retval, nil
	}
}

func newChainLookup(lookups ...LookupGeoIP) LookupGeoIP {
	if len(lookups) == 1 {
		return lookups[0]
	}
	return func(ip net.IP) (*Result, error) {
		var result = &Result{}
		for _, lookup := range lookups {
			lresult, err := lookup(ip)
			if err != nil {
				continue
			}
			simpleMerge(result, lresult)
		}
		return result, nil
	}
}

func simpleMerge(dst, src *Result) {
	if dst == nil || src == nil {
		return
	}
	if dst.country == "" {
		dst.country = src.country
	}
	if dst.countryCode == "" {
		dst.countryCode = src.countryCode
	}
	if dst.region == "" {
		dst.region = src.region
	}
	if dst.city == "" {
		dst.city = src.city
	}
	if dst.latitude == "" {
		dst.latitude = src.latitude
	}
	if dst.longitude == "" {
		dst.longitude = src.longitude
	}
	if dst.geohash == "" {
		dst.geohash = src.geohash
	}
	if dst.systemNumber == "" {
		dst.systemNumber = src.systemNumber
	}
	if dst.systemOrganization == "" {
		dst.systemOrganization = src.systemOrganization
	}
	if dst.network == "" {
		dst.network = src.network
	}
}

// NewLookup Create a new Lookup.
func NewLookup(dbPaths ...string) (LookupGeoIP, error) {
	var (
		lookups []LookupGeoIP
		err     error
	)

	slices.SortFunc(dbPaths, func(a, b string) int {
		priority := []string{"country", "city"}
		lowerA, lowerB := strings.ToLower(a), strings.ToLower(b)

		for _, p := range priority {
			if strings.Contains(lowerA, p) && !strings.Contains(lowerB, p) {
				return -1
			}
			if strings.Contains(lowerB, p) && !strings.Contains(lowerA, p) {
				return 1
			}
		}
		return 0
	})

	var dbPath string
	for _, dbPath = range dbPaths {
		switch {
		case strings.Contains(strings.ToLower(dbPath), "city"):
			var rdr *geoip2.CityReader
			rdr, err = geoip2.NewCityReaderFromFile(dbPath)
			if err != nil {
				break
			}
			lookups = append(lookups, newCityDBLookup(rdr))

		case strings.Contains(strings.ToLower(dbPath), "asn"):
			var rdr *geoip2.ASNReader
			rdr, err = geoip2.NewASNReaderFromFile(dbPath)
			if err != nil {
				break
			}
			lookups = append(lookups, newAsnDBLookup(rdr))

		case strings.Contains(strings.ToLower(dbPath), "country"):
			var rdr *geoip2.CountryReader
			rdr, err = geoip2.NewCountryReaderFromFile(dbPath)
			if err != nil {
				break
			}
			lookups = append(lookups, newCountryDBLookup(rdr))

		default:
			err = fmt.Errorf("unable to parse Geo DB type: db=%s", dbPath)
		}
	}
	if len(lookups) == 1 {
		return lookups[0], err
	}

	return newChainLookup(lookups...), err
}
