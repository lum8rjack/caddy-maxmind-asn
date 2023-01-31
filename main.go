package caddy_maxmind_asn

import (
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/oschwald/maxminddb-golang"
	"go.uber.org/zap"
)

// Interface guards
var (
	_ caddy.Module             = (*MaxmindASN)(nil)
	_ caddyhttp.RequestMatcher = (*MaxmindASN)(nil)
	_ caddy.Provisioner        = (*MaxmindASN)(nil)
	_ caddy.CleanerUpper       = (*MaxmindASN)(nil)
	_ caddyfile.Unmarshaler    = (*MaxmindASN)(nil)
)

type Record struct {
	ASN int    `maxminddb:"autonomous_system_number"`
	ASO string `maxminddb:"autonomous_system_organization"`
}

func init() {
	caddy.RegisterModule(MaxmindASN{})
}

// Allows to filter requests based on source IP ASO.
type MaxmindASN struct {
	// The path of the MaxMind GeoLite2-ASN.mmd file
	DbPath string `json:"db_path"`

	// A list of
	AllowASOs []string `json:"allow_asos"`
	DenyASOs  []string `json:"deny_asos"`

	// MaxMind database reader
	dbInst *maxminddb.Reader
	logger *zap.Logger
}

func (m *MaxmindASN) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	current := 0
	for d.Next() {
		for nesting := d.Nesting(); d.NextBlock(nesting); {
			switch d.Val() {
			case "db_path":
				current = 1
			case "allow_asos":
				current = 2
			case "deny_asos":
				current = 3
			default:
				switch current {
				case 1:
					m.DbPath = d.Val()
					current = 0
				case 2:
					m.AllowASOs = append(m.AllowASOs, strings.ToLower(d.Val()))
				case 3:
					m.DenyASOs = append(m.DenyASOs, strings.ToLower(d.Val()))
				default:
					return fmt.Errorf("unexpected config parameter %s", d.Val())
				}
			}
		}
	}
	return nil
}

func (MaxmindASN) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.matchers.maxmind_asn",
		New: func() caddy.Module { return new(MaxmindASN) },
	}
}

func (m *MaxmindASN) Provision(ctx caddy.Context) error {
	var err error
	m.logger = ctx.Logger(m)
	m.dbInst, err = maxminddb.Open(m.DbPath)
	if err != nil {
		return fmt.Errorf("cannot open database file %s: %v", m.DbPath, err)
	}

	m.logger.Debug("provisioned", zap.String("maxmind_db", m.DbPath), zap.Int("allowed_asos", len(m.AllowASOs)), zap.Int("denied_asos", len(m.DenyASOs)))
	return nil
}

func (m *MaxmindASN) Cleanup() error {
	if m.dbInst != nil {
		return m.dbInst.Close()
	}
	return nil
}

func (m *MaxmindASN) checkAllowed(asoresult string) bool {
	if asoresult == "" {
		return true
	}
	if len(m.DenyASOs) > 0 {
		for _, i := range m.DenyASOs {
			if strings.Contains(asoresult, i) {
				return false
			}
		}
		return true
	}
	if len(m.AllowASOs) > 0 {
		for _, i := range m.AllowASOs {
			if strings.Contains(asoresult, i) {
				return true
			}
		}
		return false
	}
	return true
}

func (m *MaxmindASN) Match(r *http.Request) bool {
	// If both the allow and deny fields are empty, let the request pass
	if len(m.AllowASOs) < 1 && len(m.DenyASOs) < 1 {
		return false
	}

	// Get the remote address from the web request
	remoteIp, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		m.logger.Warn("cannot split IP address", zap.String("address", r.RemoteAddr), zap.Error(err))
	}

	// Convert the IP string to net.IP
	addr := net.ParseIP(remoteIp)
	if addr == nil {
		m.logger.Warn("cannot parse IP address", zap.String("address", r.RemoteAddr))
		return false
	}

	// Get the record from the database
	var record Record
	err = m.dbInst.Lookup(addr, &record)
	if err != nil {
		m.logger.Warn("cannot lookup IP address", zap.String("address", r.RemoteAddr), zap.Error(err))
		return false
	}

	m.logger.Debug(
		"detected MaxMind data",
		zap.String("ip", r.RemoteAddr),
		zap.Int("autonomous_system_number", record.ASN),
		zap.String("autonomous_system_organization", record.ASO),
	)

	// Check if the IP against the allowed/denied ASOs
	if !m.checkAllowed(strings.ToLower(record.ASO)) {
		m.logger.Debug("aso not allowed", zap.String("autonomous_system_organization", record.ASO))
		return false
	}

	return true
}
