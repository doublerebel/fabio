package config

import (
	"encoding/json"
	"fmt"
	"log"
	"path"
	"runtime"
	"strings"
	"time"

	"github.com/spf13/viper"
)

func Load(filename string) (*Config, error) {
	v    := viper.New()
	base := path.Base(filename)
	ext := path.Ext(filename)
	name := strings.TrimSuffix(base, ext)

	v.SetConfigName(name)
	v.AddConfigPath(path.Dir(filename))
	err := v.ReadInConfig()
	if err != nil {
		return nil, err
	}
	return FromViper(v)
}

func FromViper(v *viper.Viper) (cfg *Config, err error) {
	cfg = &Config{}

	deprecate := func(key, msg string) {
		exists := v.Get(key)
		if exists != nil {
			log.Print("[WARN] config: ", msg)
		}
	}

	defaultListen, err := parseListen(Default.Listen[0].Addr, Default.Proxy.ReadTimeout, Default.Proxy.WriteTimeout)
	if err != nil {
		return nil, err
	}

	v.SetDefault("", Default)
	v.SetDefault("Listen", defaultListen)

	v.SetEnvPrefix("FABIO")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	v.Unmarshal(cfg)

	if cfg.Metrics[0].Target == "graphite" {
		cfg.Metrics[0].Addr = v.GetString("metrics.graphite.addr")
	}

	cfg.Listen, err = parseListen(v.GetString("proxy.addr"), v.GetDuration("proxy.readtimeout"), v.GetDuration("proxy.writetimeout"))
	if err != nil {
		return nil, err
	}

	deprecate("consul.addr", "consul.addr has been replaced by registry.consul.addr")
	deprecate("consul.token", "consul.token has been replaced by registry.consul.token")
	deprecate("consul.kvpath", "consul.kvpath has been replaced by registry.consul.kvpath")
	deprecate("consul.tagprefix", "consul.tagprefix has been replaced by registry.consul.tagprefix")
	deprecate("consul.register.name", "consul.register.name has been replaced by registry.consul.register.name")
	deprecate("consul.register.checkInterval", "consul.register.checkInterval has been replaced by registry.consul.register.checkInterval")
	deprecate("consul.register.checkTimeout", "consul.register.checkTimeout has been replaced by registry.consul.register.checkTimeout")
	deprecate("consul.url", "consul.url is obsolete. Please remove it.")

	proxyRoutes := v.GetString("proxy.routes")
	if strings.HasPrefix(proxyRoutes, "@") {
		cfg.Registry.Backend = "file"
		cfg.Registry.File.Path = proxyRoutes[1:]
		deprecate("proxy.routes", "Please use registry.backend=file and registry.file.path=<path> instead of proxy.routes=@<path>")
	} else if proxyRoutes != "" {
		cfg.Registry.Backend = "static"
		cfg.Registry.Static.Routes = proxyRoutes
		deprecate("proxy.routes", "Please use registry.backend=static and registry.static.routes=<routes> instead of proxy.routes=<routes>")
	}

	if cfg.Runtime.GOMAXPROCS == -1 {
		cfg.Runtime.GOMAXPROCS = runtime.NumCPU()
	}

	dump(cfg)
	return cfg, nil
}

func dump(cfg *Config) {
	data, err := json.MarshalIndent(cfg, "", "    ")
	if err != nil {
		log.Fatal("[FATAL] Cannot dump runtime config. ", err)
	}
	log.Println("[INFO] Runtime config\n" + string(data))
}

func parseMetrics(target, prefix, graphiteAddr string, interval time.Duration) []Metrics {
	m := Metrics{Target: target, Prefix: prefix, Interval: interval}
	if target == "graphite" {
		m.Addr = graphiteAddr
	}
	return []Metrics{m}
}

func parseListen(addrs string, readTimeout, writeTimeout time.Duration) ([]Listen, error) {
	listen := []Listen{}
	for _, addr := range strings.Split(addrs, ",") {
		addr = strings.TrimSpace(addr)
		if addr == "" {
			continue
		}

		var l Listen
		p := strings.Split(addr, ";")
		switch len(p) {
		case 1:
			l.Addr = p[0]
		case 2:
			l.Addr, l.CertFile, l.KeyFile, l.TLS = p[0], p[1], p[1], true
		case 3:
			l.Addr, l.CertFile, l.KeyFile, l.TLS = p[0], p[1], p[2], true
		case 4:
			l.Addr, l.CertFile, l.KeyFile, l.ClientAuthFile, l.TLS = p[0], p[1], p[2], p[3], true
		default:
			return nil, fmt.Errorf("invalid address %s", addr)
		}
		l.ReadTimeout = readTimeout
		l.WriteTimeout = writeTimeout
		listen = append(listen, l)
	}
	return listen, nil
}
