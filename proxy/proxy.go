package proxy

import (
	"net"
	"net/http"
	"time"

	"github.com/eBay/fabio/config"

	"github.com/doublerebel/publictransport"

	gometrics "github.com/rcrowley/go-metrics"
)

// Proxy is a dynamic reverse proxy.
type Proxy struct {
	tr       http.RoundTripper
	Cfg      config.Proxy
	requests gometrics.Timer
	Conns    map[net.Conn]*PersistConnHeaders
}

func New(tr http.RoundTripper, cfg config.Proxy) *Proxy {
	return &Proxy{
		tr:       tr,
		Cfg:      cfg,
		requests: gometrics.GetOrRegisterTimer("requests", gometrics.DefaultRegistry),
	}
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if ShuttingDown() {
		http.Error(w, "shutting down", http.StatusServiceUnavailable)
		return
	}

	t := target(r)
	if t == nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	if p.Cfg.CopyHeaders {
		p.CopyHeaders(w, r)
	}

	if err := addHeaders(r, p.Cfg); err != nil {
		http.Error(w, "cannot parse "+r.RemoteAddr, http.StatusInternalServerError)
		return
	}

	var h http.Handler
	switch {
	case r.Header.Get("Upgrade") == "websocket":
		h = newRawProxy(t.URL)

		// To use the filtered proxy use
		// h = newWSProxy(t.URL)
	default:
		h = newHTTPProxy(t.URL, p.tr)
	}

	start := time.Now()
	h.ServeHTTP(w, r)
	p.requests.UpdateSince(start)
	t.Timer.UpdateSince(start)
}

type HeaderMap map[string]string

type PersistConnHeaders struct {
		pastFirstRequest  bool
		hasExtraHeaders   bool
		HeaderMap         HeaderMap
}

func (p *Proxy) CopyHeaders(w http.ResponseWriter, r *http.Request) {
	if p.Conns == nil {
		p.Conns = make(map[net.Conn]*PersistConnHeaders)
	}

	res, ok := w.(*publictransport.Response)
	if !ok {
		return
	}

	conn := res.Conn.Rwc

	if p.Conns[conn] == nil {
		p.Conns[conn] = &PersistConnHeaders{
			HeaderMap: HeaderMap{
				"X-Forwarded-For":   "",
				"X-Forwarded-Proto": "",
				"Forwarded":         "",
			},
		}
	}

	pch := p.Conns[conn]

	if !pch.pastFirstRequest {
		pch.pastFirstRequest = true
		for name := range pch.HeaderMap {
			if header := r.Header.Get(name); header != "" {
				pch.HeaderMap[name] = header
				pch.hasExtraHeaders = true
			}
		}
	} else if pch.hasExtraHeaders {
		for name, header := range pch.HeaderMap {
			r.Header.Set(name, header)
		}
	}

}

