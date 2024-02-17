package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"

	"golang.org/x/crypto/acme/autocert"
)

var enableTLS bool
var listenPort uint

var listenDomains = []string{
	"jsonip.io",
	"ipv4.jsonip.io",
	"ipv6.jsonip.io",
}

func init() {
	flag.BoolVar(&enableTLS, "tls", false, "whether to enable TLS")
	flag.UintVar(&listenPort, "port", 8080, "port on which to listen for HTTP traffic")
}

type Response struct {
	Address   string `json:"address"`
	Version   int    `json:"version"`
	Error     string `json:"error"`
	ErrorCode int    `json:"errorCode"`
	Usage     string `json:"usage"`
}

func main() {
	flag.Parse()

	// Attach handlers
	http.HandleFunc("/usage", Usage)
	http.HandleFunc("/", ReturnIP)

	if enableTLS {
		go func() {
			// Listen on HTTPS, with autocert
			log.Fatal("failed to start TLS server: ",http.Serve(autocert.NewListener(listenDomains...), nil))
		}()
	}

	// Listen on HTTP
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d",listenPort), nil))
}

func Usage(w http.ResponseWriter, r *http.Request) {
	if _, err := w.Write([]byte(`<html>
	<body>
	<h1>jsonip.io</h1>
	<p>Returns JSON indicating the IP address and version of the client</p>
	<p>If there is an error or the system is unable to determine the address, errorCode will be non-zero</p>
	<p> Options: </p>
	<ul>
		<li> http://ipv4.jsonip.io - force IPv4 address detection</li>
		<li> http://jsonip.io/ipv4 - redirects to ipv4.jsonip.io</li>
		<li> http://ipv6.jsonip.io - force IPv6 address detection</li>
		<li> http://jsonip.io/ipv6 - redirects to ipv6.jsonip.io</li>
	</ul>
	Example:<br/>
	<pre>
		{
			"address": "2001:db8:eadc::1",
			"version": 6,
			"errorCode": 0
		}
	</pre>
	<p>Service provided by <a href="http://cycoresys.com">CyCore Systems, Inc</a>.</p>
	</body>
	</html>
		`)); err != nil {
		log.Printf("error: failed to write help to requester: %s", err.Error())
	}
}

func ReturnIP(w http.ResponseWriter, r *http.Request) {
	var canceled bool

	resp := Response{
		Usage:  "http://jsonip.io/usage", 
	}

	defer func() {
		if canceled {
			// Response already handled
			return
		}

		w.Header().Set("Content-Type", "application/json")

		respBytes, err := json.Marshal(resp)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Write(respBytes) //nolint: errcheck

		log.Printf("{ \"Address\": \"%s\", \"Version\": %d }", resp.Address, resp.Version)
	}()

	// Get the IP address
	ip := GetIP(r)
	if ip == nil {
		w.WriteHeader(http.StatusInternalServerError)
		resp.ErrorCode = 1
		resp.Error = "Failed to determine IP address"
		return
	}

	resp.Address = ip.String()

	// Determine IP version
	resp.Version = GetVersion(ip)
	if resp.Version == 0 {
		w.WriteHeader(http.StatusInternalServerError)
		resp.ErrorCode = 2
		resp.Error = "Failed to determine IP version"
		return
	}

	// Handle version requests
	if isIPv6Request(r) && resp.Version != 6 {
		log.Println("Redirecting request to v6")
		http.Redirect(w, r, "http://ipv6.jsonip.io", 301)
		canceled = true
		return
	}
	if isIPv4Request(r) && resp.Version != 4 {
		log.Println("Redirecting request to v4")
		http.Redirect(w, r, "http://ipv4.jsonip.io", 301)
		canceled = true
		return
	}
}

// isIPv6Request returns true if the request was
// explicitly for IPv6
func isIPv6Request(r *http.Request) bool {
	if strings.HasPrefix(r.URL.Host, "ipv6") || strings.HasSuffix(r.URL.Path, "ipv6") {
		return true
	}
	return false
}

// isIPv4Request returns true if the request was
// explicitly for IPv4
func isIPv4Request(r *http.Request) bool {
	if strings.HasPrefix(r.URL.Host, "ipv4") || strings.HasSuffix(r.URL.Path, "ipv4") {
		return true
	}
	return false
}

// GetIP returns the IP address
func GetIP(r *http.Request) net.IP {
	ip := r.Header.Get("X-FORWARDED-FOR")
	if len(ip) < 1 {
		ip, _, _ = net.SplitHostPort(r.RemoteAddr)
	}
	return net.ParseIP(ip)
}

// Returns the IP address version number (4 or 6);
// Returns 0 on error
func GetVersion(ip net.IP) int {
	if ip.To4() != nil {
		return 4
	} else if ip.To16() != nil {
		return 6
	}
	return 0
}
