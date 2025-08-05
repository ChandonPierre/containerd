/*
   Copyright The containerd Authors.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

package docker

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"sigs.k8s.io/yaml"
)

// HostCapabilities represent the capabilities of the registry
// host. This also represents the set of operations for which
// the registry host may be trusted to perform.
//
// For example pushing is a capability which should only be
// performed on an upstream source, not a mirror.
// Resolving (the process of converting a name into a digest)
// must be considered a trusted operation and only done by
// a host which is trusted (or more preferably by secure process
// which can prove the provenance of the mapping). A public
// mirror should never be trusted to do a resolve action.
//
// | Registry Type    | Pull | Resolve | Push |
// |------------------|------|---------|------|
// | Public Registry  | yes  | yes     | yes  |
// | Private Registry | yes  | yes     | yes  |
// | Public Mirror    | yes  | no      | no   |
// | Private Mirror   | yes  | yes     | no   |
type HostCapabilities uint8

// KubeletConfiguration contains the configuration for the Kubelet
type KubeletConfiguration struct {
	// clusterDNS is a list of IP addresses for the cluster DNS server. If set,
	// kubelet will configure all containers to use this for DNS resolution
	// instead of the host's DNS servers.
	ClusterDNS []string `json:"clusterDNS,omitempty"`
}

const (
	// HostCapabilityPull represents the capability to fetch manifests
	// and blobs by digest
	HostCapabilityPull HostCapabilities = 1 << iota

	// HostCapabilityResolve represents the capability to fetch manifests
	// by name
	HostCapabilityResolve

	// HostCapabilityPush represents the capability to push blobs and
	// manifests
	HostCapabilityPush

	// KubeletRunDirectory specifies the directory where the kubelet runtime information is stored.
	KubeletRunDirectory = "/var/lib/kubelet"

	// KubeletConfigurationFileName specifies the file name on the node which stores initial remote configuration of kubelet
	// This file should exist under KubeletRunDirectory
	KubeletConfigurationFileName = "config.yaml"

	// KubeletConfigurationFilePath is the absolute path to the kubelet configuration file
	KubeletConfigurationFilePath = KubeletRunDirectory + "/" + KubeletConfigurationFileName

	// DNSServerPort is the default port for DNS servers
	DNSServerPort = "53"

	// resolvConfPath is the abs path of resolv.conf on host or container.
	resolvConfPath = "/etc/resolv.conf"

	// Reserved for future capabilities (i.e. search, catalog, remove)
)

// Has checks whether the capabilities list has the provide capability
func (c HostCapabilities) Has(t HostCapabilities) bool {
	return c&t == t
}

// RegistryHost represents a complete configuration for a registry
// host, representing the capabilities, authorizations, connection
// configuration, and location.
type RegistryHost struct {
	Client       *http.Client
	Authorizer   Authorizer
	Host         string
	Scheme       string
	Path         string
	Capabilities HostCapabilities
	Header       http.Header
}

func (h RegistryHost) isProxy(refhost string) bool {
	if refhost != h.Host {
		if refhost != "docker.io" || h.Host != "registry-1.docker.io" {
			return true
		}
	}
	return false
}

// RegistryHosts fetches the registry hosts for a given namespace,
// provided by the host component of an distribution image reference.
type RegistryHosts func(string) ([]RegistryHost, error)

// Registries joins multiple registry configuration functions, using the same
// order as provided within the arguments. When an empty registry configuration
// is returned with a nil error, the next function will be called.
// NOTE: This function will not join configurations, as soon as a non-empty
// configuration is returned from a configuration function, it will be returned
// to the caller.
func Registries(registries ...RegistryHosts) RegistryHosts {
	return func(host string) ([]RegistryHost, error) {
		for _, registry := range registries {
			config, err := registry(host)
			if err != nil {
				return config, err
			}
			if len(config) > 0 {
				return config, nil
			}
		}
		return nil, nil
	}
}

type registryOpts struct {
	authorizer Authorizer
	plainHTTP  func(string) (bool, error)
	host       func(string) (string, error)
	client     *http.Client
}

// RegistryOpt defines a registry default option
type RegistryOpt func(*registryOpts)

// WithPlainHTTP configures registries to use plaintext http scheme
// for the provided host match function.
func WithPlainHTTP(f func(string) (bool, error)) RegistryOpt {
	return func(opts *registryOpts) {
		opts.plainHTTP = f
	}
}

// WithAuthorizer configures the default authorizer for a registry
func WithAuthorizer(a Authorizer) RegistryOpt {
	return func(opts *registryOpts) {
		opts.authorizer = a
	}
}

// WithHostTranslator defines the default translator to use for registry hosts
func WithHostTranslator(h func(string) (string, error)) RegistryOpt {
	return func(opts *registryOpts) {
		opts.host = h
	}
}

// WithClient configures the default http client for a registry
func WithClient(c *http.Client) RegistryOpt {
	return func(opts *registryOpts) {
		opts.client = c
	}
}

// ConfigureDefaultRegistries is used to create a default configuration for
// registries. For more advanced configurations or per-domain setups,
// the RegistryHosts interface should be used directly.
// NOTE: This function will always return a non-empty value or error
func ConfigureDefaultRegistries(ropts ...RegistryOpt) RegistryHosts {
	var opts registryOpts
	for _, opt := range ropts {
		opt(&opts)
	}

	return func(host string) ([]RegistryHost, error) {
		config := RegistryHost{
			Client:       opts.client,
			Authorizer:   opts.authorizer,
			Host:         host,
			Scheme:       "https",
			Path:         "/v2",
			Capabilities: HostCapabilityPull | HostCapabilityResolve | HostCapabilityPush,
		}

		if config.Client == nil {
			config.Client = &http.Client{
				Transport: DefaultHTTPTransport(nil),
			}
		}

		if opts.plainHTTP != nil {
			match, err := opts.plainHTTP(host)
			if err != nil {
				return nil, err
			}
			if match {
				config.Scheme = "http"
			}
		}

		if opts.host != nil {
			var err error
			config.Host, err = opts.host(config.Host)
			if err != nil {
				return nil, err
			}
		} else if host == "docker.io" {
			config.Host = "registry-1.docker.io"
		}

		return []RegistryHost{config}, nil
	}
}

// MatchAllHosts is a host match function which is always true.
func MatchAllHosts(string) (bool, error) {
	return true, nil
}

// MatchLocalhost is a host match function which returns true for
// localhost.
//
// Note: this does not handle matching of ip addresses in octal,
// decimal or hex form.
func MatchLocalhost(host string) (bool, error) {
	switch host {
	case "::1":
		return true, nil
	case "[::1]":
		return true, nil
	}
	h, p, err := net.SplitHostPort(host)

	// addrError helps distinguish between errors of form
	// "no colon in address" and "too many colons in address".
	// The former is fine as the host string need not have a
	// port. Latter needs to be handled.
	addrError := &net.AddrError{
		Err:  "missing port in address",
		Addr: host,
	}
	if err != nil {
		if err.Error() != addrError.Error() {
			return false, err
		}
		// host string without any port specified
		h = host
	} else if len(p) == 0 {
		return false, errors.New("invalid host name format")
	}

	// use ipv4 dotted decimal for further checking
	if h == "localhost" {
		h = "127.0.0.1"
	}
	ip := net.ParseIP(h)

	return ip.IsLoopback(), nil
}

func getKubeletClusterDNS(kubeletConfigPath string) ([]string, error) {
	var config KubeletConfiguration
	data, err := os.ReadFile(kubeletConfigPath)
	if err != nil {
		return nil, err
	}
	unmarshalErr := yaml.Unmarshal(data, &config)
	if unmarshalErr != nil {
		return nil, unmarshalErr
	}
	return config.ClusterDNS, nil
}

func getSystemResolvers(resolvConfPath string) ([]string, error) {
	data, err := os.ReadFile(resolvConfPath)
	if err != nil {
		return nil, err
	}

	var resolvers []string
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "nameserver ") {
			fields := strings.Fields(line)
			if len(fields) == 2 {
				resolvers = append(resolvers, fields[1])
			}
		}
	}
	return resolvers, nil
}

func newDialResolver(servers []string) *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var lastErr error
			for _, ip := range servers {
				addr := net.JoinHostPort(ip, DNSServerPort)
				conn, err := (&net.Dialer{}).DialContext(ctx, network, addr)
				if err == nil {
					return conn, nil
				}
				lastErr = err
			}
			return nil, lastErr
		},
	}
}

func newDialContext() *net.Dialer {
	var resolvers []string
	kubeletResolvers, err := getKubeletClusterDNS(KubeletConfigurationFilePath)
	if err == nil {
		resolvers = append(resolvers, kubeletResolvers...)
	}
	systemResolvers, err := getSystemResolvers(resolvConfPath)
	if err == nil {
		resolvers = append(resolvers, systemResolvers...)
	}
	var r *net.Resolver
	if len(resolvers) != 0 {
		r = newDialResolver(resolvers)
	}

	d := &net.Dialer{
		Timeout:       30 * time.Second,
		KeepAlive:     30 * time.Second,
		FallbackDelay: 300 * time.Millisecond,
	}

	if r != nil {
		d.Resolver = r
	}

	return d
}
func DefaultHTTPTransport(defaultTLSConfig *tls.Config) *http.Transport {
	dialer := newDialContext()
	if dialer == nil {
		dialer = &net.Dialer{}
	}
	return &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           dialer.DialContext,
		MaxIdleConns:          10,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		TLSClientConfig:       defaultTLSConfig,
		ExpectContinueTimeout: 5 * time.Second,
	}
}
