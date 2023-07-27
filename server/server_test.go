// Copyright 2012-2020 The NATS Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
)

func checkForErr(totalWait, sleepDur time.Duration, f func() error) error {
	timeout := time.Now().Add(totalWait)
	var err error
	for time.Now().Before(timeout) {
		err = f()
		if err == nil {
			return nil
		}
		time.Sleep(sleepDur)
	}
	return err
}

func checkFor(t testing.TB, totalWait, sleepDur time.Duration, f func() error) {
	t.Helper()
	err := checkForErr(totalWait, sleepDur, f)
	if err != nil {
		t.Fatal(err.Error())
	}
}

func DefaultOptions() *Options {
	return &Options{
		Host:     "127.0.0.1",
		Port:     -1,
		HTTPPort: -1,
		NoLog:    true,
		NoSigs:   true,
		Debug:    true,
		Trace:    true,
	}
}

// New Go Routine based server
func RunServer(opts *Options) *Server {
	if opts == nil {
		opts = DefaultOptions()
	}
	s, err := NewServer(opts)
	if err != nil || s == nil {
		panic(fmt.Sprintf("No NATS Server object returned: %v", err))
	}

	if !opts.NoLog {
		s.ConfigureLogger()
	}

	// Run server in Go routine.
	s.Start()

	// Wait for accept loop(s) to be started
	if err := s.readyForConnections(10 * time.Second); err != nil {
		panic(err)
	}
	return s
}

// LoadConfig loads a configuration from a filename
func LoadConfig(configFile string) (opts *Options) {
	opts, err := ProcessConfigFile(configFile)
	if err != nil {
		panic(fmt.Sprintf("Error processing configuration file: %v", err))
	}
	opts.NoSigs, opts.NoLog = true, opts.LogFile == _EMPTY_
	return
}

// RunServerWithConfig starts a new Go routine based server with a configuration file.
func RunServerWithConfig(configFile string) (srv *Server, opts *Options) {
	opts = LoadConfig(configFile)
	srv = RunServer(opts)
	return
}

func TestVersionMatchesTag(t *testing.T) {
	tag := os.Getenv("TRAVIS_TAG")
	// Travis started to return '' when no tag is set. Support both now.
	if tag == "" || tag == "''" {
		t.SkipNow()
	}
	// We expect a tag of the form vX.Y.Z. If that's not the case,
	// we need someone to have a look. So fail if first letter is not
	// a `v`
	if tag[0] != 'v' {
		t.Fatalf("Expect tag to start with `v`, tag is: %s", tag)
	}
	// Strip the `v` from the tag for the version comparison.
	if VERSION != tag[1:] {
		t.Fatalf("Version (%s) does not match tag (%s)", VERSION, tag[1:])
	}
}

func TestStartProfiler(t *testing.T) {
	s := New(DefaultOptions())
	s.StartProfiler()
	s.mu.Lock()
	s.profiler.Close()
	s.mu.Unlock()
}

func TestStartupAndShutdown(t *testing.T) {
	opts := DefaultOptions()
	opts.NoSystemAccount = true

	s := RunServer(opts)
	defer s.Shutdown()

	if !s.isRunning() {
		t.Fatal("Could not run server")
	}

	// Debug stuff.
	numRoutes := s.NumRoutes()
	if numRoutes != 0 {
		t.Fatalf("Expected numRoutes to be 0 vs %d\n", numRoutes)
	}

	numClients := s.NumClients()
	if numClients != 0 && numClients != 1 {
		t.Fatalf("Expected numClients to be 1 or 0 vs %d\n", numClients)
	}

	numSubscriptions := s.NumSubscriptions()
	if numSubscriptions != 0 {
		t.Fatalf("Expected numSubscriptions to be 0 vs %d\n", numSubscriptions)
	}
}

func TestTLSVersions(t *testing.T) {
	for _, test := range []struct {
		name     string
		value    uint16
		expected string
	}{
		{"1.0", tls.VersionTLS10, "1.0"},
		{"1.1", tls.VersionTLS11, "1.1"},
		{"1.2", tls.VersionTLS12, "1.2"},
		{"1.3", tls.VersionTLS13, "1.3"},
		{"unknown", 0x999, "Unknown [0x999]"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if v := tlsVersion(test.value); v != test.expected {
				t.Fatalf("Expected value 0x%x to be %q, got %q", test.value, test.expected, v)
			}
		})
	}
}

func TestTlsCipher(t *testing.T) {
	if strings.Compare(tlsCipher(0x0005), "TLS_RSA_WITH_RC4_128_SHA") != 0 {
		t.Fatalf("Invalid tls cipher")
	}
	if strings.Compare(tlsCipher(0x000a), "TLS_RSA_WITH_3DES_EDE_CBC_SHA") != 0 {
		t.Fatalf("Invalid tls cipher")
	}
	if strings.Compare(tlsCipher(0x002f), "TLS_RSA_WITH_AES_128_CBC_SHA") != 0 {
		t.Fatalf("Invalid tls cipher")
	}
	if strings.Compare(tlsCipher(0x0035), "TLS_RSA_WITH_AES_256_CBC_SHA") != 0 {
		t.Fatalf("Invalid tls cipher")
	}
	if strings.Compare(tlsCipher(0xc007), "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA") != 0 {
		t.Fatalf("Invalid tls cipher")
	}
	if strings.Compare(tlsCipher(0xc009), "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA") != 0 {
		t.Fatalf("Invalid tls cipher")
	}
	if strings.Compare(tlsCipher(0xc00a), "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA") != 0 {
		t.Fatalf("Invalid tls cipher")
	}
	if strings.Compare(tlsCipher(0xc011), "TLS_ECDHE_RSA_WITH_RC4_128_SHA") != 0 {
		t.Fatalf("Invalid tls cipher")
	}
	if strings.Compare(tlsCipher(0xc012), "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA") != 0 {
		t.Fatalf("Invalid tls cipher")
	}
	if strings.Compare(tlsCipher(0xc013), "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA") != 0 {
		t.Fatalf("Invalid tls cipher")
	}
	if strings.Compare(tlsCipher(0xc014), "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA") != 0 {
		t.Fatalf("IUnknownnvalid tls cipher")
	}
	if strings.Compare(tlsCipher(0xc02f), "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256") != 0 {
		t.Fatalf("Invalid tls cipher")
	}
	if strings.Compare(tlsCipher(0xc02b), "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256") != 0 {
		t.Fatalf("Invalid tls cipher")
	}
	if strings.Compare(tlsCipher(0xc030), "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384") != 0 {
		t.Fatalf("Invalid tls cipher")
	}
	if strings.Compare(tlsCipher(0xc02c), "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384") != 0 {
		t.Fatalf("Invalid tls cipher")
	}
	if strings.Compare(tlsCipher(0x1301), "TLS_AES_128_GCM_SHA256") != 0 {
		t.Fatalf("Invalid tls cipher")
	}
	if strings.Compare(tlsCipher(0x1302), "TLS_AES_256_GCM_SHA384") != 0 {
		t.Fatalf("Invalid tls cipher")
	}
	if strings.Compare(tlsCipher(0x1303), "TLS_CHACHA20_POLY1305_SHA256") != 0 {
		t.Fatalf("Invalid tls cipher")
	}
	if strings.Compare(tlsCipher(0x9999), "Unknown [0x9999]") != 0 {
		t.Fatalf("Expected an unknown cipher")
	}
}

func TestGetConnectURLs(t *testing.T) {
	opts := DefaultOptions()
	opts.Port = 4222

	var globalIP net.IP

	checkGlobalConnectURLs := func() {
		s := New(opts)
		defer s.Shutdown()

		s.mu.Lock()
		urls := s.getClientConnectURLs()
		s.mu.Unlock()
		if len(urls) == 0 {
			t.Fatalf("Expected to get a list of urls, got none for listen addr: %v", opts.Host)
		}
		for _, u := range urls {
			tcpaddr, err := net.ResolveTCPAddr("tcp", u)
			if err != nil {
				t.Fatalf("Error resolving: %v", err)
			}
			ip := tcpaddr.IP
			if !ip.IsGlobalUnicast() {
				t.Fatalf("IP %v is not global", ip.String())
			}
			if ip.IsUnspecified() {
				t.Fatalf("IP %v is unspecified", ip.String())
			}
			addr := strings.TrimSuffix(u, ":4222")
			if addr == opts.Host {
				t.Fatalf("Returned url is not right: %v", u)
			}
			if globalIP == nil {
				globalIP = ip
			}
		}
	}

	listenAddrs := []string{"0.0.0.0", "::"}
	for _, listenAddr := range listenAddrs {
		opts.Host = listenAddr
		checkGlobalConnectURLs()
	}

	checkConnectURLsHasOnlyOne := func() {
		s := New(opts)
		defer s.Shutdown()

		s.mu.Lock()
		urls := s.getClientConnectURLs()
		s.mu.Unlock()
		if len(urls) != 1 {
			t.Fatalf("Expected one URL, got %v", urls)
		}
		tcpaddr, err := net.ResolveTCPAddr("tcp", urls[0])
		if err != nil {
			t.Fatalf("Error resolving: %v", err)
		}
		ip := tcpaddr.IP
		if ip.String() != opts.Host {
			t.Fatalf("Expected connect URL to be %v, got %v", opts.Host, ip.String())
		}
	}

	singleConnectReturned := []string{"127.0.0.1", "::1"}
	if globalIP != nil {
		singleConnectReturned = append(singleConnectReturned, globalIP.String())
	}
	for _, listenAddr := range singleConnectReturned {
		opts.Host = listenAddr
		checkConnectURLsHasOnlyOne()
	}
}

func TestInfoServerNameDefaultsToPK(t *testing.T) {
	opts := DefaultOptions()
	opts.Port = 4222
	opts.ClientAdvertise = "nats.example.com"
	s := New(opts)
	defer s.Shutdown()

	if s.info.Name != s.info.ID {
		t.Fatalf("server info hostname is incorrect, got: '%v' expected: '%v'", s.info.Name, s.info.ID)
	}
}

func TestInfoServerNameIsSettable(t *testing.T) {
	opts := DefaultOptions()
	opts.Port = 4222
	opts.ClientAdvertise = "nats.example.com"
	opts.ServerName = "test_server_name"
	s := New(opts)
	defer s.Shutdown()

	if s.info.Name != "test_server_name" {
		t.Fatalf("server info hostname is incorrect, got: '%v' expected: 'test_server_name'", s.info.Name)
	}
}

func TestClientAdvertiseConnectURL(t *testing.T) {
	opts := DefaultOptions()
	opts.Port = 4222
	opts.ClientAdvertise = "nats.example.com"
	s := New(opts)
	defer s.Shutdown()

	s.mu.Lock()
	urls := s.getClientConnectURLs()
	s.mu.Unlock()
	if len(urls) != 1 {
		t.Fatalf("Expected to get one url, got none: %v with ClientAdvertise %v",
			opts.Host, opts.ClientAdvertise)
	}
	if urls[0] != "nats.example.com:4222" {
		t.Fatalf("Expected to get '%s', got: '%v'", "nats.example.com:4222", urls[0])
	}
	s.Shutdown()

	opts.ClientAdvertise = "nats.example.com:7777"
	s = New(opts)
	s.mu.Lock()
	urls = s.getClientConnectURLs()
	s.mu.Unlock()
	if len(urls) != 1 {
		t.Fatalf("Expected to get one url, got none: %v with ClientAdvertise %v",
			opts.Host, opts.ClientAdvertise)
	}
	if urls[0] != "nats.example.com:7777" {
		t.Fatalf("Expected 'nats.example.com:7777', got: '%v'", urls[0])
	}
	if s.info.Host != "nats.example.com" {
		t.Fatalf("Expected host to be set to nats.example.com")
	}
	if s.info.Port != 7777 {
		t.Fatalf("Expected port to be set to 7777")
	}
	s.Shutdown()

	opts = DefaultOptions()
	opts.Port = 0
	opts.ClientAdvertise = "nats.example.com:7777"
	s = New(opts)
	if s.info.Host != "nats.example.com" && s.info.Port != 7777 {
		t.Fatalf("Expected Client Advertise Host:Port to be nats.example.com:7777, got: %s:%d",
			s.info.Host, s.info.Port)
	}
	s.Shutdown()
}

func TestClientAdvertiseErrorOnStartup(t *testing.T) {
	opts := DefaultOptions()
	// Set invalid address
	opts.ClientAdvertise = "addr:::123"
	testFatalErrorOnStart(t, opts, "ClientAdvertise")
}

type captureFatalLogger struct {
	DummyLogger
	fatalCh chan string
}

func (l *captureFatalLogger) Fatalf(format string, v ...interface{}) {
	select {
	case l.fatalCh <- fmt.Sprintf(format, v...):
	default:
	}
}

func testFatalErrorOnStart(t *testing.T, o *Options, errTxt string) {
	t.Helper()
	s := New(o)
	defer s.Shutdown()
	l := &captureFatalLogger{fatalCh: make(chan string, 1)}
	s.SetLogger(l, false, false)
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		s.Start()
		wg.Done()
	}()
	select {
	case e := <-l.fatalCh:
		if !strings.Contains(e, errTxt) {
			t.Fatalf("Error should contain %q, got %s", errTxt, e)
		}
	case <-time.After(time.Second):
		t.Fatal("Should have got a fatal error")
	}
	s.Shutdown()
	wg.Wait()
}

func TestNoDeadlockOnStartFailure(t *testing.T) {
	opts := DefaultOptions()
	opts.Host = "x.x.x.x" // bad host
	opts.Port = 4222
	opts.HTTPHost = opts.Host
	opts.ProfPort = -1
	s := New(opts)

	// This should return since it should fail to start a listener
	// on x.x.x.x:4222
	ch := make(chan struct{})
	go func() {
		s.Start()
		close(ch)
	}()
	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Fatalf("Start() should have returned due to failure to start listener")
	}

	// We should be able to shutdown
	s.Shutdown()
}

func TestMaxConnections(t *testing.T) {
	opts := DefaultOptions()
	opts.MaxConn = 1
	s := RunServer(opts)
	defer s.Shutdown()

	addr := fmt.Sprintf("nats://%s:%d", opts.Host, opts.Port)
	nc, err := nats.Connect(addr)
	if err != nil {
		t.Fatalf("Error creating client: %v\n", err)
	}
	defer nc.Close()

	nc2, err := nats.Connect(addr)
	if err == nil {
		nc2.Close()
		t.Fatal("Expected connection to fail")
	}
}

func TestMaxSubscriptions(t *testing.T) {
	opts := DefaultOptions()
	opts.MaxSubs = 10
	s := RunServer(opts)
	defer s.Shutdown()

	addr := fmt.Sprintf("nats://%s:%d", opts.Host, opts.Port)
	nc, err := nats.Connect(addr)
	if err != nil {
		t.Fatalf("Error creating client: %v\n", err)
	}
	defer nc.Close()

	for i := 0; i < 10; i++ {
		_, err := nc.Subscribe(fmt.Sprintf("foo.%d", i), func(*nats.Msg) {})
		if err != nil {
			t.Fatalf("Error subscribing: %v\n", err)
		}
	}
	// This should cause the error.
	nc.Subscribe("foo.22", func(*nats.Msg) {})
	nc.Flush()
	if err := nc.LastError(); err == nil {
		t.Fatal("Expected an error but got none\n")
	}
}

func TestProcessCommandLineArgs(t *testing.T) {
	var host string
	var port int
	cmd := flag.NewFlagSet("nats-server", flag.ExitOnError)
	cmd.StringVar(&host, "a", "0.0.0.0", "Host.")
	cmd.IntVar(&port, "p", 4222, "Port.")

	cmd.Parse([]string{"-a", "127.0.0.1", "-p", "9090"})
	showVersion, showHelp, err := ProcessCommandLineArgs(cmd)
	if err != nil {
		t.Errorf("Expected no errors, got: %s", err)
	}
	if showVersion || showHelp {
		t.Errorf("Expected not having to handle subcommands")
	}

	cmd.Parse([]string{"version"})
	showVersion, showHelp, err = ProcessCommandLineArgs(cmd)
	if err != nil {
		t.Errorf("Expected no errors, got: %s", err)
	}
	if !showVersion {
		t.Errorf("Expected having to handle version command")
	}
	if showHelp {
		t.Errorf("Expected not having to handle help command")
	}

	cmd.Parse([]string{"help"})
	showVersion, showHelp, err = ProcessCommandLineArgs(cmd)
	if err != nil {
		t.Errorf("Expected no errors, got: %s", err)
	}
	if showVersion {
		t.Errorf("Expected not having to handle version command")
	}
	if !showHelp {
		t.Errorf("Expected having to handle help command")
	}

	cmd.Parse([]string{"foo", "-p", "9090"})
	_, _, err = ProcessCommandLineArgs(cmd)
	if err == nil {
		t.Errorf("Expected an error handling the command arguments")
	}
}

func TestRandomPorts(t *testing.T) {
	opts := DefaultOptions()
	opts.HTTPPort = -1
	opts.Port = -1
	s := RunServer(opts)

	defer s.Shutdown()

	if s.Addr() == nil || s.Addr().(*net.TCPAddr).Port <= 0 {
		t.Fatal("Should have dynamically assigned server port.")
	}

	if s.Addr() == nil || s.Addr().(*net.TCPAddr).Port == 4222 {
		t.Fatal("Should not have dynamically assigned default port: 4222.")
	}

	if s.MonitorAddr() == nil || s.MonitorAddr().Port <= 0 {
		t.Fatal("Should have dynamically assigned monitoring port.")
	}

}

func TestNilMonitoringPort(t *testing.T) {
	opts := DefaultOptions()
	opts.HTTPPort = 0
	opts.HTTPSPort = 0
	s := RunServer(opts)

	defer s.Shutdown()

	if s.MonitorAddr() != nil {
		t.Fatal("HttpAddr should be nil.")
	}
}

type DummyAuth struct {
	t         *testing.T
	needNonce bool
}

func (d *DummyAuth) Check(c ClientAuthentication) bool {
	if d.needNonce && len(c.GetNonce()) == 0 {
		d.t.Fatalf("Expected a nonce but received none")
	} else if !d.needNonce && len(c.GetNonce()) > 0 {
		d.t.Fatalf("Received a nonce when none was expected")
	}

	return c.GetOpts().Username == "valid"
}

func TestCustomClientAuthentication(t *testing.T) {
	testAuth := func(t *testing.T, nonce bool) {
		clientAuth := &DummyAuth{t, nonce}

		opts := DefaultOptions()
		opts.CustomClientAuthentication = clientAuth
		opts.AlwaysEnableNonce = nonce

		s := RunServer(opts)
		defer s.Shutdown()

		addr := fmt.Sprintf("nats://%s:%d", opts.Host, opts.Port)

		nc, err := nats.Connect(addr, nats.UserInfo("valid", ""))
		if err != nil {
			t.Fatalf("Expected client to connect, got: %s", err)
		}
		nc.Close()
		if _, err := nats.Connect(addr, nats.UserInfo("invalid", "")); err == nil {
			t.Fatal("Expected client to fail to connect")
		}
	}

	t.Run("with nonce", func(t *testing.T) { testAuth(t, true) })
	t.Run("without nonce", func(t *testing.T) { testAuth(t, false) })
}

func TestMonitoringNoTimeout(t *testing.T) {
	s := runMonitorServer()
	defer s.Shutdown()

	s.mu.Lock()
	srv := s.monitoringServer
	s.mu.Unlock()

	if srv == nil {
		t.Fatalf("Monitoring server not set")
	}
	if srv.ReadTimeout != 0 {
		t.Fatalf("ReadTimeout should not be set, was set to %v", srv.ReadTimeout)
	}
	if srv.WriteTimeout != 0 {
		t.Fatalf("WriteTimeout should not be set, was set to %v", srv.WriteTimeout)
	}
}

func TestProfilingNoTimeout(t *testing.T) {
	opts := DefaultOptions()
	opts.ProfPort = -1
	s := RunServer(opts)
	defer s.Shutdown()

	paddr := s.ProfilerAddr()
	if paddr == nil {
		t.Fatalf("Profiler not started")
	}
	pport := paddr.Port
	if pport <= 0 {
		t.Fatalf("Expected profiler port to be set, got %v", pport)
	}
	s.mu.Lock()
	srv := s.profilingServer
	s.mu.Unlock()

	if srv == nil {
		t.Fatalf("Profiling server not set")
	}
	if srv.ReadTimeout != 0 {
		t.Fatalf("ReadTimeout should not be set, was set to %v", srv.ReadTimeout)
	}
	if srv.WriteTimeout != 0 {
		t.Fatalf("WriteTimeout should not be set, was set to %v", srv.WriteTimeout)
	}
}

func TestLameDuckOptionsValidation(t *testing.T) {
	o := DefaultOptions()
	o.LameDuckDuration = 5 * time.Second
	o.LameDuckGracePeriod = 10 * time.Second
	s, err := NewServer(o)
	if s != nil {
		s.Shutdown()
	}
	if err == nil || !strings.Contains(err.Error(), "should be strictly lower") {
		t.Fatalf("Expected error saying that ldm grace period should be lower than ldm duration, got %v", err)
	}
}

func testSetLDMGracePeriod(o *Options, val time.Duration) {
	// For tests, we set the grace period as a negative value
	// so we can have a grace period bigger than the total duration.
	// When validating options, we would not be able to run the
	// server without this trick.
	o.LameDuckGracePeriod = val * -1
}

func TestAcceptError(t *testing.T) {
	o := DefaultOptions()
	s := New(o)
	s.mu.Lock()
	s.running = true
	s.mu.Unlock()
	defer s.Shutdown()
	orgDelay := time.Hour
	delay := s.acceptError("Test", fmt.Errorf("any error"), orgDelay)
	if delay != orgDelay {
		t.Fatalf("With this type of error, delay should have stayed same, got %v", delay)
	}

	// Create any net.Error and make it a temporary
	ne := &net.DNSError{IsTemporary: true}
	orgDelay = 10 * time.Millisecond
	delay = s.acceptError("Test", ne, orgDelay)
	if delay != 2*orgDelay {
		t.Fatalf("Expected delay to double, got %v", delay)
	}
	// Now check the max
	orgDelay = 60 * ACCEPT_MAX_SLEEP / 100
	delay = s.acceptError("Test", ne, orgDelay)
	if delay != ACCEPT_MAX_SLEEP {
		t.Fatalf("Expected delay to double, got %v", delay)
	}
	wg := sync.WaitGroup{}
	wg.Add(1)
	start := time.Now()
	go func() {
		s.acceptError("Test", ne, orgDelay)
		wg.Done()
	}()
	time.Sleep(100 * time.Millisecond)
	// This should kick out the sleep in acceptError
	s.Shutdown()
	if dur := time.Since(start); dur >= ACCEPT_MAX_SLEEP {
		t.Fatalf("Shutdown took too long: %v", dur)
	}
	wg.Wait()
	if d := s.acceptError("Test", ne, orgDelay); d >= 0 {
		t.Fatalf("Expected delay to be negative, got %v", d)
	}
}

func TestServerShutdownDuringStart(t *testing.T) {
	o := DefaultOptions()
	o.ServerName = "server"
	o.DisableShortFirstPing = true
	o.Accounts = []*Account{NewAccount("$SYS")}
	o.SystemAccount = "$SYS"

	// We are going to test that if the server is shutdown
	// while Start() runs (in this case, before), we don't
	// start the listeners and therefore leave accept loops
	// hanging.
	s, err := NewServer(o)
	if err != nil {
		t.Fatalf("Error creating server: %v", err)
	}
	s.Shutdown()

	// Start() should not block, but just in case, start in
	// different go routine.
	ch := make(chan struct{}, 1)
	go func() {
		s.Start()
		close(ch)
	}()
	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Fatal("Start appear to have blocked after server was shutdown")
	}
	// Now make sure that none of the listeners have been created
	listeners := []string{}
	s.mu.Lock()
	if s.listener != nil {
		listeners = append(listeners, "client")
	}

	s.mu.Unlock()
	if len(listeners) > 0 {
		lst := ""
		for i, l := range listeners {
			if i > 0 {
				lst += ", "
			}
			lst += l
		}
		t.Fatalf("Following listeners have been created: %s", lst)
	}
}

type myDummyDNSResolver struct {
	ips []string
	err error
}

func (r *myDummyDNSResolver) LookupHost(ctx context.Context, host string) ([]string, error) {
	if r.err != nil {
		return nil, r.err
	}
	return r.ips, nil
}

func TestGetRandomIP(t *testing.T) {
	s := &Server{}
	resolver := &myDummyDNSResolver{}
	// no port...
	if _, err := s.getRandomIP(resolver, "noport", nil); err == nil || !strings.Contains(err.Error(), "port") {
		t.Fatalf("Expected error about port missing, got %v", err)
	}
	resolver.err = fmt.Errorf("on purpose")
	if _, err := s.getRandomIP(resolver, "localhost:4222", nil); err == nil || !strings.Contains(err.Error(), "on purpose") {
		t.Fatalf("Expected error about no port, got %v", err)
	}
	resolver.err = nil
	a, err := s.getRandomIP(resolver, "localhost:4222", nil)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if a != "localhost:4222" {
		t.Fatalf("Expected address to be %q, got %q", "localhost:4222", a)
	}
	resolver.ips = []string{"1.2.3.4"}
	a, err = s.getRandomIP(resolver, "localhost:4222", nil)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if a != "1.2.3.4:4222" {
		t.Fatalf("Expected address to be %q, got %q", "1.2.3.4:4222", a)
	}
	// Check for randomness
	resolver.ips = []string{"1.2.3.4", "2.2.3.4", "3.2.3.4"}
	dist := [3]int{}
	for i := 0; i < 100; i++ {
		ip, err := s.getRandomIP(resolver, "localhost:4222", nil)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		v := int(ip[0]-'0') - 1
		dist[v]++
	}
	low := 20
	high := 47
	for i, d := range dist {
		if d == 0 || d == 100 {
			t.Fatalf("Unexpected distribution for ip %v, got %v", i, d)
		} else if d < low || d > high {
			t.Logf("Warning: out of expected range [%v,%v] for ip %v, got %v", low, high, i, d)
		}
	}

	// Check IP exclusions
	excludedIPs := map[string]struct{}{"1.2.3.4:4222": {}}
	for i := 0; i < 100; i++ {
		ip, err := s.getRandomIP(resolver, "localhost:4222", excludedIPs)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if ip[0] == '1' {
			t.Fatalf("Should not have returned this ip: %q", ip)
		}
	}
	excludedIPs["2.2.3.4:4222"] = struct{}{}
	for i := 0; i < 100; i++ {
		ip, err := s.getRandomIP(resolver, "localhost:4222", excludedIPs)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if ip[0] != '3' {
			t.Fatalf("Should only have returned '3.2.3.4', got returned %q", ip)
		}
	}
	excludedIPs["3.2.3.4:4222"] = struct{}{}
	for i := 0; i < 100; i++ {
		if _, err := s.getRandomIP(resolver, "localhost:4222", excludedIPs); err != errNoIPAvail {
			t.Fatalf("Unexpected error: %v", err)
		}
	}

	// Now check that exclusion takes into account the port number.
	resolver.ips = []string{"127.0.0.1"}
	excludedIPs = map[string]struct{}{"127.0.0.1:4222": {}}
	for i := 0; i < 100; i++ {
		if _, err := s.getRandomIP(resolver, "localhost:4223", excludedIPs); err == errNoIPAvail {
			t.Fatal("Should not have failed")
		}
	}
}

type shortWriteConn struct {
	net.Conn
}

func (swc *shortWriteConn) Write(b []byte) (int, error) {
	// Limit the write to 10 bytes at a time.
	short := false
	max := len(b)
	if max > 10 {
		max = 10
		short = true
	}
	n, err := swc.Conn.Write(b[:max])
	if err == nil && short {
		return n, io.ErrShortWrite
	}
	return n, err
}

func TestClientWriteLoopStall(t *testing.T) {
	opts := DefaultOptions()
	s := RunServer(opts)
	defer s.Shutdown()

	errCh := make(chan error, 1)

	url := fmt.Sprintf("nats://%s:%d", opts.Host, opts.Port)
	nc, err := nats.Connect(url,
		nats.ErrorHandler(func(_ *nats.Conn, _ *nats.Subscription, e error) {
			select {
			case errCh <- e:
			default:
			}
		}))
	if err != nil {
		t.Fatalf("Error on connect: %v", err)
	}
	defer nc.Close()
	sub, err := nc.SubscribeSync("foo")
	if err != nil {
		t.Fatalf("Error on subscribe: %v", err)
	}
	nc.Flush()
	cid, _ := nc.GetClientID()

	sender, err := nats.Connect(url)
	if err != nil {
		t.Fatalf("Error on connect: %v", err)
	}
	defer sender.Close()

	c := s.getClient(cid)
	c.mu.Lock()
	c.nc = &shortWriteConn{Conn: c.nc}
	c.mu.Unlock()

	sender.Publish("foo", make([]byte, 100))

	if _, err := sub.NextMsg(3 * time.Second); err != nil {
		t.Fatalf("WriteLoop has stalled!")
	}

	// Make sure that we did not get any async error
	select {
	case e := <-errCh:
		t.Fatalf("Got error: %v", e)
	case <-time.After(250 * time.Millisecond):
	}
}

func TestServerLogsConfigurationFile(t *testing.T) {
	file := createTempFile(t, "nats_server_log_")
	file.Close()

	conf := createConfFile(t, []byte(fmt.Sprintf(`
	port: -1
	logfile: '%s'
	`, file.Name())))

	o := LoadConfig(conf)
	o.ConfigFile = file.Name()
	o.NoLog = false
	s := RunServer(o)
	s.Shutdown()

	log, err := os.ReadFile(file.Name())
	if err != nil {
		t.Fatalf("Error reading log file: %v", err)
	}
	if !bytes.Contains(log, []byte(fmt.Sprintf("Using configuration file: %s", file.Name()))) {
		t.Fatalf("Config file location was not reported in log: %s", log)
	}
}

func TestServerRateLimitLogging(t *testing.T) {
	s := RunServer(DefaultOptions())
	defer s.Shutdown()

	s.changeRateLimitLogInterval(100 * time.Millisecond)

	l := &captureWarnLogger{warn: make(chan string, 100)}
	s.SetLogger(l, false, false)

	s.RateLimitWarnf("Warning number 1")
	s.RateLimitWarnf("Warning number 2")
	s.RateLimitWarnf("Warning number 1")
	s.RateLimitWarnf("Warning number 2")

	checkLog := func(c1, c2 *client) {
		t.Helper()

		nb1 := "Warning number 1"
		nb2 := "Warning number 2"
		gotOne := 0
		gotTwo := 0
		for done := false; !done; {
			select {
			case w := <-l.warn:
				if strings.Contains(w, nb1) {
					gotOne++
				} else if strings.Contains(w, nb2) {
					gotTwo++
				}
			case <-time.After(150 * time.Millisecond):
				done = true
			}
		}
		if gotOne != 1 {
			t.Fatalf("Should have had only 1 warning for nb1, got %v", gotOne)
		}
		if gotTwo != 1 {
			t.Fatalf("Should have had only 1 warning for nb2, got %v", gotTwo)
		}

		// Wait for more than the expiration interval
		time.Sleep(200 * time.Millisecond)
		if c1 == nil {
			s.RateLimitWarnf(nb1)
		} else {
			c1.RateLimitWarnf(nb1)
			c2.RateLimitWarnf(nb1)
		}
		gotOne = 0
		for {
			select {
			case w := <-l.warn:
				if strings.Contains(w, nb1) {
					gotOne++
				}
			case <-time.After(200 * time.Millisecond):
				if gotOne == 0 {
					t.Fatalf("Warning was still suppressed")
				} else if gotOne > 1 {
					t.Fatalf("Should have had only 1 warning for nb1, got %v", gotOne)
				} else {
					// OK! we are done
					return
				}
			}
		}
	}

	checkLog(nil, nil)

	nc1 := natsConnect(t, s.ClientURL(), nats.Name("c1"))
	defer nc1.Close()
	nc2 := natsConnect(t, s.ClientURL(), nats.Name("c2"))
	defer nc2.Close()

	var c1 *client
	var c2 *client
	s.mu.Lock()
	for _, cli := range s.clients {
		cli.mu.Lock()
		switch cli.opts.Name {
		case "c1":
			c1 = cli
		case "c2":
			c2 = cli
		}
		cli.mu.Unlock()
		if c1 != nil && c2 != nil {
			break
		}
	}
	s.mu.Unlock()
	if c1 == nil || c2 == nil {
		t.Fatal("Did not find the clients")
	}

	// Wait for more than the expiration interval
	time.Sleep(200 * time.Millisecond)

	c1.RateLimitWarnf("Warning number 1")
	c1.RateLimitWarnf("Warning number 2")
	c2.RateLimitWarnf("Warning number 1")
	c2.RateLimitWarnf("Warning number 2")

	checkLog(c1, c2)
}
