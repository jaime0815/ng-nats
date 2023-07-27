// Copyright 2020-2023 The NATS Authors
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

// Do not exlude this file with the !skip_js_tests since those helpers
// are also used by MQTT.

package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	"golang.org/x/time/rate"
)

// Used to setup clusters of clusters for tests.
type cluster struct {
	servers  []*Server
	opts     []*Options
	name     string
	t        testing.TB
	nproxies []*netProxy
}

// Used to setup superclusters for tests.
type supercluster struct {
	t        *testing.T
	clusters []*cluster
	nproxies []*netProxy
}

func (sc *supercluster) shutdown() {
	if sc == nil {
		return
	}
	for _, np := range sc.nproxies {
		np.stop()
	}
	for _, c := range sc.clusters {
		shutdownCluster(c)
	}
}

func (sc *supercluster) serverByName(sname string) *Server {
	for _, c := range sc.clusters {
		if s := c.serverByName(sname); s != nil {
			return s
		}
	}
	return nil
}

var jsClusterAccountsTempl = `
	listen: 127.0.0.1:-1

	server_name: %s
	jetstream: {max_mem_store: 256MB, max_file_store: 2GB, store_dir: '%s'}

	leaf {
		listen: 127.0.0.1:-1
	}

	cluster {
		name: %s
		listen: 127.0.0.1:%d
		routes = [%s]
	}

	websocket {
		listen: 127.0.0.1:-1
		compression: true
		handshake_timeout: "5s"
		no_tls: true
	}

	no_auth_user: one

	accounts {
		ONE { users = [ { user: "one", pass: "p" } ]; jetstream: enabled }
		TWO { users = [ { user: "two", pass: "p" } ]; jetstream: enabled }
		NOJS { users = [ { user: "nojs", pass: "p" } ] }
		$SYS { users = [ { user: "admin", pass: "s3cr3t!" } ] }
	}
`

var jsClusterTempl = `
	listen: 127.0.0.1:-1
	server_name: %s
	jetstream: {max_mem_store: 256MB, max_file_store: 2GB, store_dir: '%s'}

	leaf {
		listen: 127.0.0.1:-1
	}

	cluster {
		name: %s
		listen: 127.0.0.1:%d
		routes = [%s]
	}

	# For access to system account.
	accounts { $SYS { users = [ { user: "admin", pass: "s3cr3t!" } ] } }
`

var jsClusterEncryptedTempl = `
	listen: 127.0.0.1:-1
	server_name: %s
	jetstream: {max_mem_store: 256MB, max_file_store: 2GB, store_dir: '%s', key: "s3cr3t!"}

	leaf {
		listen: 127.0.0.1:-1
	}

	cluster {
		name: %s
		listen: 127.0.0.1:%d
		routes = [%s]
	}

	# For access to system account.
	accounts { $SYS { users = [ { user: "admin", pass: "s3cr3t!" } ] } }
`

var jsClusterMaxBytesTempl = `
	listen: 127.0.0.1:-1
	server_name: %s
	jetstream: {max_mem_store: 256MB, max_file_store: 2GB, store_dir: '%s'}

	leaf {
		listen: 127.0.0.1:-1
	}

	cluster {
		name: %s
		listen: 127.0.0.1:%d
		routes = [%s]
	}

	no_auth_user: u

	accounts {
		$U {
			users = [ { user: "u", pass: "p" } ]
			jetstream: {
				max_mem:   128MB
				max_file:  18GB
				max_bytes: true // Forces streams to indicate max_bytes.
			}
		}
		$SYS { users = [ { user: "admin", pass: "s3cr3t!" } ] }
	}
`

var jsClusterMaxBytesAccountLimitTempl = `
	listen: 127.0.0.1:-1
	server_name: %s
	jetstream: {max_mem_store: 256MB, max_file_store: 4GB, store_dir: '%s'}

	leaf {
		listen: 127.0.0.1:-1
	}

	cluster {
		name: %s
		listen: 127.0.0.1:%d
		routes = [%s]
	}

	no_auth_user: u

	accounts {
		$U {
			users = [ { user: "u", pass: "p" } ]
			jetstream: {
				max_mem:   128MB
				max_file:  3GB
				max_bytes: true // Forces streams to indicate max_bytes.
			}
		}
		$SYS { users = [ { user: "admin", pass: "s3cr3t!" } ] }
	}
`

var jsSuperClusterTempl = `
	%s
	gateway {
		name: %s
		listen: 127.0.0.1:%d
		gateways = [%s
		]
	}

	system_account: "$SYS"
`

var jsClusterLimitsTempl = `
	listen: 127.0.0.1:-1
	server_name: %s
	jetstream: {max_mem_store: 2MB, max_file_store: 8MB, store_dir: '%s'}

	cluster {
		name: %s
		listen: 127.0.0.1:%d
		routes = [%s]
	}

	no_auth_user: u

	accounts {
		ONE {
			users = [ { user: "u", pass: "s3cr3t!" } ]
			jetstream: enabled
		}
		$SYS { users = [ { user: "admin", pass: "s3cr3t!" } ] }
	}
`

var jsMixedModeGlobalAccountTempl = `
	listen: 127.0.0.1:-1
	server_name: %s
	jetstream: {max_mem_store: 2MB, max_file_store: 8MB, store_dir: '%s'}

	cluster {
		name: %s
		listen: 127.0.0.1:%d
		routes = [%s]
	}

	accounts {$SYS { users = [ { user: "admin", pass: "s3cr3t!" } ] } }
`

// Helper function to close and disable leafnodes.
func (s *Server) closeAndDisableLeafnodes() {
	var leafs []*client
	s.mu.Lock()
	for _, ln := range s.leafs {
		leafs = append(leafs, ln)
	}
	// Disable leafnodes for now.
	s.leafDisableConnect = true
	s.mu.Unlock()

	for _, ln := range leafs {
		ln.closeConnection(Revocation)
	}
}

// Helper function to re-enable leafnode connections.
func (s *Server) reEnableLeafnodes() {
	s.mu.Lock()
	// Re-enable leafnodes.
	s.leafDisableConnect = false
	s.mu.Unlock()
}

// Helper to set the remote migrate feature.
func (s *Server) setJetStreamMigrateOnRemoteLeaf() {
	s.mu.Lock()
	for _, cfg := range s.leafRemoteCfgs {
		cfg.JetStreamClusterMigrate = true
	}
	s.mu.Unlock()
}

// Will add in the mapping for the account to each server.
func (c *cluster) addSubjectMapping(account, src, dest string) {
	c.t.Helper()

	for _, s := range c.servers {
		if s.ClusterName() != c.name {
			continue
		}
		acc, err := s.LookupAccount(account)
		if err != nil {
			c.t.Fatalf("Unexpected error on %v: %v", s, err)
		}
		if err := acc.AddMapping(src, dest); err != nil {
			c.t.Fatalf("Error adding mapping: %v", err)
		}
	}
	// Make sure interest propagates.
	time.Sleep(200 * time.Millisecond)
}

// Adjust limits for the given account.
func (c *cluster) updateLimits(account string, newLimits map[string]JetStreamAccountLimits) {
	c.t.Helper()
	for _, s := range c.servers {
		acc, err := s.LookupAccount(account)
		if err != nil {
			c.t.Fatalf("Unexpected error: %v", err)
		}
		if err := acc.UpdateJetStreamLimits(newLimits); err != nil {
			c.t.Fatalf("Unexpected error: %v", err)
		}
	}
}

// Hack for staticcheck
var skip = func(t *testing.T) {
	t.SkipNow()
}

func jsClientConnect(t testing.TB, s *Server, opts ...nats.Option) (*nats.Conn, nats.JetStreamContext) {
	t.Helper()
	nc, err := nats.Connect(s.ClientURL(), opts...)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	js, err := nc.JetStream(nats.MaxWait(10 * time.Second))
	if err != nil {
		t.Fatalf("Unexpected error getting JetStream context: %v", err)
	}
	return nc, js
}

func jsClientConnectEx(t testing.TB, s *Server, domain string, opts ...nats.Option) (*nats.Conn, nats.JetStreamContext) {
	t.Helper()
	nc, err := nats.Connect(s.ClientURL(), opts...)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	js, err := nc.JetStream(nats.MaxWait(10*time.Second), nats.Domain(domain))
	if err != nil {
		t.Fatalf("Unexpected error getting JetStream context: %v", err)
	}
	return nc, js
}

func jsClientConnectURL(t testing.TB, url string, opts ...nats.Option) (*nats.Conn, nats.JetStreamContext) {
	t.Helper()

	nc, err := nats.Connect(url, opts...)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	js, err := nc.JetStream(nats.MaxWait(10 * time.Second))
	if err != nil {
		t.Fatalf("Unexpected error getting JetStream context: %v", err)
	}
	return nc, js
}

func checkSubsPending(t *testing.T, sub *nats.Subscription, numExpected int) {
	t.Helper()
	checkFor(t, 10*time.Second, 20*time.Millisecond, func() error {
		if nmsgs, _, err := sub.Pending(); err != nil || nmsgs != numExpected {
			return fmt.Errorf("Did not receive correct number of messages: %d vs %d", nmsgs, numExpected)
		}
		return nil
	})
}

func fetchMsgs(t *testing.T, sub *nats.Subscription, numExpected int, totalWait time.Duration) []*nats.Msg {
	t.Helper()
	result := make([]*nats.Msg, 0, numExpected)
	for start, count, wait := time.Now(), numExpected, totalWait; len(result) != numExpected; {
		msgs, err := sub.Fetch(count, nats.MaxWait(wait))
		if err != nil {
			t.Fatal(err)
		}
		result = append(result, msgs...)
		count -= len(msgs)
		if wait = totalWait - time.Since(start); wait < 0 {
			break
		}
	}
	if len(result) != numExpected {
		t.Fatalf("Unexpected msg count, got %d, want %d", len(result), numExpected)
	}
	return result
}

func (c *cluster) restartServer(rs *Server) *Server {
	c.t.Helper()
	index := -1
	var opts *Options
	for i, s := range c.servers {
		if s == rs {
			index = i
			break
		}
	}
	if index < 0 {
		c.t.Fatalf("Could not find server %v to restart", rs)
	}
	opts = c.opts[index]
	s, o := RunServerWithConfig(opts.ConfigFile)
	c.servers[index] = s
	c.opts[index] = o
	return s
}

func (c *cluster) waitOnServerHealthz(s *Server) {
	c.t.Helper()
	expires := time.Now().Add(30 * time.Second)
	for time.Now().Before(expires) {
		hs := s.healthz(nil)
		if hs.Status == "ok" && hs.Error == _EMPTY_ {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	c.t.Fatalf("Expected server %q to eventually return healthz 'ok', but got %q", s, s.healthz(nil).Error)
}

func (c *cluster) waitOnServerCurrent(s *Server) {
	c.t.Helper()
	expires := time.Now().Add(30 * time.Second)
	for time.Now().Before(expires) {
		time.Sleep(100 * time.Millisecond)
		if !s.JetStreamEnabled() {
			return
		}
	}
	c.t.Fatalf("Expected server %q to eventually be current", s)
}

func (c *cluster) waitOnAllCurrent() {
	c.t.Helper()
	for _, cs := range c.servers {
		c.waitOnServerCurrent(cs)
	}
}

func (c *cluster) serverByName(sname string) *Server {
	for _, s := range c.servers {
		if s.Name() == sname {
			return s
		}
	}
	return nil
}

// Helper function to remove JetStream from a server.
func (c *cluster) removeJetStream(s *Server) {
	c.t.Helper()
	index := -1
	for i, cs := range c.servers {
		if cs == s {
			index = i
			break
		}
	}
	cf := c.opts[index].ConfigFile
	cb, _ := os.ReadFile(cf)
	var sb strings.Builder
	for _, l := range strings.Split(string(cb), "\n") {
		if !strings.HasPrefix(strings.TrimSpace(l), "jetstream") {
			sb.WriteString(l + "\n")
		}
	}
	if err := os.WriteFile(cf, []byte(sb.String()), 0644); err != nil {
		c.t.Fatalf("Error writing updated config file: %v", err)
	}
	if err := s.Reload(); err != nil {
		c.t.Fatalf("Error on server reload: %v", err)
	}
	time.Sleep(100 * time.Millisecond)
}

func (c *cluster) stopAll() {
	c.t.Helper()
	for _, s := range c.servers {
		s.Shutdown()
	}
}

func (c *cluster) totalSubs() (total int) {
	c.t.Helper()
	for _, s := range c.servers {
		total += int(s.NumSubscriptions())
	}
	return total
}

func (c *cluster) stableTotalSubs() (total int) {
	nsubs := -1
	checkFor(c.t, 2*time.Second, 250*time.Millisecond, func() error {
		subs := c.totalSubs()
		if subs == nsubs {
			return nil
		}
		nsubs = subs
		return fmt.Errorf("Still stabilizing")
	})
	return nsubs

}

func addStream(t *testing.T, nc *nats.Conn, cfg *StreamConfig) *StreamInfo {
	t.Helper()
	si, err := addStreamWithError(t, nc, cfg)
	if err != nil {
		t.Fatalf("Unexpected error: %+v", err)
	}
	return si
}

func addStreamWithError(t *testing.T, nc *nats.Conn, cfg *StreamConfig) (*StreamInfo, *ApiError) {
	t.Helper()
	req, err := json.Marshal(cfg)
	require_NoError(t, err)
	rmsg, err := nc.Request(fmt.Sprintf(JSApiStreamCreateT, cfg.Name), req, time.Second)
	require_NoError(t, err)
	var resp JSApiStreamCreateResponse
	err = json.Unmarshal(rmsg.Data, &resp)
	require_NoError(t, err)
	if resp.Type != JSApiStreamCreateResponseType {
		t.Fatalf("Invalid response type %s expected %s", resp.Type, JSApiStreamCreateResponseType)
	}
	return resp.StreamInfo, resp.Error
}

func updateStream(t *testing.T, nc *nats.Conn, cfg *StreamConfig) *StreamInfo {
	t.Helper()
	req, err := json.Marshal(cfg)
	require_NoError(t, err)
	rmsg, err := nc.Request(fmt.Sprintf(JSApiStreamUpdateT, cfg.Name), req, time.Second)
	require_NoError(t, err)
	var resp JSApiStreamCreateResponse
	err = json.Unmarshal(rmsg.Data, &resp)
	require_NoError(t, err)
	if resp.Type != JSApiStreamUpdateResponseType {
		t.Fatalf("Invalid response type %s expected %s", resp.Type, JSApiStreamUpdateResponseType)
	}
	if resp.Error != nil {
		t.Fatalf("Unexpected error: %+v", resp.Error)
	}
	return resp.StreamInfo
}

// setInActiveDeleteThreshold sets the delete threshold for how long to wait
// before deleting an inactive consumer.
func (o *consumer) setInActiveDeleteThreshold(dthresh time.Duration) error {
	o.mu.Lock()
	defer o.mu.Unlock()

	deleteWasRunning := o.dtmr != nil
	stopAndClearTimer(&o.dtmr)
	// Do not add jitter if set via here.
	o.dthresh = dthresh
	if deleteWasRunning {
		o.dtmr = time.AfterFunc(o.dthresh, func() { o.deleteNotActive() })
	}
	return nil
}

// Net Proxy - For introducing RTT and BW constraints.
type netProxy struct {
	listener net.Listener
	conns    []net.Conn
	rtt      time.Duration
	up       int
	down     int
	url      string
	surl     string
}

func newNetProxy(rtt time.Duration, upRate, downRate int, serverURL string) *netProxy {
	return createNetProxy(rtt, upRate, downRate, serverURL, true)
}

func createNetProxy(rtt time.Duration, upRate, downRate int, serverURL string, start bool) *netProxy {
	hp := net.JoinHostPort("127.0.0.1", "0")
	l, e := net.Listen("tcp", hp)
	if e != nil {
		panic(fmt.Sprintf("Error listening on port: %s, %q", hp, e))
	}
	port := l.Addr().(*net.TCPAddr).Port
	proxy := &netProxy{
		listener: l,
		rtt:      rtt,
		up:       upRate,
		down:     downRate,
		url:      fmt.Sprintf("nats://127.0.0.1:%d", port),
		surl:     serverURL,
	}
	if start {
		proxy.start()
	}
	return proxy
}

func (np *netProxy) start() {
	u, err := url.Parse(np.surl)
	if err != nil {
		panic(fmt.Sprintf("Could not parse server URL: %v", err))
	}
	host := u.Host

	go func() {
		for {
			client, err := np.listener.Accept()
			if err != nil {
				return
			}
			server, err := net.DialTimeout("tcp", host, time.Second)
			if err != nil {
				continue
			}
			np.conns = append(np.conns, client, server)
			go np.loop(np.rtt, np.up, client, server)
			go np.loop(np.rtt, np.down, server, client)
		}
	}()
}

func (np *netProxy) clientURL() string {
	return np.url
}

func (np *netProxy) routeURL() string {
	return strings.Replace(np.url, "nats", "nats-route", 1)
}

func (np *netProxy) loop(rtt time.Duration, tbw int, r, w net.Conn) {
	delay := rtt / 2
	const rbl = 8192
	var buf [rbl]byte
	ctx := context.Background()

	rl := rate.NewLimiter(rate.Limit(tbw), rbl)

	for {
		n, err := r.Read(buf[:])
		if err != nil {
			return
		}
		// RTT delays
		if delay > 0 {
			time.Sleep(delay)
		}
		if err := rl.WaitN(ctx, n); err != nil {
			return
		}
		if _, err = w.Write(buf[:n]); err != nil {
			return
		}
	}
}

func (np *netProxy) stop() {
	if np.listener != nil {
		np.listener.Close()
		np.listener = nil
		for _, c := range np.conns {
			c.Close()
		}
	}
}

// Bitset, aka bitvector, allows tracking of large number of bits efficiently
type bitset struct {
	// Bit map storage
	bitmap []uint8
	// Number of bits currently set to 1
	currentCount uint64
	// Number of bits stored
	size uint64
}

func NewBitset(size uint64) *bitset {
	byteSize := (size + 7) / 8 //Round up to the nearest byte

	return &bitset{
		bitmap:       make([]uint8, int(byteSize)),
		size:         size,
		currentCount: 0,
	}
}

func (b *bitset) get(index uint64) bool {
	if index >= b.size {
		panic(fmt.Sprintf("Index %d out of bounds, size %d", index, b.size))
	}
	byteIndex := index / 8
	bitIndex := uint(index % 8)
	bit := (b.bitmap[byteIndex] & (uint8(1) << bitIndex))
	return bit != 0
}

func (b *bitset) set(index uint64, value bool) {
	if index >= b.size {
		panic(fmt.Sprintf("Index %d out of bounds, size %d", index, b.size))
	}
	byteIndex := index / 8
	bitIndex := uint(index % 8)
	byteMask := uint8(1) << bitIndex
	isSet := (b.bitmap[byteIndex] & (uint8(1) << bitIndex)) != 0
	if value {
		b.bitmap[byteIndex] |= byteMask
		if !isSet {
			b.currentCount += 1
		}
	} else {
		b.bitmap[byteIndex] &= ^byteMask
		if isSet {
			b.currentCount -= 1
		}
	}
}

func (b *bitset) count() uint64 {
	return b.currentCount
}

func (b *bitset) String() string {
	const block = 8 // 8 bytes, 64 bits per line
	sb := strings.Builder{}

	sb.WriteString(fmt.Sprintf("Bits set: %d/%d\n", b.currentCount, b.size))
	for i := 0; i < len(b.bitmap); i++ {
		if i%block == 0 {
			if i > 0 {
				sb.WriteString("\n")
			}
			sb.WriteString(fmt.Sprintf("[%4d] ", i*8))
		}
		for j := uint8(0); j < 8; j++ {
			if b.bitmap[i]&(1<<j) > 0 {
				sb.WriteString("1")
			} else {
				sb.WriteString("0")
			}
		}
	}
	sb.WriteString("\n")
	return sb.String()
}
