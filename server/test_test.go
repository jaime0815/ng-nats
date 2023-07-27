// Copyright 2019-2023 The NATS Authors
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
	"fmt"
	"math/rand"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

// DefaultTestOptions are default options for the unit tests.
var DefaultTestOptions = Options{
	Host:                  "127.0.0.1",
	Port:                  4222,
	NoLog:                 true,
	NoSigs:                true,
	MaxControlLine:        4096,
	DisableShortFirstPing: true,
}

func testDefaultClusterOptionsForLeafNodes() *Options {
	o := DefaultTestOptions
	o.Port = -1
	o.Cluster.Host = o.Host
	o.Cluster.Port = -1
	o.Gateway.Host = o.Host
	o.Gateway.Port = -1
	o.LeafNode.Host = o.Host
	o.LeafNode.Port = -1
	return &o
}

func RunRandClientPortServer() *Server {
	opts := DefaultTestOptions
	opts.Port = -1
	return RunServer(&opts)
}

func require_True(t *testing.T, b bool) {
	t.Helper()
	if !b {
		t.Fatalf("require true, but got false")
	}
}

func require_False(t *testing.T, b bool) {
	t.Helper()
	if b {
		t.Fatalf("require false, but got true")
	}
}

func require_NoError(t testing.TB, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("require no error, but got: %v", err)
	}
}

func require_NotNil(t testing.TB, v any) {
	t.Helper()
	if v == nil {
		t.Fatalf("require not nil, but got: %v", v)
	}
}

func require_Contains(t *testing.T, s string, subStrs ...string) {
	t.Helper()
	for _, subStr := range subStrs {
		if !strings.Contains(s, subStr) {
			t.Fatalf("require %q to be contained in %q", subStr, s)
		}
	}
}

func require_Error(t *testing.T, err error, expected ...error) {
	t.Helper()
	if err == nil {
		t.Fatalf("require error, but got none")
	}
	if len(expected) == 0 {
		return
	}
	// Try to strip nats prefix from Go library if present.
	const natsErrPre = "nats: "
	eStr := err.Error()
	if strings.HasPrefix(eStr, natsErrPre) {
		eStr = strings.Replace(eStr, natsErrPre, _EMPTY_, 1)
	}

	for _, e := range expected {
		if err == e || strings.Contains(eStr, e.Error()) || strings.Contains(e.Error(), eStr) {
			return
		}
	}
	t.Fatalf("Expected one of %v, got '%v'", expected, err)
}

func require_Equal(t *testing.T, a, b string) {
	t.Helper()
	if strings.Compare(a, b) != 0 {
		t.Fatalf("require equal, but got: %v != %v", a, b)
	}
}

func require_NotEqual(t *testing.T, a, b [32]byte) {
	t.Helper()
	if bytes.Equal(a[:], b[:]) {
		t.Fatalf("require not equal, but got: %v != %v", a, b)
	}
}

func require_Len(t *testing.T, a, b int) {
	t.Helper()
	if a != b {
		t.Fatalf("require len, but got: %v != %v", a, b)
	}
}

func checkNatsError(t *testing.T, e *ApiError, id ErrorIdentifier) {
	t.Helper()
	ae, ok := ApiErrors[id]
	if !ok {
		t.Fatalf("Unknown error ID identifier: %d", id)
	}

	if e.ErrCode != ae.ErrCode {
		t.Fatalf("Did not get NATS Error %d: %+v", e.ErrCode, e)
	}
}

func (c *cluster) shutdown() {
	if c == nil {
		return
	}
	// Stop any proxies.
	for _, np := range c.nproxies {
		np.stop()
	}
	// Shutdown and cleanup servers.
	for i, s := range c.servers {
		sd := s.StoreDir()
		s.Shutdown()
		if cf := c.opts[i].ConfigFile; cf != _EMPTY_ {
			os.Remove(cf)
		}
		if sd != _EMPTY_ {
			sd = strings.TrimSuffix(sd, JetStreamStoreDir)
			os.RemoveAll(sd)
		}
	}
}

func shutdownCluster(c *cluster) {
	c.shutdown()
}

func (c *cluster) randomServer() *Server {
	return c.randomServerFromCluster(c.name)
}

func (c *cluster) randomServerFromCluster(cname string) *Server {
	// Since these can be randomly shutdown in certain tests make sure they are running first.
	// Copy our servers list and shuffle then walk looking for first running server.
	cs := append(c.servers[:0:0], c.servers...)
	rand.Shuffle(len(cs), func(i, j int) { cs[i], cs[j] = cs[j], cs[i] })

	for _, s := range cs {
		if s.Running() && s.ClusterName() == cname {
			return s
		}
	}
	return nil
}

func runSolicitLeafServer(lso *Options) (*Server, *Options) {
	return runSolicitLeafServerToURL(fmt.Sprintf("nats-leaf://%s:%d", lso.LeafNode.Host, lso.LeafNode.Port))
}

func runSolicitLeafServerToURL(surl string) (*Server, *Options) {
	o := DefaultTestOptions
	o.Port = -1
	o.NoSystemAccount = true
	rurl, _ := url.Parse(surl)
	o.LeafNode.Remotes = []*RemoteLeafOpts{{URLs: []*url.URL{rurl}}}
	o.LeafNode.ReconnectInterval = 100 * time.Millisecond
	return RunServer(&o), &o
}
