// Copyright 2022-2023 The NATS Authors
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

//go:build windows

package server

import (
	"fmt"
	"github.com/nats-io/nats.go"
	"os"
	"os/exec"
	"testing"
)

func runPowershellScript(scriptFile string, args []string) error {
	_ = args
	psExec, _ := exec.LookPath("powershell.exe")
	execArgs := []string{psExec, "-command", fmt.Sprintf("& '%s'", scriptFile)}

	cmdImport := &exec.Cmd{
		Path:   psExec,
		Args:   execArgs,
		Stdout: os.Stdout,
		Stderr: os.Stderr,
	}
	return cmdImport.Run()
}

// TestServerTLSWindowsCertStore tests the topology of a NATS server requiring TLS and gettings it own server
// cert identiy (as used when accepting NATS client connections and negotiating TLS) from Windows certificate store.
func TestServerTLSWindowsCertStore(t *testing.T) {

	// Server Identity (server.pem)
	// Issuer: O = Synadia Communications Inc., OU = NATS.io, CN = localhost
	// Subject: OU = NATS.io Operators, CN = localhost

	// Make sure windows cert store is reset to avoid conflict with other tests
	err := runPowershellScript("../test/configs/certs/tlsauth/certstore/delete-cert-from-store.ps1", nil)
	if err != nil {
		t.Fatalf("expected powershell cert delete to succeed: %s", err.Error())
	}

	// Provision Windows cert store with server cert and secret
	err = runPowershellScript("../test/configs/certs/tlsauth/certstore/import-p12-server.ps1", nil)
	if err != nil {
		t.Fatalf("expected powershell provision to succeed: %s", err.Error())
	}

	// Fire up the server
	srvConfig := createConfFile(t, []byte(`
	listen: "localhost:-1"
	tls {
		cert_store: "WindowsCurrentUser"
		cert_match_by: "Subject"
		cert_match: "NATS.io Operators"
		timeout: 5
	}
	`))
	defer removeFile(t, srvConfig)
	srvServer, _ := RunServerWithConfig(srvConfig)
	if srvServer == nil {
		t.Fatalf("expected to be able start server with cert store configuration")
	}
	defer srvServer.Shutdown()

	testCases := []struct {
		clientCA string
		expect   bool
	}{
		{"../test/configs/certs/tlsauth/ca.pem", true},
		{"../test/configs/certs/tlsauth/client.pem", false},
	}
	for _, tc := range testCases {
		t.Run(fmt.Sprintf("Client CA: %s", tc.clientCA), func(t *testing.T) {
			nc, _ := nats.Connect(srvServer.clientConnectURLs[0], nats.RootCAs(tc.clientCA))
			err := nc.Publish("foo", []byte("hello TLS server-authenticated server"))
			if (err != nil) == tc.expect {
				t.Fatalf("expected publish result %v to TLS authenticated server", tc.expect)
			}
			nc.Close()

			for i := 0; i < 5; i++ {
				nc, _ = nats.Connect(srvServer.clientConnectURLs[0], nats.RootCAs(tc.clientCA))
				err = nc.Publish("foo", []byte("hello TLS server-authenticated server"))
				if (err != nil) == tc.expect {
					t.Fatalf("expected repeated connection result %v to TLS authenticated server", tc.expect)
				}
				nc.Close()
			}
		})
	}
}
