// Copyright 2020-2022 The NATS Authors
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

//go:build !skip_js_tests
// +build !skip_js_tests

package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
)

func TestJetStreamJWTLimits(t *testing.T) {
	updateJwt := func(url string, creds string, pubKey string, jwt string) {
		t.Helper()
		c := natsConnect(t, url, nats.UserCredentials(creds))
		defer c.Close()
		if msg, err := c.Request(fmt.Sprintf(accUpdateEventSubjNew, pubKey), []byte(jwt), time.Second); err != nil {
			t.Fatal("error not expected in this test", err)
		} else {
			content := make(map[string]interface{})
			if err := json.Unmarshal(msg.Data, &content); err != nil {
				t.Fatalf("%v", err)
			} else if _, ok := content["data"]; !ok {
				t.Fatalf("did not get an ok response got: %v", content)
			}
		}
	}
	require_IdenticalLimits := func(infoLim JetStreamAccountLimits, lim jwt.JetStreamLimits) {
		t.Helper()
		if int64(infoLim.MaxConsumers) != lim.Consumer || int64(infoLim.MaxStreams) != lim.Streams ||
			infoLim.MaxMemory != lim.MemoryStorage || infoLim.MaxStore != lim.DiskStorage {
			t.Fatalf("limits do not match %v != %v", infoLim, lim)
		}
	}
	expect_JSDisabledForAccount := func(c *nats.Conn) {
		t.Helper()
		if _, err := c.Request("$JS.API.INFO", nil, time.Second); err != nats.ErrTimeout && err != nats.ErrNoResponders {
			t.Fatalf("Unexpected error: %v", err)
		}
	}
	expect_InfoError := func(c *nats.Conn) {
		t.Helper()
		var info JSApiAccountInfoResponse
		if resp, err := c.Request("$JS.API.INFO", nil, time.Second); err != nil {
			t.Fatalf("Unexpected error: %v", err)
		} else if err = json.Unmarshal(resp.Data, &info); err != nil {
			t.Fatalf("response1 %v got error %v", string(resp.Data), err)
		} else if info.Error == nil {
			t.Fatalf("expected error")
		}
	}
	validate_limits := func(c *nats.Conn, expectedLimits jwt.JetStreamLimits) {
		t.Helper()
		var info JSApiAccountInfoResponse
		if resp, err := c.Request("$JS.API.INFO", nil, time.Second); err != nil {
			t.Fatalf("Unexpected error: %v", err)
		} else if err = json.Unmarshal(resp.Data, &info); err != nil {
			t.Fatalf("response1 %v got error %v", string(resp.Data), err)
		} else {
			require_IdenticalLimits(info.Limits, expectedLimits)
		}
	}
	// create system account
	sysKp, _ := nkeys.CreateAccount()
	sysPub, _ := sysKp.PublicKey()
	sysUKp, _ := nkeys.CreateUser()
	sysUSeed, _ := sysUKp.Seed()
	uclaim := newJWTTestUserClaims()
	uclaim.Subject, _ = sysUKp.PublicKey()
	sysUserJwt, err := uclaim.Encode(sysKp)
	require_NoError(t, err)
	sysKp.Seed()
	sysCreds := genCredsFile(t, sysUserJwt, sysUSeed)
	// limits to apply and check
	limits1 := jwt.JetStreamLimits{MemoryStorage: 1024 * 1024, DiskStorage: 2048 * 1024, Streams: 1, Consumer: 2, MaxBytesRequired: true}
	// has valid limits that would fail when incorrectly applied twice
	limits2 := jwt.JetStreamLimits{MemoryStorage: 4096 * 1024, DiskStorage: 8192 * 1024, Streams: 3, Consumer: 4}
	// limits exceeding actual configured value of DiskStorage
	limitsExceeded := jwt.JetStreamLimits{MemoryStorage: 8192 * 1024, DiskStorage: 16384 * 1024, Streams: 5, Consumer: 6}
	// create account using jetstream with both limits
	akp, _ := nkeys.CreateAccount()
	aPub, _ := akp.PublicKey()
	claim := jwt.NewAccountClaims(aPub)
	claim.Limits.JetStreamLimits = limits1
	aJwt1, err := claim.Encode(oKp)
	require_NoError(t, err)
	claim.Limits.JetStreamLimits = limits2
	aJwt2, err := claim.Encode(oKp)
	require_NoError(t, err)
	claim.Limits.JetStreamLimits = limitsExceeded
	aJwtLimitsExceeded, err := claim.Encode(oKp)
	require_NoError(t, err)
	claim.Limits.JetStreamLimits = jwt.JetStreamLimits{} // disabled
	aJwt4, err := claim.Encode(oKp)
	require_NoError(t, err)
	// account user
	uKp, _ := nkeys.CreateUser()
	uSeed, _ := uKp.Seed()
	uclaim = newJWTTestUserClaims()
	uclaim.Subject, _ = uKp.PublicKey()
	userJwt, err := uclaim.Encode(akp)
	require_NoError(t, err)
	userCreds := genCredsFile(t, userJwt, uSeed)
	dir := t.TempDir()
	conf := createConfFile(t, []byte(fmt.Sprintf(`
		listen: 127.0.0.1:-1
		jetstream: {max_mem_store: 10Mb, max_file_store: 10Mb}
		operator: %s
		resolver: {
			type: full
			dir: '%s'
		}
		system_account: %s
    `, ojwt, dir, sysPub)))
	s, opts := RunServerWithConfig(conf)
	defer s.Shutdown()
	port := opts.Port
	updateJwt(s.ClientURL(), sysCreds, aPub, aJwt1)
	c := natsConnect(t, s.ClientURL(), nats.UserCredentials(userCreds), nats.ReconnectWait(200*time.Millisecond))
	defer c.Close()
	validate_limits(c, limits1)
	// keep using the same connection
	updateJwt(s.ClientURL(), sysCreds, aPub, aJwt2)
	validate_limits(c, limits2)
	// keep using the same connection but do NOT CHANGE anything.
	// This tests if the jwt is applied a second time (would fail)
	updateJwt(s.ClientURL(), sysCreds, aPub, aJwt2)
	validate_limits(c, limits2)
	// keep using the same connection. This update EXCEEDS LIMITS
	updateJwt(s.ClientURL(), sysCreds, aPub, aJwtLimitsExceeded)
	validate_limits(c, limits2)
	// disable test after failure
	updateJwt(s.ClientURL(), sysCreds, aPub, aJwt4)
	expect_InfoError(c)
	// re enable, again testing with a value that can't be applied twice
	updateJwt(s.ClientURL(), sysCreds, aPub, aJwt2)
	validate_limits(c, limits2)
	// disable test no prior failure
	updateJwt(s.ClientURL(), sysCreds, aPub, aJwt4)
	expect_InfoError(c)
	// Wrong limits form start
	updateJwt(s.ClientURL(), sysCreds, aPub, aJwtLimitsExceeded)
	expect_JSDisabledForAccount(c)
	// enable js but exceed limits. Followed by fix via restart
	updateJwt(s.ClientURL(), sysCreds, aPub, aJwt2)
	validate_limits(c, limits2)
	updateJwt(s.ClientURL(), sysCreds, aPub, aJwtLimitsExceeded)
	validate_limits(c, limits2)
	s.Shutdown()
	conf = createConfFile(t, []byte(fmt.Sprintf(`
		listen: 127.0.0.1:%d
		jetstream: {max_mem_store: 20Mb, max_file_store: 20Mb}
		operator: %s
		resolver: {
			type: full
			dir: '%s'
		}
		system_account: %s
    `, port, ojwt, dir, sysPub)))
	s, _ = RunServerWithConfig(conf)
	defer s.Shutdown()
	c.Flush() // force client to discover the disconnect
	checkClientsCount(t, s, 1)
	validate_limits(c, limitsExceeded)
	s.Shutdown()
	// disable jetstream test
	conf = createConfFile(t, []byte(fmt.Sprintf(`
		listen: 127.0.0.1:%d
		operator: %s
		resolver: {
			type: full
			dir: '%s'
		}
		system_account: %s
    `, port, ojwt, dir, sysPub)))
	s, _ = RunServerWithConfig(conf)
	defer s.Shutdown()
	c.Flush() // force client to discover the disconnect
	checkClientsCount(t, s, 1)
	expect_JSDisabledForAccount(c)
	// test that it stays disabled
	updateJwt(s.ClientURL(), sysCreds, aPub, aJwt2)
	expect_JSDisabledForAccount(c)
	c.Close()
}

func TestJetStreamJWTDisallowBearer(t *testing.T) {
	sysKp, syspub := createKey(t)
	sysJwt := encodeClaim(t, jwt.NewAccountClaims(syspub), syspub)
	sysCreds := newUser(t, sysKp)

	accKp, err := nkeys.CreateAccount()
	require_NoError(t, err)
	accIdPub, err := accKp.PublicKey()
	require_NoError(t, err)
	aClaim := jwt.NewAccountClaims(accIdPub)
	accJwt1, err := aClaim.Encode(oKp)
	require_NoError(t, err)
	aClaim.Limits.DisallowBearer = true
	accJwt2, err := aClaim.Encode(oKp)
	require_NoError(t, err)

	uc := jwt.NewUserClaims("dummy")
	uc.BearerToken = true
	uOpt1 := createUserCredsEx(t, uc, accKp)
	uc.BearerToken = false
	uOpt2 := createUserCredsEx(t, uc, accKp)

	dir := t.TempDir()
	cf := createConfFile(t, []byte(fmt.Sprintf(`
		port: -1
		operator = %s
		system_account: %s
		resolver: {
			type: full
			dir: '%s/jwt'
		}
		resolver_preload = {
			%s : "%s"
		}
		`, ojwt, syspub, dir, syspub, sysJwt)))
	s, _ := RunServerWithConfig(cf)
	defer s.Shutdown()

	updateJwt(t, s.ClientURL(), sysCreds, accJwt1, 1)
	disconnectErrCh := make(chan error, 10)
	defer close(disconnectErrCh)
	nc1, err := nats.Connect(s.ClientURL(), uOpt1,
		nats.NoReconnect(),
		nats.ErrorHandler(func(conn *nats.Conn, s *nats.Subscription, err error) {
			disconnectErrCh <- err
		}))
	require_NoError(t, err)
	defer nc1.Close()

	// update jwt and observe bearer token get disconnected
	updateJwt(t, s.ClientURL(), sysCreds, accJwt2, 1)
	select {
	case err := <-disconnectErrCh:
		require_Contains(t, err.Error(), "authorization violation")
	case <-time.After(time.Second):
		t.Fatalf("expected error on disconnect")
	}

	// assure bearer token is not allowed to connect
	_, err = nats.Connect(s.ClientURL(), uOpt1)
	require_Error(t, err)

	// assure non bearer token can connect
	nc2, err := nats.Connect(s.ClientURL(), uOpt2)
	require_NoError(t, err)
	defer nc2.Close()
}

func TestJetStreamExpiredAccountNotCountedTowardLimits(t *testing.T) {
	op, _ := nkeys.CreateOperator()
	opPk, _ := op.PublicKey()
	sk, _ := nkeys.CreateOperator()
	skPk, _ := sk.PublicKey()
	opClaim := jwt.NewOperatorClaims(opPk)
	opClaim.SigningKeys.Add(skPk)
	opJwt, err := opClaim.Encode(op)
	require_NoError(t, err)
	createAccountAndUser := func(pubKey, jwt1, creds1 *string) {
		t.Helper()
		kp, _ := nkeys.CreateAccount()
		*pubKey, _ = kp.PublicKey()
		claim := jwt.NewAccountClaims(*pubKey)
		claim.Limits.JetStreamLimits = jwt.JetStreamLimits{MemoryStorage: 7 * 1024 * 1024, DiskStorage: 7 * 1024 * 1024, Streams: 10}
		var err error
		*jwt1, err = claim.Encode(sk)
		require_NoError(t, err)

		ukp, _ := nkeys.CreateUser()
		seed, _ := ukp.Seed()
		upub, _ := ukp.PublicKey()
		uclaim := newJWTTestUserClaims()
		uclaim.Subject = upub

		ujwt1, err := uclaim.Encode(kp)
		require_NoError(t, err)
		*creds1 = genCredsFile(t, ujwt1, seed)
	}
	generateRequest := func(accs []string, kp nkeys.KeyPair) []byte {
		t.Helper()
		opk, _ := kp.PublicKey()
		c := jwt.NewGenericClaims(opk)
		c.Data["accounts"] = accs
		cJwt, err := c.Encode(kp)
		if err != nil {
			t.Fatalf("Expected no error %v", err)
		}
		return []byte(cJwt)
	}

	var syspub, sysjwt, sysCreds string
	createAccountAndUser(&syspub, &sysjwt, &sysCreds)

	dirSrv := t.TempDir()
	conf := createConfFile(t, []byte(fmt.Sprintf(`
		listen: 127.0.0.1:-1
		operator: %s
		jetstream: {max_mem_store: 10Mb, max_file_store: 10Mb}
		system_account: %s
		resolver: {
			type: full
			allow_delete: true
			dir: '%s'
			timeout: "500ms"
		}
    `, opJwt, syspub, dirSrv)))

	s, _ := RunServerWithConfig(conf)
	defer s.Shutdown()

	// update system account jwt
	updateJwt(t, s.ClientURL(), sysCreds, sysjwt, 1)

	var apub, ajwt1, aCreds1 string
	createAccountAndUser(&apub, &ajwt1, &aCreds1)
	// push jwt (for full resolver)
	updateJwt(t, s.ClientURL(), sysCreds, ajwt1, 1)

	ncA, jsA := jsClientConnect(t, s, nats.UserCredentials(aCreds1))
	defer ncA.Close()

	ai, err := jsA.AccountInfo()
	require_NoError(t, err)
	require_True(t, ai.Limits.MaxMemory == 7*1024*1024)
	ncA.Close()

	nc := natsConnect(t, s.ClientURL(), nats.UserCredentials(sysCreds))
	defer nc.Close()
	resp, err := nc.Request(accDeleteReqSubj, generateRequest([]string{apub}, sk), time.Second)
	require_NoError(t, err)
	require_True(t, strings.Contains(string(resp.Data), `"message":"deleted 1 accounts"`))

	var apub2, ajwt2, aCreds2 string
	createAccountAndUser(&apub2, &ajwt2, &aCreds2)
	// push jwt (for full resolver)
	updateJwt(t, s.ClientURL(), sysCreds, ajwt2, 1)

	ncB, jsB := jsClientConnect(t, s, nats.UserCredentials(aCreds2))
	defer ncB.Close()

	ai, err = jsB.AccountInfo()
	require_NoError(t, err)
	require_True(t, ai.Limits.MaxMemory == 7*1024*1024)
}

func TestJetStreamDeletedAccountDoesNotLeakSubscriptions(t *testing.T) {
	op, _ := nkeys.CreateOperator()
	opPk, _ := op.PublicKey()
	sk, _ := nkeys.CreateOperator()
	skPk, _ := sk.PublicKey()
	opClaim := jwt.NewOperatorClaims(opPk)
	opClaim.SigningKeys.Add(skPk)
	opJwt, err := opClaim.Encode(op)
	require_NoError(t, err)
	createAccountAndUser := func(pubKey, jwt1, creds1 *string) {
		t.Helper()
		kp, _ := nkeys.CreateAccount()
		*pubKey, _ = kp.PublicKey()
		claim := jwt.NewAccountClaims(*pubKey)
		claim.Limits.JetStreamLimits = jwt.JetStreamLimits{MemoryStorage: 7 * 1024 * 1024, DiskStorage: 7 * 1024 * 1024, Streams: 10}
		var err error
		*jwt1, err = claim.Encode(sk)
		require_NoError(t, err)

		ukp, _ := nkeys.CreateUser()
		seed, _ := ukp.Seed()
		upub, _ := ukp.PublicKey()
		uclaim := newJWTTestUserClaims()
		uclaim.Subject = upub

		ujwt1, err := uclaim.Encode(kp)
		require_NoError(t, err)
		*creds1 = genCredsFile(t, ujwt1, seed)
	}
	generateRequest := func(accs []string, kp nkeys.KeyPair) []byte {
		t.Helper()
		opk, _ := kp.PublicKey()
		c := jwt.NewGenericClaims(opk)
		c.Data["accounts"] = accs
		cJwt, err := c.Encode(kp)
		if err != nil {
			t.Fatalf("Expected no error %v", err)
		}
		return []byte(cJwt)
	}

	var syspub, sysjwt, sysCreds string
	createAccountAndUser(&syspub, &sysjwt, &sysCreds)

	dirSrv := t.TempDir()
	conf := createConfFile(t, []byte(fmt.Sprintf(`
		listen: 127.0.0.1:-1
		operator: %s
		jetstream: {max_mem_store: 10Mb, max_file_store: 10Mb, store_dir: %v}
		system_account: %s
		resolver: {
			type: full
			allow_delete: true
			dir: '%s'
			timeout: "500ms"
		}
	`, opJwt, dirSrv, syspub, dirSrv)))

	s, _ := RunServerWithConfig(conf)
	defer s.Shutdown()

	checkNumSubs := func(expected uint32) uint32 {
		t.Helper()
		// Wait a bit before capturing number of subs...
		time.Sleep(250 * time.Millisecond)

		var ns uint32
		checkFor(t, time.Second, 50*time.Millisecond, func() error {
			subsz, err := s.Subsz(nil)
			if err != nil {
				return err
			}
			ns = subsz.NumSubs
			if expected > 0 && ns > expected {
				return fmt.Errorf("Expected num subs to be back at %v, got %v",
					expected, ns)
			}
			return nil
		})
		return ns
	}
	beforeCreate := checkNumSubs(0)

	// update system account jwt
	updateJwt(t, s.ClientURL(), sysCreds, sysjwt, 1)

	createAndDelete := func() {
		t.Helper()

		var apub, ajwt1, aCreds1 string
		createAccountAndUser(&apub, &ajwt1, &aCreds1)
		// push jwt (for full resolver)
		updateJwt(t, s.ClientURL(), sysCreds, ajwt1, 1)

		ncA, jsA := jsClientConnect(t, s, nats.UserCredentials(aCreds1))
		defer ncA.Close()

		ai, err := jsA.AccountInfo()
		require_NoError(t, err)
		require_True(t, ai.Limits.MaxMemory == 7*1024*1024)
		ncA.Close()

		nc := natsConnect(t, s.ClientURL(), nats.UserCredentials(sysCreds))
		defer nc.Close()

		resp, err := nc.Request(accDeleteReqSubj, generateRequest([]string{apub}, sk), time.Second)
		require_NoError(t, err)
		require_True(t, strings.Contains(string(resp.Data), `"message":"deleted 1 accounts"`))
	}

	// Create and delete multiple accounts
	for i := 0; i < 10; i++ {
		createAndDelete()
	}

	// There is a subscription on `_R_.>` that is created on the system account
	// and that will not go away, so discount it.
	checkNumSubs(beforeCreate + 1)
}

func TestJetStreamDeletedAccountIsReEnabled(t *testing.T) {
	op, _ := nkeys.CreateOperator()
	opPk, _ := op.PublicKey()
	sk, _ := nkeys.CreateOperator()
	skPk, _ := sk.PublicKey()
	opClaim := jwt.NewOperatorClaims(opPk)
	opClaim.SigningKeys.Add(skPk)
	opJwt, err := opClaim.Encode(op)
	require_NoError(t, err)
	createAccountAndUser := func(pubKey, jwt1, creds1 *string) {
		t.Helper()
		kp, _ := nkeys.CreateAccount()
		*pubKey, _ = kp.PublicKey()
		claim := jwt.NewAccountClaims(*pubKey)
		claim.Limits.JetStreamLimits = jwt.JetStreamLimits{MemoryStorage: 7 * 1024 * 1024, DiskStorage: 7 * 1024 * 1024, Streams: 10}
		var err error
		*jwt1, err = claim.Encode(sk)
		require_NoError(t, err)

		ukp, _ := nkeys.CreateUser()
		seed, _ := ukp.Seed()
		upub, _ := ukp.PublicKey()
		uclaim := newJWTTestUserClaims()
		uclaim.Subject = upub

		ujwt1, err := uclaim.Encode(kp)
		require_NoError(t, err)
		*creds1 = genCredsFile(t, ujwt1, seed)
	}
	generateRequest := func(accs []string, kp nkeys.KeyPair) []byte {
		t.Helper()
		opk, _ := kp.PublicKey()
		c := jwt.NewGenericClaims(opk)
		c.Data["accounts"] = accs
		cJwt, err := c.Encode(kp)
		if err != nil {
			t.Fatalf("Expected no error %v", err)
		}
		return []byte(cJwt)
	}

	// admin user
	var syspub, sysjwt, sysCreds string
	createAccountAndUser(&syspub, &sysjwt, &sysCreds)

	dirSrv := t.TempDir()
	conf := createConfFile(t, []byte(fmt.Sprintf(`
		listen: 127.0.0.1:-1
		operator: %s
		jetstream: {max_mem_store: 10Mb, max_file_store: 10Mb, store_dir: %v}
		system_account: %s
		resolver: {
			type: full
			allow_delete: true
			dir: '%s'
			timeout: "500ms"
		}
	`, opJwt, dirSrv, syspub, dirSrv)))

	s, _ := RunServerWithConfig(conf)
	defer s.Shutdown()

	// update system account jwt
	updateJwt(t, s.ClientURL(), sysCreds, sysjwt, 1)

	// create account
	var apub, ajwt1, aCreds1 string
	kp, _ := nkeys.CreateAccount()
	apub, _ = kp.PublicKey()
	claim := jwt.NewAccountClaims(apub)
	claim.Limits.JetStreamLimits = jwt.JetStreamLimits{
		MemoryStorage: 7 * 1024 * 1024,
		DiskStorage:   7 * 1024 * 1024,
		Streams:       10,
	}
	ajwt1, err = claim.Encode(sk)
	require_NoError(t, err)

	// user
	ukp, _ := nkeys.CreateUser()
	seed, _ := ukp.Seed()
	upub, _ := ukp.PublicKey()
	uclaim := newJWTTestUserClaims()
	uclaim.Subject = upub

	ujwt1, err := uclaim.Encode(kp)
	require_NoError(t, err)
	aCreds1 = genCredsFile(t, ujwt1, seed)

	// push user account
	updateJwt(t, s.ClientURL(), sysCreds, ajwt1, 1)

	ncA, jsA := jsClientConnect(t, s, nats.UserCredentials(aCreds1))
	defer ncA.Close()

	jsA.AddStream(&nats.StreamConfig{Name: "foo"})
	jsA.Publish("foo", []byte("Hello World"))
	jsA.Publish("foo", []byte("Hello Again"))

	// JS should be working
	ai, err := jsA.AccountInfo()
	require_NoError(t, err)
	require_True(t, ai.Limits.MaxMemory == 7*1024*1024)
	require_True(t, ai.Limits.MaxStore == 7*1024*1024)
	require_True(t, ai.Tier.Streams == 1)

	// connect with a different connection and delete the account.
	nc := natsConnect(t, s.ClientURL(), nats.UserCredentials(sysCreds))
	defer nc.Close()

	// delete account
	resp, err := nc.Request(accDeleteReqSubj, generateRequest([]string{apub}, sk), time.Second)
	require_NoError(t, err)
	require_True(t, strings.Contains(string(resp.Data), `"message":"deleted 1 accounts"`))

	// account was disabled and now disconnected, this should get a connection is closed error.
	_, err = jsA.AccountInfo()
	if err == nil || !errors.Is(err, nats.ErrConnectionClosed) {
		t.Errorf("Expected connection closed error, got: %v", err)
	}
	ncA.Close()

	// re-enable, same claims would be detected
	updateJwt(t, s.ClientURL(), sysCreds, ajwt1, 1)

	// expected to get authorization timeout at this time
	_, err = nats.Connect(s.ClientURL(), nats.UserCredentials(aCreds1))
	if !errors.Is(err, nats.ErrAuthorization) {
		t.Errorf("Expected authorization issue on connect, got: %v", err)
	}

	// edit the account and push again with updated claims to same account
	claim = jwt.NewAccountClaims(apub)
	claim.Limits.JetStreamLimits = jwt.JetStreamLimits{
		MemoryStorage: -1,
		DiskStorage:   10 * 1024 * 1024,
		Streams:       10,
	}
	ajwt1, err = claim.Encode(sk)
	require_NoError(t, err)
	updateJwt(t, s.ClientURL(), sysCreds, ajwt1, 1)

	// reconnect with the updated account
	ncA, jsA = jsClientConnect(t, s, nats.UserCredentials(aCreds1))
	defer ncA.Close()
	ai, err = jsA.AccountInfo()
	if err != nil {
		t.Fatal(err)
	}
	require_True(t, ai.Limits.MaxMemory == -1)
	require_True(t, ai.Limits.MaxStore == 10*1024*1024)
	require_True(t, ai.Tier.Streams == 1)

	// should be possible to get stream info again
	si, err := jsA.StreamInfo("foo")
	if err != nil {
		t.Fatal(err)
	}
	if si.State.Msgs != 2 {
		t.Fatal("Unexpected number of messages from recovered stream")
	}
	msg, err := jsA.GetMsg("foo", 1)
	if err != nil {
		t.Fatal(err)
	}
	if string(msg.Data) != "Hello World" {
		t.Error("Unexpected message")
	}
	ncA.Close()
}
