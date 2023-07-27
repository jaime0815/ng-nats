// Copyright 2018-2023 The NATS Authors
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
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
	"github.com/nats-io/nuid"
)

func createAccount(s *Server) (*Account, nkeys.KeyPair) {
	okp, _ := nkeys.FromSeed(oSeed)
	akp, _ := nkeys.CreateAccount()
	pub, _ := akp.PublicKey()
	nac := jwt.NewAccountClaims(pub)
	jwt, _ := nac.Encode(okp)
	addAccountToMemResolver(s, pub, jwt)
	acc, err := s.LookupAccount(pub)
	if err != nil {
		panic(err)
	}
	return acc, akp
}

func createUserCredsEx(t *testing.T, nuc *jwt.UserClaims, akp nkeys.KeyPair) nats.Option {
	t.Helper()
	kp, _ := nkeys.CreateUser()
	nuc.Subject, _ = kp.PublicKey()
	ujwt, err := nuc.Encode(akp)
	if err != nil {
		t.Fatalf("Error generating user JWT: %v", err)
	}
	userCB := func() (string, error) {
		return ujwt, nil
	}
	sigCB := func(nonce []byte) ([]byte, error) {
		sig, _ := kp.Sign(nonce)
		return sig, nil
	}
	return nats.UserJWT(userCB, sigCB)
}

func createUserCreds(t *testing.T, s *Server, akp nkeys.KeyPair) nats.Option {
	return createUserCredsEx(t, jwt.NewUserClaims("test"), akp)
}

func runTrustedServer(t *testing.T) (*Server, *Options) {
	t.Helper()
	opts := DefaultOptions()
	kp, _ := nkeys.FromSeed(oSeed)
	pub, _ := kp.PublicKey()
	opts.TrustedKeys = []string{pub}
	opts.AccountResolver = &MemAccResolver{}
	s := RunServer(opts)
	return s, opts
}

func TestSystemAccount(t *testing.T) {
	s, _ := runTrustedServer(t)
	defer s.Shutdown()

	acc, _ := createAccount(s)
	s.setSystemAccount(acc)

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.sys == nil || s.sys.account == nil {
		t.Fatalf("Expected sys.account to be non-nil")
	}
	if s.sys.client == nil {
		t.Fatalf("Expected sys.client to be non-nil")
	}

	s.sys.client.mu.Lock()
	defer s.sys.client.mu.Unlock()
	if s.sys.client.echo {
		t.Fatalf("Internal clients should always have echo false")
	}
}

func TestSystemAccountNewConnection(t *testing.T) {
	s, opts := runTrustedServer(t)
	defer s.Shutdown()

	acc, akp := createAccount(s)
	s.setSystemAccount(acc)

	url := fmt.Sprintf("nats://%s:%d", opts.Host, opts.Port)
	ncs, err := nats.Connect(url, createUserCreds(t, s, akp))
	if err != nil {
		t.Fatalf("Error on connect: %v", err)
	}
	defer ncs.Close()

	// We may not be able to hear ourselves (if the event is processed
	// before we create the sub), so we need to create a second client to
	// trigger the connect/disconnect events.
	acc2, akp2 := createAccount(s)

	// Be explicit to only receive the event for acc2.
	sub, _ := ncs.SubscribeSync(fmt.Sprintf("$SYS.ACCOUNT.%s.>", acc2.Name))
	defer sub.Unsubscribe()
	ncs.Flush()

	nc, err := nats.Connect(url, createUserCreds(t, s, akp2), nats.Name("TEST EVENTS"))
	if err != nil {
		t.Fatalf("Error on connect: %v", err)
	}
	defer nc.Close()

	msg, err := sub.NextMsg(time.Second)
	if err != nil {
		t.Fatalf("Error receiving msg: %v", err)
	}
	connsMsg, err := sub.NextMsg(time.Second)
	if err != nil {
		t.Fatalf("Error receiving msg: %v", err)
	}
	if strings.HasPrefix(msg.Subject, fmt.Sprintf("$SYS.ACCOUNT.%s.SERVER.CONNS", acc2.Name)) {
		msg, connsMsg = connsMsg, msg
	}
	if !strings.HasPrefix(connsMsg.Subject, fmt.Sprintf("$SYS.ACCOUNT.%s.SERVER.CONNS", acc2.Name)) {
		t.Fatalf("Expected subject to start with %q, got %q", "$SYS.ACCOUNT.<account>.CONNECT", msg.Subject)
	}
	conns := AccountNumConns{}
	if err := json.Unmarshal(connsMsg.Data, &conns); err != nil {
		t.Fatalf("Error unmarshalling conns event message: %v", err)
	} else if conns.Account != acc2.Name {
		t.Fatalf("Wrong account in conns message: %v", conns)
	} else if conns.Conns != 1 || conns.TotalConns != 1 {
		t.Fatalf("Wrong counts in conns message: %v", conns)
	}
	if !strings.HasPrefix(msg.Subject, fmt.Sprintf("$SYS.ACCOUNT.%s.CONNECT", acc2.Name)) {
		t.Fatalf("Expected subject to start with %q, got %q", "$SYS.ACCOUNT.<account>.CONNECT", msg.Subject)
	}
	tokens := strings.Split(msg.Subject, ".")
	if len(tokens) < 4 {
		t.Fatalf("Expected 4 tokens, got %d", len(tokens))
	}
	account := tokens[2]
	if account != acc2.Name {
		t.Fatalf("Expected %q for account, got %q", acc2.Name, account)
	}

	cem := ConnectEventMsg{}
	if err := json.Unmarshal(msg.Data, &cem); err != nil {
		t.Fatalf("Error unmarshalling connect event message: %v", err)
	}
	if cem.Type != ConnectEventMsgType {
		t.Fatalf("Incorrect schema in connect event: %s", cem.Type)
	}
	if cem.Time.IsZero() {
		t.Fatalf("Event time is not set")
	}
	if len(cem.ID) != 22 {
		t.Fatalf("Event ID is incorrectly set to len %d", len(cem.ID))
	}
	if cem.Server.ID != s.ID() {
		t.Fatalf("Expected server to be %q, got %q", s.ID(), cem.Server.ID)
	}
	if cem.Server.Seq == 0 {
		t.Fatalf("Expected sequence to be non-zero")
	}
	if cem.Client.Name != "TEST EVENTS" {
		t.Fatalf("Expected client name to be %q, got %q", "TEST EVENTS", cem.Client.Name)
	}
	if cem.Client.Lang != "go" {
		t.Fatalf("Expected client lang to be \"go\", got %q", cem.Client.Lang)
	}

	// Now close the other client. Should fire a disconnect event.
	// First send and receive some messages.
	sub2, _ := nc.SubscribeSync("foo")
	defer sub2.Unsubscribe()
	sub3, _ := nc.SubscribeSync("*")
	defer sub3.Unsubscribe()

	for i := 0; i < 10; i++ {
		nc.Publish("foo", []byte("HELLO WORLD"))
	}
	nc.Flush()
	nc.Close()

	msg, err = sub.NextMsg(time.Second)
	if err != nil {
		t.Fatalf("Error receiving msg: %v", err)
	}
	connsMsg, err = sub.NextMsg(time.Second)
	if err != nil {
		t.Fatalf("Error receiving msg: %v", err)
	}
	if strings.HasPrefix(msg.Subject, fmt.Sprintf("$SYS.ACCOUNT.%s.SERVER.CONNS", acc2.Name)) {
		msg, connsMsg = connsMsg, msg
	}
	if !strings.HasPrefix(connsMsg.Subject, fmt.Sprintf("$SYS.ACCOUNT.%s.SERVER.CONNS", acc2.Name)) {
		t.Fatalf("Expected subject to start with %q, got %q", "$SYS.ACCOUNT.<account>.CONNECT", msg.Subject)
	} else if !strings.Contains(string(connsMsg.Data), `"total_conns":0`) {
		t.Fatalf("Expected event to reflect created connection, got: %s", string(connsMsg.Data))
	}
	conns = AccountNumConns{}
	if err := json.Unmarshal(connsMsg.Data, &conns); err != nil {
		t.Fatalf("Error unmarshalling conns event message: %v", err)
	} else if conns.Account != acc2.Name {
		t.Fatalf("Wrong account in conns message: %v", conns)
	} else if conns.Conns != 0 || conns.TotalConns != 0 {
		t.Fatalf("Wrong counts in conns message: %v", conns)
	}
	if !strings.HasPrefix(msg.Subject, fmt.Sprintf("$SYS.ACCOUNT.%s.DISCONNECT", acc2.Name)) {
		t.Fatalf("Expected subject to start with %q, got %q", "$SYS.ACCOUNT.<account>.DISCONNECT", msg.Subject)
	}
	tokens = strings.Split(msg.Subject, ".")
	if len(tokens) < 4 {
		t.Fatalf("Expected 4 tokens, got %d", len(tokens))
	}
	account = tokens[2]
	if account != acc2.Name {
		t.Fatalf("Expected %q for account, got %q", acc2.Name, account)
	}

	dem := DisconnectEventMsg{}
	if err := json.Unmarshal(msg.Data, &dem); err != nil {
		t.Fatalf("Error unmarshalling disconnect event message: %v", err)
	}
	if dem.Type != DisconnectEventMsgType {
		t.Fatalf("Incorrect schema in connect event: %s", cem.Type)
	}
	if dem.Time.IsZero() {
		t.Fatalf("Event time is not set")
	}
	if len(dem.ID) != 22 {
		t.Fatalf("Event ID is incorrectly set to len %d", len(cem.ID))
	}
	if dem.Server.ID != s.ID() {
		t.Fatalf("Expected server to be %q, got %q", s.ID(), dem.Server.ID)
	}
	if dem.Server.Seq == 0 {
		t.Fatalf("Expected sequence to be non-zero")
	}
	if dem.Server.Seq <= cem.Server.Seq {
		t.Fatalf("Expected sequence to be increasing")
	}

	if cem.Client.Name != "TEST EVENTS" {
		t.Fatalf("Expected client name to be %q, got %q", "TEST EVENTS", dem.Client.Name)
	}
	if dem.Client.Lang != "go" {
		t.Fatalf("Expected client lang to be \"go\", got %q", dem.Client.Lang)
	}

	if dem.Sent.Msgs != 10 {
		t.Fatalf("Expected 10 msgs sent, got %d", dem.Sent.Msgs)
	}
	if dem.Sent.Bytes != 110 {
		t.Fatalf("Expected 110 bytes sent, got %d", dem.Sent.Bytes)
	}
	if dem.Received.Msgs != 20 {
		t.Fatalf("Expected 20 msgs received, got %d", dem.Sent.Msgs)
	}
	if dem.Received.Bytes != 220 {
		t.Fatalf("Expected 220 bytes sent, got %d", dem.Sent.Bytes)
	}
}

func genCredsFile(t *testing.T, jwt string, seed []byte) string {
	creds := `
		-----BEGIN NATS USER JWT-----
		%s
		------END NATS USER JWT------

		************************* IMPORTANT *************************
		NKEY Seed printed below can be used to sign and prove identity.
		NKEYs are sensitive and should be treated as secrets.

		-----BEGIN USER NKEY SEED-----
		%s
		------END USER NKEY SEED------

		*************************************************************
		`
	return createConfFile(t, []byte(strings.Replace(fmt.Sprintf(creds, jwt, seed), "\t\t", "", -1)))
}

func TestSystemAccountDisconnectBadLogin(t *testing.T) {
	s, opts := runTrustedServer(t)
	defer s.Shutdown()

	acc, akp := createAccount(s)
	s.setSystemAccount(acc)

	url := fmt.Sprintf("nats://%s:%d", opts.Host, opts.Port)
	ncs, err := nats.Connect(url, createUserCreds(t, s, akp))
	if err != nil {
		t.Fatalf("Error on connect: %v", err)
	}
	defer ncs.Close()

	// We should never hear $G account events for bad logins.
	sub, _ := ncs.SubscribeSync("$SYS.ACCOUNT.$G.*")
	defer sub.Unsubscribe()

	// Listen for auth error events though.
	asub, _ := ncs.SubscribeSync("$SYS.SERVER.*.CLIENT.AUTH.ERR")
	defer asub.Unsubscribe()

	ncs.Flush()

	nats.Connect(url, nats.Name("TEST BAD LOGIN"))

	// Should not hear these.
	if _, err := sub.NextMsg(100 * time.Millisecond); err == nil {
		t.Fatalf("Received a disconnect message from bad login, expected none")
	}

	m, err := asub.NextMsg(100 * time.Millisecond)
	if err != nil {
		t.Fatalf("Should have heard an auth error event")
	}
	dem := DisconnectEventMsg{}
	if err := json.Unmarshal(m.Data, &dem); err != nil {
		t.Fatalf("Error unmarshalling disconnect event message: %v", err)
	}
	if dem.Reason != "Authentication Failure" {
		t.Fatalf("Expected auth error, got %q", dem.Reason)
	}
}

func TestSysSubscribeRace(t *testing.T) {
	s, opts := runTrustedServer(t)
	defer s.Shutdown()

	acc, akp := createAccount(s)
	s.setSystemAccount(acc)

	url := fmt.Sprintf("nats://%s:%d", opts.Host, opts.Port)

	nc, err := nats.Connect(url, createUserCreds(t, s, akp))
	if err != nil {
		t.Fatalf("Error on connect: %v", err)
	}
	defer nc.Close()

	done := make(chan struct{})
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			nc.Publish("foo", []byte("hello"))
			select {
			case <-done:
				return
			default:
			}
		}
	}()

	time.Sleep(10 * time.Millisecond)

	received := make(chan struct{})
	// Create message callback handler.
	cb := func(sub *subscription, producer *client, _ *Account, subject, reply string, msg []byte) {
		select {
		case received <- struct{}{}:
		default:
		}
	}
	// Now create an internal subscription
	sub, err := s.sysSubscribe("foo", cb)
	if sub == nil || err != nil {
		t.Fatalf("Expected to subscribe, got %v", err)
	}
	select {
	case <-received:
		close(done)
	case <-time.After(time.Second):
		t.Fatalf("Did not receive the message")
	}
	wg.Wait()
}

func TestSystemAccountInternalSubscriptions(t *testing.T) {
	s, opts := runTrustedServer(t)
	defer s.Shutdown()

	sub, err := s.sysSubscribe("foo", nil)
	if sub != nil || err != ErrNoSysAccount {
		t.Fatalf("Expected to get proper error, got %v", err)
	}

	acc, akp := createAccount(s)
	s.setSystemAccount(acc)

	url := fmt.Sprintf("nats://%s:%d", opts.Host, opts.Port)

	nc, err := nats.Connect(url, createUserCreds(t, s, akp))
	if err != nil {
		t.Fatalf("Error on connect: %v", err)
	}
	defer nc.Close()

	sub, err = s.sysSubscribe("foo", nil)
	if sub != nil || err == nil {
		t.Fatalf("Expected to get error for no handler, got %v", err)
	}

	received := make(chan *nats.Msg)
	// Create message callback handler.
	cb := func(sub *subscription, _ *client, _ *Account, subject, reply string, msg []byte) {
		copy := append([]byte(nil), msg...)
		received <- &nats.Msg{Subject: subject, Reply: reply, Data: copy}
	}

	// Now create an internal subscription
	sub, err = s.sysSubscribe("foo", cb)
	if sub == nil || err != nil {
		t.Fatalf("Expected to subscribe, got %v", err)
	}
	// Now send out a message from our normal client.
	nc.Publish("foo", []byte("HELLO WORLD"))

	var msg *nats.Msg

	select {
	case msg = <-received:
		if msg.Subject != "foo" {
			t.Fatalf("Expected \"foo\" as subject, got %q", msg.Subject)
		}
		if msg.Reply != "" {
			t.Fatalf("Expected no reply, got %q", msg.Reply)
		}
		if !bytes.Equal(msg.Data, []byte("HELLO WORLD")) {
			t.Fatalf("Got the wrong msg payload: %q", msg.Data)
		}
		break
	case <-time.After(time.Second):
		t.Fatalf("Did not receive the message")
	}
	s.sysUnsubscribe(sub)

	// Now send out a message from our normal client.
	// We should not see this one.
	nc.Publish("foo", []byte("You There?"))

	select {
	case <-received:
		t.Fatalf("Received a message when we should not have")
	case <-time.After(100 * time.Millisecond):
		break
	}

	// Now make sure we do not hear ourselves. We optimize this for internally
	// generated messages.
	s.mu.Lock()
	s.sendInternalMsg("foo", "", nil, msg.Data)
	s.mu.Unlock()

	select {
	case <-received:
		t.Fatalf("Received a message when we should not have")
	case <-time.After(100 * time.Millisecond):
		break
	}
}

func TestSystemAccountFromConfig(t *testing.T) {
	kp, _ := nkeys.FromSeed(oSeed)
	opub, _ := kp.PublicKey()
	akp, _ := nkeys.CreateAccount()
	apub, _ := akp.PublicKey()
	nac := jwt.NewAccountClaims(apub)
	ajwt, err := nac.Encode(kp)
	if err != nil {
		t.Fatalf("Error generating account JWT: %v", err)
	}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(ajwt))
	}))
	defer ts.Close()

	confTemplate := `
		listen: -1
		trusted: %s
		system_account: %s
		resolver: URL("%s/jwt/v1/accounts/")
    `

	conf := createConfFile(t, []byte(fmt.Sprintf(confTemplate, opub, apub, ts.URL)))

	s, _ := RunServerWithConfig(conf)
	defer s.Shutdown()

	if acc := s.SystemAccount(); acc == nil || acc.Name != apub {
		t.Fatalf("System Account not properly set")
	}
}

func TestAccountClaimsUpdates(t *testing.T) {
	test := func(subj string) {
		s, opts := runTrustedServer(t)
		defer s.Shutdown()

		sacc, sakp := createAccount(s)
		s.setSystemAccount(sacc)

		// Let's create a normal account with limits we can update.
		okp, _ := nkeys.FromSeed(oSeed)
		akp, _ := nkeys.CreateAccount()
		pub, _ := akp.PublicKey()
		nac := jwt.NewAccountClaims(pub)
		nac.Limits.Conn = 4
		ajwt, _ := nac.Encode(okp)

		addAccountToMemResolver(s, pub, ajwt)

		acc, _ := s.LookupAccount(pub)
		if acc.MaxActiveConnections() != 4 {
			t.Fatalf("Expected to see a limit of 4 connections")
		}

		// Simulate a systems publisher so we can do an account claims update.
		url := fmt.Sprintf("nats://%s:%d", opts.Host, opts.Port)
		nc, err := nats.Connect(url, createUserCreds(t, s, sakp))
		if err != nil {
			t.Fatalf("Error on connect: %v", err)
		}
		defer nc.Close()

		// Update the account
		nac = jwt.NewAccountClaims(pub)
		nac.Limits.Conn = 8
		issAt := time.Now().Add(-30 * time.Second).Unix()
		nac.IssuedAt = issAt
		expires := time.Now().Add(2 * time.Second).Unix()
		nac.Expires = expires
		ajwt, _ = nac.Encode(okp)

		// Publish to the system update subject.
		claimUpdateSubj := fmt.Sprintf(subj, pub)
		nc.Publish(claimUpdateSubj, []byte(ajwt))
		nc.Flush()
		time.Sleep(200 * time.Millisecond)

		acc, _ = s.LookupAccount(pub)
		if acc.MaxActiveConnections() != 8 {
			t.Fatalf("Account was not updated")
		}
	}
	t.Run("new", func(t *testing.T) {
		test(accUpdateEventSubjNew)
	})
	t.Run("old", func(t *testing.T) {
		test(accUpdateEventSubjOld)
	})
}

func TestAccountReqMonitoring(t *testing.T) {
	s, opts := runTrustedServer(t)
	defer s.Shutdown()
	sacc, sakp := createAccount(s)
	s.setSystemAccount(sacc)
	s.EnableJetStream(nil)
	unusedAcc, _ := createAccount(s)
	acc, akp := createAccount(s)
	acc.EnableJetStream(nil)
	subsz := fmt.Sprintf(accDirectReqSubj, acc.Name, "SUBSZ")
	connz := fmt.Sprintf(accDirectReqSubj, acc.Name, "CONNZ")
	jsz := fmt.Sprintf(accDirectReqSubj, acc.Name, "JSZ")

	pStatz := fmt.Sprintf(accPingReqSubj, "STATZ")
	statz := func(name string) string { return fmt.Sprintf(accDirectReqSubj, name, "STATZ") }
	// Create system account connection to query
	url := fmt.Sprintf("nats://%s:%d", opts.Host, opts.Port)
	ncSys, err := nats.Connect(url, createUserCreds(t, s, sakp))
	if err != nil {
		t.Fatalf("Error on connect: %v", err)
	}
	defer ncSys.Close()
	// Create a connection that we can query
	nc, err := nats.Connect(url, createUserCreds(t, s, akp))
	if err != nil {
		t.Fatalf("Error on connect: %v", err)
	}
	defer nc.Close()
	// query SUBSZ for account
	resp, err := ncSys.Request(subsz, nil, time.Second)
	require_NoError(t, err)
	require_Contains(t, string(resp.Data), `"num_subscriptions":4,`)
	// create a subscription
	sub, err := nc.Subscribe("foo", func(msg *nats.Msg) {})
	require_NoError(t, err)
	defer sub.Unsubscribe()

	require_NoError(t, nc.Flush())
	// query SUBSZ for account
	resp, err = ncSys.Request(subsz, nil, time.Second)
	require_NoError(t, err)
	require_Contains(t, string(resp.Data), `"num_subscriptions":5,`, `"subject":"foo"`)
	// query connections for account
	resp, err = ncSys.Request(connz, nil, time.Second)
	require_NoError(t, err)
	require_Contains(t, string(resp.Data), `"num_connections":1,`, `"total":1,`)
	// query connections for js account
	resp, err = ncSys.Request(jsz, nil, time.Second)
	require_NoError(t, err)
	require_Contains(t, string(resp.Data), `"memory":0,`, `"storage":0,`)
	// query statz/conns for account
	resp, err = ncSys.Request(statz(acc.Name), nil, time.Second)
	require_NoError(t, err)
	respContentAcc := []string{`"conns":1,`, `"total_conns":1`, `"slow_consumers":0`, `"sent":{"msgs":0,"bytes":0}`,
		`"received":{"msgs":0,"bytes":0}`, fmt.Sprintf(`"acc":"%s"`, acc.Name)}
	require_Contains(t, string(resp.Data), respContentAcc...)

	rIb := ncSys.NewRespInbox()
	rSub, err := ncSys.SubscribeSync(rIb)
	require_NoError(t, err)
	require_NoError(t, ncSys.PublishRequest(pStatz, rIb, nil))
	minRespContentForBothAcc := []string{`"conns":1,`, `"total_conns":1`, `"slow_consumers":0`, `"acc":"`}
	resp, err = rSub.NextMsg(time.Second)
	require_NoError(t, err)
	require_Contains(t, string(resp.Data), minRespContentForBothAcc...)
	// expect one entry per account
	require_Contains(t, string(resp.Data), fmt.Sprintf(`"acc":"%s"`, acc.Name), fmt.Sprintf(`"acc":"%s"`, sacc.Name))

	// Test ping with filter by account name
	require_NoError(t, ncSys.PublishRequest(pStatz, rIb, []byte(fmt.Sprintf(`{"accounts":["%s"]}`, sacc.Name))))
	m, err := rSub.NextMsg(time.Second)
	require_NoError(t, err)
	require_Contains(t, string(m.Data), minRespContentForBothAcc...)

	require_NoError(t, ncSys.PublishRequest(pStatz, rIb, []byte(fmt.Sprintf(`{"accounts":["%s"]}`, acc.Name))))
	m, err = rSub.NextMsg(time.Second)
	require_NoError(t, err)
	require_Contains(t, string(m.Data), respContentAcc...)

	// Test include unused for statz and ping of statz
	unusedContent := []string{`"conns":0,`, `"total_conns":0`, `"slow_consumers":0`,
		fmt.Sprintf(`"acc":"%s"`, unusedAcc.Name)}

	resp, err = ncSys.Request(statz(unusedAcc.Name),
		[]byte(fmt.Sprintf(`{"accounts":["%s"], "include_unused":true}`, unusedAcc.Name)),
		time.Second)
	require_NoError(t, err)
	require_Contains(t, string(resp.Data), unusedContent...)

	require_NoError(t, ncSys.PublishRequest(pStatz, rIb,
		[]byte(fmt.Sprintf(`{"accounts":["%s"], "include_unused":true}`, unusedAcc.Name))))
	resp, err = rSub.NextMsg(time.Second)
	require_NoError(t, err)
	require_Contains(t, string(resp.Data), unusedContent...)

	require_NoError(t, ncSys.PublishRequest(pStatz, rIb, []byte(fmt.Sprintf(`{"accounts":["%s"]}`, unusedAcc.Name))))
	_, err = rSub.NextMsg(200 * time.Millisecond)
	require_Error(t, err)

	// Test ping from within account
	ib := nc.NewRespInbox()
	rSub, err = nc.SubscribeSync(ib)
	require_NoError(t, err)
	require_NoError(t, nc.PublishRequest(pStatz, ib, nil))
	resp, err = rSub.NextMsg(time.Second)
	require_NoError(t, err)
	// Since we now have processed our own message, msgs will be 1.
	respContentAcc = []string{`"conns":1,`, `"total_conns":1`, `"slow_consumers":0`, `"sent":{"msgs":0,"bytes":0}`,
		`"received":{"msgs":1,"bytes":0}`, fmt.Sprintf(`"acc":"%s"`, acc.Name)}
	require_Contains(t, string(resp.Data), respContentAcc...)
	_, err = rSub.NextMsg(200 * time.Millisecond)
	require_Error(t, err)
}

func TestAccountReqInfo(t *testing.T) {
	s, opts := runTrustedServer(t)
	defer s.Shutdown()
	sacc, sakp := createAccount(s)
	s.setSystemAccount(sacc)
	// Let's create an account with service export.
	akp, _ := nkeys.CreateAccount()
	pub1, _ := akp.PublicKey()
	nac1 := jwt.NewAccountClaims(pub1)
	nac1.Exports.Add(&jwt.Export{Subject: "req.*", Type: jwt.Service})
	ajwt1, _ := nac1.Encode(oKp)
	addAccountToMemResolver(s, pub1, ajwt1)
	s.LookupAccount(pub1)
	info1 := fmt.Sprintf(accDirectReqSubj, pub1, "INFO")
	// Now add an account with service imports.
	akp2, _ := nkeys.CreateAccount()
	pub2, _ := akp2.PublicKey()
	nac2 := jwt.NewAccountClaims(pub2)
	nac2.Imports.Add(&jwt.Import{Account: pub1, Subject: "req.1", Type: jwt.Service})
	ajwt2, _ := nac2.Encode(oKp)
	addAccountToMemResolver(s, pub2, ajwt2)
	s.LookupAccount(pub2)
	info2 := fmt.Sprintf(accDirectReqSubj, pub2, "INFO")
	// Create system account connection to query
	url := fmt.Sprintf("nats://%s:%d", opts.Host, opts.Port)
	ncSys, err := nats.Connect(url, createUserCreds(t, s, sakp))
	if err != nil {
		t.Fatalf("Error on connect: %v", err)
	}
	defer ncSys.Close()
	checkCommon := func(info *AccountInfo, srv *ServerInfo, pub, jwt string) {
		if info.Complete != true {
			t.Fatalf("Unexpected value: %v", info.Complete)
		} else if info.Expired != false {
			t.Fatalf("Unexpected value: %v", info.Expired)
		} else if info.JetStream != false {
			t.Fatalf("Unexpected value: %v", info.JetStream)
		} else if info.ClientCnt != 0 {
			t.Fatalf("Unexpected value: %v", info.ClientCnt)
		} else if info.AccountName != pub {
			t.Fatalf("Unexpected value: %v", info.AccountName)
		} else if info.Jwt != jwt {
			t.Fatalf("Unexpected value: %v", info.Jwt)
		} else if srv.Name != s.Name() {
			t.Fatalf("Unexpected value: %v", srv.Name)
		} else if srv.Host != opts.Host {
			t.Fatalf("Unexpected value: %v", srv.Host)
		} else if srv.Seq < 1 {
			t.Fatalf("Unexpected value: %v", srv.Seq)
		}
	}
	info := AccountInfo{}
	srv := ServerInfo{}
	msg := struct {
		Data *AccountInfo `json:"data"`
		Srv  *ServerInfo  `json:"server"`
	}{
		&info,
		&srv,
	}
	if resp, err := ncSys.Request(info1, nil, time.Second); err != nil {
		t.Fatalf("Error on request: %v", err)
	} else if err := json.Unmarshal(resp.Data, &msg); err != nil {
		t.Fatalf("Unmarshalling failed: %v", err)
	} else if len(info.Exports) != 1 {
		t.Fatalf("Unexpected value: %v", info.Exports)
	} else if len(info.Imports) != 3 {
		t.Fatalf("Unexpected value: %+v", info.Imports)
	} else if info.Exports[0].Subject != "req.*" {
		t.Fatalf("Unexpected value: %v", info.Exports)
	} else if info.Exports[0].Type != jwt.Service {
		t.Fatalf("Unexpected value: %v", info.Exports)
	} else if info.Exports[0].ResponseType != jwt.ResponseTypeSingleton {
		t.Fatalf("Unexpected value: %v", info.Exports)
	} else if info.SubCnt != 3 {
		t.Fatalf("Unexpected value: %v", info.SubCnt)
	} else {
		checkCommon(&info, &srv, pub1, ajwt1)
	}
	info = AccountInfo{}
	srv = ServerInfo{}
	if resp, err := ncSys.Request(info2, nil, time.Second); err != nil {
		t.Fatalf("Error on request: %v", err)
	} else if err := json.Unmarshal(resp.Data, &msg); err != nil {
		t.Fatalf("Unmarshalling failed: %v", err)
	} else if len(info.Exports) != 0 {
		t.Fatalf("Unexpected value: %v", info.Exports)
	} else if len(info.Imports) != 4 {
		t.Fatalf("Unexpected value: %+v", info.Imports)
	}
	// Here we need to find our import
	var si *ExtImport
	for _, im := range info.Imports {
		if im.Subject == "req.1" {
			si = &im
			break
		}
	}
	if si == nil {
		t.Fatalf("Could not find our import")
	}
	if si.Type != jwt.Service {
		t.Fatalf("Unexpected value: %+v", si)
	} else if si.Account != pub1 {
		t.Fatalf("Unexpected value: %+v", si)
	} else if info.SubCnt != 4 {
		t.Fatalf("Unexpected value: %+v", si)
	} else {
		checkCommon(&info, &srv, pub2, ajwt2)
	}
}

func TestAccountClaimsUpdatesWithServiceImports(t *testing.T) {
	s, opts := runTrustedServer(t)
	defer s.Shutdown()

	sacc, sakp := createAccount(s)
	s.setSystemAccount(sacc)

	okp, _ := nkeys.FromSeed(oSeed)

	// Let's create an account with service export.
	akp, _ := nkeys.CreateAccount()
	pub, _ := akp.PublicKey()
	nac := jwt.NewAccountClaims(pub)
	nac.Exports.Add(&jwt.Export{Subject: "req.*", Type: jwt.Service})
	ajwt, _ := nac.Encode(okp)
	addAccountToMemResolver(s, pub, ajwt)
	s.LookupAccount(pub)

	// Now add an account with multiple service imports.
	akp2, _ := nkeys.CreateAccount()
	pub2, _ := akp2.PublicKey()
	nac2 := jwt.NewAccountClaims(pub2)
	nac2.Imports.Add(&jwt.Import{Account: pub, Subject: "req.1", Type: jwt.Service})
	ajwt2, _ := nac2.Encode(okp)

	addAccountToMemResolver(s, pub2, ajwt2)
	s.LookupAccount(pub2)

	startSubs := s.NumSubscriptions()

	// Simulate a systems publisher so we can do an account claims update.
	url := fmt.Sprintf("nats://%s:%d", opts.Host, opts.Port)
	nc, err := nats.Connect(url, createUserCreds(t, s, sakp))
	if err != nil {
		t.Fatalf("Error on connect: %v", err)
	}
	defer nc.Close()

	// Update the account several times
	for i := 1; i <= 10; i++ {
		nac2 = jwt.NewAccountClaims(pub2)
		nac2.Limits.Conn = int64(i)
		nac2.Imports.Add(&jwt.Import{Account: pub, Subject: "req.1", Type: jwt.Service})
		ajwt2, _ = nac2.Encode(okp)

		// Publish to the system update subject.
		claimUpdateSubj := fmt.Sprintf(accUpdateEventSubjNew, pub2)
		nc.Publish(claimUpdateSubj, []byte(ajwt2))
	}
	nc.Flush()
	time.Sleep(50 * time.Millisecond)

	if startSubs < s.NumSubscriptions() {
		t.Fatalf("Subscriptions leaked: %d vs %d", startSubs, s.NumSubscriptions())
	}
}

func TestAccountConnsLimitExceededAfterUpdate(t *testing.T) {
	s, opts := runTrustedServer(t)
	defer s.Shutdown()

	sacc, _ := createAccount(s)
	s.setSystemAccount(sacc)

	// Let's create a normal  account with limits we can update.
	okp, _ := nkeys.FromSeed(oSeed)
	akp, _ := nkeys.CreateAccount()
	pub, _ := akp.PublicKey()
	nac := jwt.NewAccountClaims(pub)
	nac.Limits.Conn = 10
	ajwt, _ := nac.Encode(okp)

	addAccountToMemResolver(s, pub, ajwt)
	acc, _ := s.LookupAccount(pub)

	// Now create the max connections.
	url := fmt.Sprintf("nats://%s:%d", opts.Host, opts.Port)
	for {
		nc, err := nats.Connect(url, createUserCreds(t, s, akp))
		if err != nil {
			break
		}
		defer nc.Close()
	}

	// We should have max here.
	checkFor(t, 2*time.Second, 50*time.Millisecond, func() error {
		if total := s.NumClients(); total != acc.MaxActiveConnections() {
			return fmt.Errorf("Expected %d connections, got %d", acc.MaxActiveConnections(), total)
		}
		return nil
	})

	// Now change limits to make current connections over the limit.
	nac = jwt.NewAccountClaims(pub)
	nac.Limits.Conn = 2
	ajwt, _ = nac.Encode(okp)

	s.updateAccountWithClaimJWT(acc, ajwt)
	if acc.MaxActiveConnections() != 2 {
		t.Fatalf("Expected max connections to be set to 2, got %d", acc.MaxActiveConnections())
	}
	// We should have closed the excess connections.
	checkClientsCount(t, s, acc.MaxActiveConnections())
}

func TestAccountConnsLimitExceededAfterUpdateDisconnectNewOnly(t *testing.T) {
	s, opts := runTrustedServer(t)
	defer s.Shutdown()

	sacc, _ := createAccount(s)
	s.setSystemAccount(sacc)

	// Let's create a normal  account with limits we can update.
	okp, _ := nkeys.FromSeed(oSeed)
	akp, _ := nkeys.CreateAccount()
	pub, _ := akp.PublicKey()
	nac := jwt.NewAccountClaims(pub)
	nac.Limits.Conn = 10
	ajwt, _ := nac.Encode(okp)

	addAccountToMemResolver(s, pub, ajwt)
	acc, _ := s.LookupAccount(pub)

	// Now create the max connections.
	// We create half then we will wait and then create the rest.
	// Will test that we disconnect the newest ones.
	newConns := make([]*nats.Conn, 0, 5)
	url := fmt.Sprintf("nats://%s:%d", opts.Host, opts.Port)
	for i := 0; i < 5; i++ {
		nc, err := nats.Connect(url, nats.NoReconnect(), createUserCreds(t, s, akp))
		require_NoError(t, err)
		defer nc.Close()
	}
	time.Sleep(500 * time.Millisecond)
	for i := 0; i < 5; i++ {
		nc, err := nats.Connect(url, nats.NoReconnect(), createUserCreds(t, s, akp))
		require_NoError(t, err)
		defer nc.Close()
		newConns = append(newConns, nc)
	}

	// We should have max here.
	checkClientsCount(t, s, acc.MaxActiveConnections())

	// Now change limits to make current connections over the limit.
	nac = jwt.NewAccountClaims(pub)
	nac.Limits.Conn = 5
	ajwt, _ = nac.Encode(okp)

	s.updateAccountWithClaimJWT(acc, ajwt)
	if acc.MaxActiveConnections() != 5 {
		t.Fatalf("Expected max connections to be set to 2, got %d", acc.MaxActiveConnections())
	}
	// We should have closed the excess connections.
	checkClientsCount(t, s, acc.MaxActiveConnections())

	// Now make sure that only the new ones were closed.
	var closed int
	for _, nc := range newConns {
		if !nc.IsClosed() {
			closed++
		}
	}
	if closed != 5 {
		t.Fatalf("Expected all new clients to be closed, only got %d of 5", closed)
	}
}

func TestSystemAccountWithBadRemoteLatencyUpdate(t *testing.T) {
	s, _ := runTrustedServer(t)
	defer s.Shutdown()

	acc, _ := createAccount(s)
	s.setSystemAccount(acc)

	rl := remoteLatency{
		Account: "NONSENSE",
		ReqId:   "_INBOX.22",
	}
	b, _ := json.Marshal(&rl)
	s.remoteLatencyUpdate(nil, nil, nil, "foo", _EMPTY_, nil, b)
}

func TestSystemAccountNoAuthUser(t *testing.T) {
	conf := createConfFile(t, []byte(`
		listen: "127.0.0.1:-1"
		accounts {
			$SYS {
				users [{user: "admin", password: "pwd"}]
			}
		}
	`))
	defer os.Remove(conf)
	s, o := RunServerWithConfig(conf)
	defer s.Shutdown()

	for _, test := range []struct {
		name    string
		usrInfo string
		ok      bool
		account string
	}{
		{"valid user/pwd", "admin:pwd@", true, "$SYS"},
		{"invalid pwd", "admin:wrong@", false, _EMPTY_},
		{"some token", "sometoken@", false, _EMPTY_},
		{"user used without pwd", "admin@", false, _EMPTY_}, // will be treated as a token
		{"user with empty password", "admin:@", false, _EMPTY_},
		{"no user means global account", _EMPTY_, true, globalAccountName},
	} {
		t.Run(test.name, func(t *testing.T) {
			url := fmt.Sprintf("nats://%s127.0.0.1:%d", test.usrInfo, o.Port)
			nc, err := nats.Connect(url)
			if err != nil {
				if test.ok {
					t.Fatalf("Unexpected error: %v", err)
				}
				return
			} else if !test.ok {
				nc.Close()
				t.Fatalf("Should have failed, did not")
			}
			var accName string
			s.mu.Lock()
			for _, c := range s.clients {
				c.mu.Lock()
				if c.acc != nil {
					accName = c.acc.Name
				}
				c.mu.Unlock()
				break
			}
			s.mu.Unlock()
			nc.Close()
			checkClientsCount(t, s, 0)
			if accName != test.account {
				t.Fatalf("The account should have been %q, got %q", test.account, accName)
			}
		})
	}
}

func TestServerAccountConns(t *testing.T) {
	// speed up hb
	orgHBInterval := eventsHBInterval
	eventsHBInterval = time.Millisecond * 100
	defer func() { eventsHBInterval = orgHBInterval }()
	conf := createConfFile(t, []byte(`
	   host: 127.0.0.1
	   port: -1
	   system_account: SYS
	   accounts: {
			   SYS: {users: [{user: s, password: s}]}
			   ACC: {users: [{user: a, password: a}]}
	   }`))
	s, _ := RunServerWithConfig(conf)
	defer s.Shutdown()

	nc := natsConnect(t, s.ClientURL(), nats.UserInfo("a", "a"))
	defer nc.Close()

	subOut, err := nc.SubscribeSync("foo")
	require_NoError(t, err)
	hw := "HELLO WORLD"
	nc.Publish("foo", []byte(hw))
	nc.Publish("bar", []byte(hw)) // will only count towards received
	nc.Flush()
	m, err := subOut.NextMsg(time.Second)
	require_NoError(t, err)
	require_Equal(t, string(m.Data), hw)

	ncs := natsConnect(t, s.ClientURL(), nats.UserInfo("s", "s"))
	defer ncs.Close()
	subs, err := ncs.SubscribeSync("$SYS.ACCOUNT.ACC.SERVER.CONNS")
	require_NoError(t, err)

	m, err = subs.NextMsg(time.Second)
	require_NoError(t, err)
	accConns := &AccountNumConns{}
	err = json.Unmarshal(m.Data, accConns)
	require_NoError(t, err)

	require_True(t, accConns.Received.Msgs == 2)
	require_True(t, accConns.Received.Bytes == 2*int64(len(hw)))
	require_True(t, accConns.Sent.Msgs == 1)
	require_True(t, accConns.Sent.Bytes == int64(len(hw)))
}

func TestServerEventsReceivedByQSubs(t *testing.T) {
	s, opts := runTrustedServer(t)
	defer s.Shutdown()

	acc, akp := createAccount(s)
	s.setSystemAccount(acc)

	url := fmt.Sprintf("nats://%s:%d", opts.Host, opts.Port)
	ncs, err := nats.Connect(url, createUserCreds(t, s, akp))
	if err != nil {
		t.Fatalf("Error on connect: %v", err)
	}
	defer ncs.Close()

	// Listen for auth error events.
	qsub, _ := ncs.QueueSubscribeSync("$SYS.SERVER.*.CLIENT.AUTH.ERR", "queue")
	defer qsub.Unsubscribe()

	ncs.Flush()

	nats.Connect(url, nats.Name("TEST BAD LOGIN"))

	m, err := qsub.NextMsg(time.Second)
	if err != nil {
		t.Fatalf("Should have heard an auth error event")
	}
	dem := DisconnectEventMsg{}
	if err := json.Unmarshal(m.Data, &dem); err != nil {
		t.Fatalf("Error unmarshalling disconnect event message: %v", err)
	}
	if dem.Reason != "Authentication Failure" {
		t.Fatalf("Expected auth error, got %q", dem.Reason)
	}
}

func TestServerEventsStatszSingleServer(t *testing.T) {
	conf := createConfFile(t, []byte(`
		listen: "127.0.0.1:-1"
		accounts { $SYS { users [{user: "admin", password: "p1d"}]} }
	`))
	s, _ := RunServerWithConfig(conf)
	defer s.Shutdown()

	// Grab internal system client.
	s.mu.RLock()
	sysc := s.sys.client
	wait := s.sys.cstatsz + 25*time.Millisecond
	s.mu.RUnlock()

	// Wait for when first statsz would have gone out..
	time.Sleep(wait)

	sysc.mu.Lock()
	outMsgs := sysc.stats.outMsgs
	sysc.mu.Unlock()

	require_True(t, outMsgs == 0)

	// Connect as a system user and make sure if there is
	// subscription interest that we will receive updates.
	nc, _ := jsClientConnect(t, s, nats.UserInfo("admin", "p1d"))
	defer nc.Close()

	sub, err := nc.SubscribeSync(fmt.Sprintf(serverStatsSubj, "*"))
	require_NoError(t, err)

	checkSubsPending(t, sub, 1)
}

func Benchmark_GetHash(b *testing.B) {
	b.StopTimer()
	// Get 100 random names
	names := make([]string, 0, 100)
	for i := 0; i < 100; i++ {
		names = append(names, nuid.Next())
	}
	hashes := make([]string, 0, 100)
	for j := 0; j < 100; j++ {
		sha := sha256.New()
		sha.Write([]byte(names[j]))
		b := sha.Sum(nil)
		for i := 0; i < 8; i++ {
			b[i] = digits[int(b[i]%base)]
		}
		hashes = append(hashes, string(b[:8]))
	}
	wg := sync.WaitGroup{}
	wg.Add(8)
	errCh := make(chan error, 8)
	b.StartTimer()
	for i := 0; i < 8; i++ {
		go func() {
			defer wg.Done()
			for i := 0; i < b.N; i++ {
				idx := rand.Intn(100)
				if h := getHash(names[idx]); h != hashes[idx] {
					errCh <- fmt.Errorf("Hash for name %q was %q, but should be %q", names[idx], h, hashes[idx])
					return
				}
			}
		}()
	}
	wg.Wait()
	select {
	case err := <-errCh:
		b.Fatal(err.Error())
	default:
	}
}
