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

//go:build !race && !skip_no_race_tests
// +build !race,!skip_no_race_tests

package server

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"crypto/hmac"
	crand "crypto/rand"
	"crypto/sha256"

	"github.com/klauspost/compress/s2"
	"github.com/nats-io/nats.go"
)

// IMPORTANT: Tests in this file are not executed when running with the -race flag.
//            The test name should be prefixed with TestNoRace so we can run only
//            those tests: go test -run=TestNoRace ...

func TestNoRaceAvoidSlowConsumerBigMessages(t *testing.T) {
	opts := DefaultOptions() // Use defaults to make sure they avoid pending slow consumer.
	opts.NoSystemAccount = true
	s := RunServer(opts)
	defer s.Shutdown()

	nc1, err := nats.Connect(fmt.Sprintf("nats://%s:%d", opts.Host, opts.Port))
	if err != nil {
		t.Fatalf("Error on connect: %v", err)
	}
	defer nc1.Close()

	nc2, err := nats.Connect(fmt.Sprintf("nats://%s:%d", opts.Host, opts.Port))
	if err != nil {
		t.Fatalf("Error on connect: %v", err)
	}
	defer nc2.Close()

	data := make([]byte, 1024*1024) // 1MB payload
	rand.Read(data)

	expected := int32(500)
	received := int32(0)

	done := make(chan bool)

	// Create Subscription.
	nc1.Subscribe("slow.consumer", func(m *nats.Msg) {
		// Just eat it so that we are not measuring
		// code time, just delivery.
		atomic.AddInt32(&received, 1)
		if received >= expected {
			done <- true
		}
	})

	// Create Error handler
	nc1.SetErrorHandler(func(c *nats.Conn, s *nats.Subscription, err error) {
		t.Fatalf("Received an error on the subscription's connection: %v\n", err)
	})

	nc1.Flush()

	for i := 0; i < int(expected); i++ {
		nc2.Publish("slow.consumer", data)
	}
	nc2.Flush()

	select {
	case <-done:
		return
	case <-time.After(10 * time.Second):
		r := atomic.LoadInt32(&received)
		if s.NumSlowConsumers() > 0 {
			t.Fatalf("Did not receive all large messages due to slow consumer status: %d of %d", r, expected)
		}
		t.Fatalf("Failed to receive all large messages: %d of %d\n", r, expected)
	}
}

func TestNoRaceClosedSlowConsumerWriteDeadline(t *testing.T) {
	opts := DefaultOptions()
	opts.NoSystemAccount = true
	opts.WriteDeadline = 10 * time.Millisecond // Make very small to trip.
	opts.MaxPending = 500 * 1024 * 1024        // Set high so it will not trip here.
	s := RunServer(opts)
	defer s.Shutdown()

	c, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", opts.Host, opts.Port), 3*time.Second)
	if err != nil {
		t.Fatalf("Error on connect: %v", err)
	}
	defer c.Close()
	if _, err := c.Write([]byte("CONNECT {}\r\nPING\r\nSUB foo 1\r\n")); err != nil {
		t.Fatalf("Error sending protocols to server: %v", err)
	}
	// Reduce socket buffer to increase reliability of data backing up in the server destined
	// for our subscribed client.
	c.(*net.TCPConn).SetReadBuffer(128)

	url := fmt.Sprintf("nats://%s:%d", opts.Host, opts.Port)
	sender, err := nats.Connect(url)
	if err != nil {
		t.Fatalf("Error on connect: %v", err)
	}
	defer sender.Close()

	payload := make([]byte, 1024*1024)
	for i := 0; i < 100; i++ {
		if err := sender.Publish("foo", payload); err != nil {
			t.Fatalf("Error on publish: %v", err)
		}
	}

	// Flush sender connection to ensure that all data has been sent.
	if err := sender.Flush(); err != nil {
		t.Fatalf("Error on flush: %v", err)
	}

	// At this point server should have closed connection c.
	checkClosedConns(t, s, 1, 2*time.Second)
	conns := s.closedClients()
	if lc := len(conns); lc != 1 {
		t.Fatalf("len(conns) expected to be %d, got %d\n", 1, lc)
	}
	checkReason(t, conns[0].Reason, SlowConsumerWriteDeadline)
}

func TestNoRaceClosedSlowConsumerPendingBytes(t *testing.T) {
	opts := DefaultOptions()
	opts.NoSystemAccount = true
	opts.WriteDeadline = 30 * time.Second // Wait for long time so write deadline does not trigger slow consumer.
	opts.MaxPending = 1 * 1024 * 1024     // Set to low value (1MB) to allow SC to trip.
	s := RunServer(opts)
	defer s.Shutdown()

	c, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", opts.Host, opts.Port), 3*time.Second)
	if err != nil {
		t.Fatalf("Error on connect: %v", err)
	}
	defer c.Close()
	if _, err := c.Write([]byte("CONNECT {}\r\nPING\r\nSUB foo 1\r\n")); err != nil {
		t.Fatalf("Error sending protocols to server: %v", err)
	}
	// Reduce socket buffer to increase reliability of data backing up in the server destined
	// for our subscribed client.
	c.(*net.TCPConn).SetReadBuffer(128)

	url := fmt.Sprintf("nats://%s:%d", opts.Host, opts.Port)
	sender, err := nats.Connect(url)
	if err != nil {
		t.Fatalf("Error on connect: %v", err)
	}
	defer sender.Close()

	payload := make([]byte, 1024*1024)
	for i := 0; i < 100; i++ {
		if err := sender.Publish("foo", payload); err != nil {
			t.Fatalf("Error on publish: %v", err)
		}
	}

	// Flush sender connection to ensure that all data has been sent.
	if err := sender.Flush(); err != nil {
		t.Fatalf("Error on flush: %v", err)
	}

	// At this point server should have closed connection c.
	checkClosedConns(t, s, 1, 2*time.Second)
	conns := s.closedClients()
	if lc := len(conns); lc != 1 {
		t.Fatalf("len(conns) expected to be %d, got %d\n", 1, lc)
	}
	checkReason(t, conns[0].Reason, SlowConsumerPendingBytes)
}

func TestNoRaceSlowConsumerPendingBytes(t *testing.T) {
	opts := DefaultOptions()
	opts.NoSystemAccount = true
	opts.WriteDeadline = 30 * time.Second // Wait for long time so write deadline does not trigger slow consumer.
	opts.MaxPending = 1 * 1024 * 1024     // Set to low value (1MB) to allow SC to trip.
	s := RunServer(opts)
	defer s.Shutdown()

	c, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", opts.Host, opts.Port), 3*time.Second)
	if err != nil {
		t.Fatalf("Error on connect: %v", err)
	}
	defer c.Close()
	if _, err := c.Write([]byte("CONNECT {}\r\nPING\r\nSUB foo 1\r\n")); err != nil {
		t.Fatalf("Error sending protocols to server: %v", err)
	}
	// Reduce socket buffer to increase reliability of data backing up in the server destined
	// for our subscribed client.
	c.(*net.TCPConn).SetReadBuffer(128)

	url := fmt.Sprintf("nats://%s:%d", opts.Host, opts.Port)
	sender, err := nats.Connect(url)
	if err != nil {
		t.Fatalf("Error on connect: %v", err)
	}
	defer sender.Close()

	payload := make([]byte, 1024*1024)
	for i := 0; i < 100; i++ {
		if err := sender.Publish("foo", payload); err != nil {
			t.Fatalf("Error on publish: %v", err)
		}
	}

	// Flush sender connection to ensure that all data has been sent.
	if err := sender.Flush(); err != nil {
		t.Fatalf("Error on flush: %v", err)
	}

	// At this point server should have closed connection c.

	// On certain platforms, it may take more than one call before
	// getting the error.
	for i := 0; i < 100; i++ {
		if _, err := c.Write([]byte("PUB bar 5\r\nhello\r\n")); err != nil {
			// ok
			return
		}
	}
	t.Fatal("Connection should have been closed")
}

func TestNoRaceWriteDeadline(t *testing.T) {
	opts := DefaultOptions()
	opts.NoSystemAccount = true
	opts.WriteDeadline = 30 * time.Millisecond
	s := RunServer(opts)
	defer s.Shutdown()

	c, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", opts.Host, opts.Port), 3*time.Second)
	if err != nil {
		t.Fatalf("Error on connect: %v", err)
	}
	defer c.Close()
	if _, err := c.Write([]byte("CONNECT {}\r\nPING\r\nSUB foo 1\r\n")); err != nil {
		t.Fatalf("Error sending protocols to server: %v", err)
	}
	// Reduce socket buffer to increase reliability of getting
	// write deadline errors.
	c.(*net.TCPConn).SetReadBuffer(4)

	url := fmt.Sprintf("nats://%s:%d", opts.Host, opts.Port)
	sender, err := nats.Connect(url)
	if err != nil {
		t.Fatalf("Error on connect: %v", err)
	}
	defer sender.Close()

	payload := make([]byte, 1000000)
	total := 1000
	for i := 0; i < total; i++ {
		if err := sender.Publish("foo", payload); err != nil {
			t.Fatalf("Error on publish: %v", err)
		}
	}
	// Flush sender connection to ensure that all data has been sent.
	if err := sender.Flush(); err != nil {
		t.Fatalf("Error on flush: %v", err)
	}

	// At this point server should have closed connection c.

	// On certain platforms, it may take more than one call before
	// getting the error.
	for i := 0; i < 100; i++ {
		if _, err := c.Write([]byte("PUB bar 5\r\nhello\r\n")); err != nil {
			// ok
			return
		}
	}
	t.Fatal("Connection should have been closed")
}

// This test is same than TestAccountAddServiceImportRace but running
// without the -race flag, it would capture more easily the possible
// duplicate sid, resulting in less than expected number of subscriptions
// in the account's internal subscriptions map.
func TestNoRaceAccountAddServiceImportRace(t *testing.T) {
	TestAccountAddServiceImportRace(t)
}

// Similar to the routed version. Make sure we receive all of the
// messages with auto-unsubscribe enabled.
func TestNoRaceQueueAutoUnsubscribe(t *testing.T) {
	opts := DefaultOptions()
	s := RunServer(opts)
	defer s.Shutdown()

	nc, err := nats.Connect(fmt.Sprintf("nats://%s:%d", opts.Host, opts.Port))
	if err != nil {
		t.Fatalf("Error on connect: %v", err)
	}
	defer nc.Close()

	rbar := int32(0)
	barCb := func(m *nats.Msg) {
		atomic.AddInt32(&rbar, 1)
	}
	rbaz := int32(0)
	bazCb := func(m *nats.Msg) {
		atomic.AddInt32(&rbaz, 1)
	}

	// Create 1000 subscriptions with auto-unsubscribe of 1.
	// Do two groups, one bar and one baz.
	total := 1000
	for i := 0; i < total; i++ {
		qsub, err := nc.QueueSubscribe("foo", "bar", barCb)
		if err != nil {
			t.Fatalf("Error on subscribe: %v", err)
		}
		if err := qsub.AutoUnsubscribe(1); err != nil {
			t.Fatalf("Error on auto-unsubscribe: %v", err)
		}
		qsub, err = nc.QueueSubscribe("foo", "baz", bazCb)
		if err != nil {
			t.Fatalf("Error on subscribe: %v", err)
		}
		if err := qsub.AutoUnsubscribe(1); err != nil {
			t.Fatalf("Error on auto-unsubscribe: %v", err)
		}
	}
	nc.Flush()

	expected := int32(total)
	for i := int32(0); i < expected; i++ {
		nc.Publish("foo", []byte("Don't Drop Me!"))
	}
	nc.Flush()

	checkFor(t, 5*time.Second, 10*time.Millisecond, func() error {
		nbar := atomic.LoadInt32(&rbar)
		nbaz := atomic.LoadInt32(&rbaz)
		if nbar == expected && nbaz == expected {
			return nil
		}
		return fmt.Errorf("Did not receive all %d queue messages, received %d for 'bar' and %d for 'baz'",
			expected, atomic.LoadInt32(&rbar), atomic.LoadInt32(&rbaz))
	})
}

func TestNoRaceAcceptLoopsDoNotLeaveOpenedConn(t *testing.T) {
	for _, test := range []struct {
		name string
		url  func(o *Options) (string, int)
	}{
		{"client", func(o *Options) (string, int) { return o.Host, o.Port }},
	} {
		t.Run(test.name, func(t *testing.T) {
			o := DefaultOptions()
			o.DisableShortFirstPing = true
			o.Accounts = []*Account{NewAccount("$SYS")}
			o.SystemAccount = "$SYS"
			s := RunServer(o)
			defer s.Shutdown()

			host, port := test.url(o)
			url := fmt.Sprintf("%s:%d", host, port)
			var conns []net.Conn

			wg := sync.WaitGroup{}
			wg.Add(1)
			done := make(chan struct{}, 1)
			go func() {
				defer wg.Done()
				// Have an upper limit
				for i := 0; i < 200; i++ {
					c, err := net.Dial("tcp", url)
					if err != nil {
						return
					}
					conns = append(conns, c)
					select {
					case <-done:
						return
					default:
					}
				}
			}()
			time.Sleep(15 * time.Millisecond)
			s.Shutdown()
			close(done)
			wg.Wait()
			for _, c := range conns {
				c.SetReadDeadline(time.Now().Add(2 * time.Second))
				br := bufio.NewReader(c)
				// Read INFO for connections that were accepted
				_, _, err := br.ReadLine()
				if err == nil {
					// After that, the connection should be closed,
					// so we should get an error here.
					_, _, err = br.ReadLine()
				}
				// We expect an io.EOF or any other error indicating the use of a closed
				// connection, but we should not get the timeout error.
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					err = nil
				}
				if err == nil {
					var buf [10]byte
					c.SetDeadline(time.Now().Add(2 * time.Second))
					c.Write([]byte("C"))
					_, err = c.Read(buf[:])
					if ne, ok := err.(net.Error); ok && ne.Timeout() {
						err = nil
					}
				}
				if err == nil {
					t.Fatalf("Connection should have been closed")
				}
				c.Close()
			}
		})
	}
}

func TestNoRaceJetStreamDeleteStreamManyConsumers(t *testing.T) {
	s := RunBasicJetStreamServer(t)
	defer s.Shutdown()

	mname := "MYS"
	mset, err := s.GlobalAccount().addStream(&StreamConfig{Name: mname, Storage: FileStorage})
	if err != nil {
		t.Fatalf("Unexpected error adding stream: %v", err)
	}

	// This number needs to be higher than the internal sendq size to trigger what this test is testing.
	for i := 0; i < 2000; i++ {
		_, err := mset.addConsumer(&ConsumerConfig{
			Durable:        fmt.Sprintf("D-%d", i),
			DeliverSubject: fmt.Sprintf("deliver.%d", i),
		})
		if err != nil {
			t.Fatalf("Error creating consumer: %v", err)
		}
	}
	// With bug this would not return and would hang.
	mset.delete()
}

// We used to swap accounts on an inbound message when processing service imports.
// Until JetStream this was kinda ok, but with JetStream we can have pull consumers
// trying to access the clients account in another Go routine now which causes issues.
// This is not limited to the case above, its just the one that exposed it.
// This test is to show that issue and that the fix works, meaning we no longer swap c.acc.
func TestNoRaceJetStreamServiceImportAccountSwapIssue(t *testing.T) {
	s := RunBasicJetStreamServer(t)
	defer s.Shutdown()

	// Client based API
	nc, js := jsClientConnect(t, s)
	defer nc.Close()

	_, err := js.AddStream(&nats.StreamConfig{
		Name:     "TEST",
		Subjects: []string{"foo", "bar"},
	})
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	sub, err := js.PullSubscribe("foo", "dlc")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	beforeSubs := s.NumSubscriptions()

	// How long we want both sides to run.
	timeout := time.Now().Add(3 * time.Second)
	errs := make(chan error, 1)

	// Publishing side, which will signal the consumer that is waiting and which will access c.acc. If publish
	// operation runs concurrently we will catch c.acc being $SYS some of the time.
	go func() {
		time.Sleep(100 * time.Millisecond)
		for time.Now().Before(timeout) {
			// This will signal the delivery of the pull messages.
			js.Publish("foo", []byte("Hello"))
			// This will swap the account because of JetStream service import.
			// We can get an error here with the bug or not.
			if _, err := js.StreamInfo("TEST"); err != nil {
				errs <- err
				return
			}
		}
		errs <- nil
	}()

	// Pull messages flow.
	var received int
	for time.Now().Before(timeout) {
		if msgs, err := sub.Fetch(1, nats.MaxWait(200*time.Millisecond)); err == nil {
			for _, m := range msgs {
				received++
				m.AckSync()
			}
		} else {
			break
		}
	}
	// Wait on publisher Go routine and check for errors.
	if err := <-errs; err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	// Double check all received.
	si, err := js.StreamInfo("TEST")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if int(si.State.Msgs) != received {
		t.Fatalf("Expected to receive %d msgs, only got %d", si.State.Msgs, received)
	}
	// Now check for leaked subs from the fetch call above. That is what we first saw from the bug.
	if afterSubs := s.NumSubscriptions(); afterSubs != beforeSubs {
		t.Fatalf("Leaked subscriptions: %d before, %d after", beforeSubs, afterSubs)
	}
}

func TestNoRaceJetStreamAPIStreamListPaging(t *testing.T) {
	s := RunBasicJetStreamServer(t)
	defer s.Shutdown()

	// Create 2X limit
	streamsNum := 2 * JSApiNamesLimit
	for i := 1; i <= streamsNum; i++ {
		name := fmt.Sprintf("STREAM-%06d", i)
		cfg := StreamConfig{Name: name, Storage: MemoryStorage}
		_, err := s.GlobalAccount().addStream(&cfg)
		if err != nil {
			t.Fatalf("Unexpected error adding stream: %v", err)
		}
	}

	// Client for API requests.
	nc := clientConnectToServer(t, s)
	defer nc.Close()

	reqList := func(offset int) []byte {
		t.Helper()
		var req []byte
		if offset > 0 {
			req, _ = json.Marshal(&ApiPagedRequest{Offset: offset})
		}
		resp, err := nc.Request(JSApiStreams, req, time.Second)
		if err != nil {
			t.Fatalf("Unexpected error getting stream list: %v", err)
		}
		return resp.Data
	}

	checkResp := func(resp []byte, expectedLen, expectedOffset int) {
		t.Helper()
		var listResponse JSApiStreamNamesResponse
		if err := json.Unmarshal(resp, &listResponse); err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if len(listResponse.Streams) != expectedLen {
			t.Fatalf("Expected only %d streams but got %d", expectedLen, len(listResponse.Streams))
		}
		if listResponse.Total != streamsNum {
			t.Fatalf("Expected total to be %d but got %d", streamsNum, listResponse.Total)
		}
		if listResponse.Offset != expectedOffset {
			t.Fatalf("Expected offset to be %d but got %d", expectedOffset, listResponse.Offset)
		}
		if expectedLen < 1 {
			return
		}
		// Make sure we get the right stream.
		sname := fmt.Sprintf("STREAM-%06d", expectedOffset+1)
		if listResponse.Streams[0] != sname {
			t.Fatalf("Expected stream %q to be first, got %q", sname, listResponse.Streams[0])
		}
	}

	checkResp(reqList(0), JSApiNamesLimit, 0)
	checkResp(reqList(JSApiNamesLimit), JSApiNamesLimit, JSApiNamesLimit)
	checkResp(reqList(streamsNum), 0, streamsNum)
	checkResp(reqList(streamsNum-22), 22, streamsNum-22)
	checkResp(reqList(streamsNum+22), 0, streamsNum)
}

func TestNoRaceJetStreamAPIConsumerListPaging(t *testing.T) {
	s := RunBasicJetStreamServer(t)
	defer s.Shutdown()

	sname := "MYSTREAM"
	mset, err := s.GlobalAccount().addStream(&StreamConfig{Name: sname})
	if err != nil {
		t.Fatalf("Unexpected error adding stream: %v", err)
	}

	// Client for API requests.
	nc := clientConnectToServer(t, s)
	defer nc.Close()

	consumersNum := JSApiNamesLimit
	for i := 1; i <= consumersNum; i++ {
		dsubj := fmt.Sprintf("d.%d", i)
		sub, _ := nc.SubscribeSync(dsubj)
		defer sub.Unsubscribe()
		nc.Flush()

		_, err := mset.addConsumer(&ConsumerConfig{DeliverSubject: dsubj})
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
	}

	reqListSubject := fmt.Sprintf(JSApiConsumersT, sname)
	reqList := func(offset int) []byte {
		t.Helper()
		var req []byte
		if offset > 0 {
			req, _ = json.Marshal(&JSApiConsumersRequest{ApiPagedRequest: ApiPagedRequest{Offset: offset}})
		}
		resp, err := nc.Request(reqListSubject, req, time.Second)
		if err != nil {
			t.Fatalf("Unexpected error getting stream list: %v", err)
		}
		return resp.Data
	}

	checkResp := func(resp []byte, expectedLen, expectedOffset int) {
		t.Helper()
		var listResponse JSApiConsumerNamesResponse
		if err := json.Unmarshal(resp, &listResponse); err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if len(listResponse.Consumers) != expectedLen {
			t.Fatalf("Expected only %d streams but got %d", expectedLen, len(listResponse.Consumers))
		}
		if listResponse.Total != consumersNum {
			t.Fatalf("Expected total to be %d but got %d", consumersNum, listResponse.Total)
		}
		if listResponse.Offset != expectedOffset {
			t.Fatalf("Expected offset to be %d but got %d", expectedOffset, listResponse.Offset)
		}
	}

	checkResp(reqList(0), JSApiNamesLimit, 0)
	checkResp(reqList(consumersNum-22), 22, consumersNum-22)
	checkResp(reqList(consumersNum+22), 0, consumersNum)
}

func TestNoRaceJetStreamWorkQueueLoadBalance(t *testing.T) {
	s := RunBasicJetStreamServer(t)
	defer s.Shutdown()

	mname := "MY_MSG_SET"
	mset, err := s.GlobalAccount().addStream(&StreamConfig{Name: mname, Subjects: []string{"foo", "bar"}})
	if err != nil {
		t.Fatalf("Unexpected error adding message set: %v", err)
	}
	defer mset.delete()

	// Create basic work queue mode consumer.
	oname := "WQ"
	o, err := mset.addConsumer(&ConsumerConfig{Durable: oname, AckPolicy: AckExplicit})
	if err != nil {
		t.Fatalf("Expected no error with durable, got %v", err)
	}
	defer o.delete()

	// To send messages.
	nc := clientConnectToServer(t, s)
	defer nc.Close()

	// For normal work queue semantics, you send requests to the subject with stream and consumer name.
	reqMsgSubj := o.requestNextMsgSubject()

	numWorkers := 25
	counts := make([]int32, numWorkers)
	var received int32

	rwg := &sync.WaitGroup{}
	rwg.Add(numWorkers)

	wg := &sync.WaitGroup{}
	wg.Add(numWorkers)
	ch := make(chan bool)

	toSend := 1000

	for i := 0; i < numWorkers; i++ {
		nc := clientConnectToServer(t, s)
		defer nc.Close()

		go func(index int32) {
			rwg.Done()
			defer wg.Done()
			<-ch

			for counter := &counts[index]; ; {
				m, err := nc.Request(reqMsgSubj, nil, 100*time.Millisecond)
				if err != nil {
					return
				}
				m.Respond(nil)
				atomic.AddInt32(counter, 1)
				if total := atomic.AddInt32(&received, 1); total >= int32(toSend) {
					return
				}
			}
		}(int32(i))
	}

	// Wait for requestors to be ready
	rwg.Wait()
	close(ch)

	sendSubj := "bar"
	for i := 0; i < toSend; i++ {
		sendStreamMsg(t, nc, sendSubj, "Hello World!")
	}

	// Wait for test to complete.
	wg.Wait()

	target := toSend / numWorkers
	delta := target/2 + 5
	low, high := int32(target-delta), int32(target+delta)

	for i := 0; i < numWorkers; i++ {
		if msgs := atomic.LoadInt32(&counts[i]); msgs < low || msgs > high {
			t.Fatalf("Messages received for worker [%d] too far off from target of %d, got %d", i, target, msgs)
		}
	}
}

func TestNoRaceJetStreamSlowFilteredInititalPendingAndFirstMsg(t *testing.T) {
	s := RunBasicJetStreamServer(t)
	defer s.Shutdown()

	// Create directly here to force multiple blocks, etc.
	a, err := s.LookupAccount("$G")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	mset, err := a.addStreamWithStore(
		&StreamConfig{
			Name:     "S",
			Subjects: []string{"foo", "bar", "baz", "foo.bar.baz", "foo.*"},
		},
		&FileStoreConfig{
			BlockSize:  4 * 1024 * 1024,
			AsyncFlush: true,
		},
	)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	nc, js := jsClientConnect(t, s)
	defer nc.Close()

	toSend := 100_000 // 500k total though.

	// Messages will be 'foo' 'bar' 'baz' repeated 100k times.
	// Then 'foo.bar.baz' all contigous for 100k.
	// Then foo.N for 1-100000
	for i := 0; i < toSend; i++ {
		js.PublishAsync("foo", []byte("HELLO"))
		js.PublishAsync("bar", []byte("WORLD"))
		js.PublishAsync("baz", []byte("AGAIN"))
	}
	// Make contiguous block of same subject.
	for i := 0; i < toSend; i++ {
		js.PublishAsync("foo.bar.baz", []byte("ALL-TOGETHER"))
	}
	// Now add some more at the end.
	for i := 0; i < toSend; i++ {
		js.PublishAsync(fmt.Sprintf("foo.%d", i+1), []byte("LATER"))
	}

	checkFor(t, 10*time.Second, 250*time.Millisecond, func() error {
		si, err := js.StreamInfo("S")
		if err != nil {
			return err
		}
		if si.State.Msgs != uint64(5*toSend) {
			return fmt.Errorf("Expected %d msgs, got %d", 5*toSend, si.State.Msgs)
		}
		return nil
	})

	// Threshold for taking too long.
	const thresh = 100 * time.Millisecond

	var dindex int
	testConsumerCreate := func(subj string, startSeq, expectedNumPending uint64) {
		t.Helper()
		dindex++
		dname := fmt.Sprintf("dur-%d", dindex)
		cfg := ConsumerConfig{FilterSubject: subj, Durable: dname, AckPolicy: AckExplicit}
		if startSeq > 1 {
			cfg.OptStartSeq, cfg.DeliverPolicy = startSeq, DeliverByStartSequence
		}
		start := time.Now()
		o, err := mset.addConsumer(&cfg)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if delta := time.Since(start); delta > thresh {
			t.Fatalf("Creating consumer for %q and start: %d took too long: %v", subj, startSeq, delta)
		}
		if ci := o.info(); ci.NumPending != expectedNumPending {
			t.Fatalf("Expected NumPending of %d, got %d", expectedNumPending, ci.NumPending)
		}
	}

	testConsumerCreate("foo.100000", 1, 1)
	testConsumerCreate("foo.100000", 222_000, 1)
	testConsumerCreate("foo", 1, 100_000)
	testConsumerCreate("foo", 4, 100_000-1)
	testConsumerCreate("foo.bar.baz", 1, 100_000)
	testConsumerCreate("foo.bar.baz", 350_001, 50_000)
	testConsumerCreate("*", 1, 300_000)
	testConsumerCreate("*", 4, 300_000-3)
	testConsumerCreate(">", 1, 500_000)
	testConsumerCreate(">", 50_000, 500_000-50_000+1)
	testConsumerCreate("foo.10", 1, 1)

	// Also test that we do not take long if the start sequence is later in the stream.
	sub, err := js.PullSubscribe("foo.100000", "dlc")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	start := time.Now()
	fetchMsgs(t, sub, 1, time.Second)
	if delta := time.Since(start); delta > thresh {
		t.Fatalf("Took too long for pull subscriber to fetch the message: %v", delta)
	}

	// Now do some deletes and make sure these are handled correctly.
	// Delete 3 foo messages.
	mset.removeMsg(1)
	mset.removeMsg(4)
	mset.removeMsg(7)
	testConsumerCreate("foo", 1, 100_000-3)

	// Make sure wider scoped subjects do the right thing from a pending perspective.
	o, err := mset.addConsumer(&ConsumerConfig{FilterSubject: ">", Durable: "cat", AckPolicy: AckExplicit})
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	ci, expected := o.info(), uint64(500_000-3)
	if ci.NumPending != expected {
		t.Fatalf("Expected NumPending of %d, got %d", expected, ci.NumPending)
	}
	// Send another and make sure its captured by our wide scope consumer.
	js.Publish("foo", []byte("HELLO AGAIN"))
	if ci = o.info(); ci.NumPending != expected+1 {
		t.Fatalf("Expected the consumer to recognize the wide scoped consumer, wanted pending of %d, got %d", expected+1, ci.NumPending)
	}

	// Stop current server and test restart..
	sd := s.JetStreamConfig().StoreDir
	s.Shutdown()
	// Restart.
	s = RunJetStreamServerOnPort(-1, sd)
	defer s.Shutdown()

	a, err = s.LookupAccount("$G")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	mset, err = a.lookupStream("S")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Make sure we recovered our per subject state on restart.
	testConsumerCreate("foo.100000", 1, 1)
	testConsumerCreate("foo", 1, 100_000-2)
}

func TestNoRaceJetStreamFileStoreBufferReuse(t *testing.T) {
	// Uncomment to run. Needs to be on a big machine.
	skip(t)

	s := RunBasicJetStreamServer(t)
	defer s.Shutdown()

	cfg := &StreamConfig{Name: "TEST", Subjects: []string{"foo", "bar", "baz"}, Storage: FileStorage}
	if _, err := s.GlobalAccount().addStreamWithStore(cfg, nil); err != nil {
		t.Fatalf("Unexpected error adding stream: %v", err)
	}

	// Client for API requests.
	nc, js := jsClientConnect(t, s)
	defer nc.Close()

	toSend := 200_000

	m := nats.NewMsg("foo")
	m.Data = make([]byte, 8*1024)
	rand.Read(m.Data)

	start := time.Now()
	for i := 0; i < toSend; i++ {
		m.Reply = _EMPTY_
		switch i % 3 {
		case 0:
			m.Subject = "foo"
		case 1:
			m.Subject = "bar"
		case 2:
			m.Subject = "baz"
		}
		m.Header.Set("X-ID2", fmt.Sprintf("XXXXX-%d", i))
		if _, err := js.PublishMsgAsync(m); err != nil {
			t.Fatalf("Err on publish: %v", err)
		}
	}
	<-js.PublishAsyncComplete()
	fmt.Printf("TOOK %v to publish\n", time.Since(start))

	v, err := s.Varz(nil)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	fmt.Printf("MEM AFTER PUBLISH is %v\n", friendlyBytes(v.Mem))

	si, _ := js.StreamInfo("TEST")
	fmt.Printf("si is %+v\n", si.State)

	received := 0
	done := make(chan bool)

	cb := func(m *nats.Msg) {
		received++
		if received >= toSend {
			done <- true
		}
	}

	start = time.Now()
	sub, err := js.Subscribe("*", cb, nats.EnableFlowControl(), nats.IdleHeartbeat(time.Second), nats.AckNone())
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	defer sub.Unsubscribe()
	<-done
	fmt.Printf("TOOK %v to consume\n", time.Since(start))

	v, err = s.Varz(nil)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	fmt.Printf("MEM AFTER SUBSCRIBE is %v\n", friendlyBytes(v.Mem))
}

// Report of slow restart for a server that has many messages that have expired while it was not running.
func TestNoRaceJetStreamSlowRestartWithManyExpiredMsgs(t *testing.T) {
	opts := DefaultTestOptions
	opts.Port = -1
	opts.JetStream = true
	s := RunServer(&opts)
	if config := s.JetStreamConfig(); config != nil {
		defer removeDir(t, config.StoreDir)
	}
	defer s.Shutdown()

	// Client for API requests.
	nc, js := jsClientConnect(t, s)
	defer nc.Close()

	ttl := 2 * time.Second
	_, err := js.AddStream(&nats.StreamConfig{
		Name:     "ORDERS",
		Subjects: []string{"orders.*"},
		MaxAge:   ttl,
	})
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Attach a consumer who is filtering on a wildcard subject as well.
	// This does not affect it like I thought originally but will keep it here.
	_, err = js.AddConsumer("ORDERS", &nats.ConsumerConfig{
		Durable:       "c22",
		FilterSubject: "orders.*",
		AckPolicy:     nats.AckExplicitPolicy,
	})
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Now fill up with messages.
	toSend := 100_000
	for i := 1; i <= toSend; i++ {
		js.PublishAsync(fmt.Sprintf("orders.%d", i), []byte("OK"))
	}
	<-js.PublishAsyncComplete()

	sdir := strings.TrimSuffix(s.JetStreamConfig().StoreDir, JetStreamStoreDir)
	s.Shutdown()

	// Let them expire while not running.
	time.Sleep(ttl + 500*time.Millisecond)

	start := time.Now()
	opts.Port = -1
	opts.StoreDir = sdir
	s = RunServer(&opts)
	elapsed := time.Since(start)
	defer s.Shutdown()

	if elapsed > 2*time.Second {
		t.Fatalf("Took %v for restart which is too long", elapsed)
	}

	// Check everything is correct.
	nc, js = jsClientConnect(t, s)
	defer nc.Close()

	si, err := js.StreamInfo("ORDERS")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if si.State.Msgs != 0 {
		t.Fatalf("Expected no msgs after restart, got %d", si.State.Msgs)
	}
}

func TestNoRaceCompressedConnz(t *testing.T) {
	s := RunBasicJetStreamServer(t)
	defer s.Shutdown()

	nc, _ := jsClientConnect(t, s)
	defer nc.Close()

	doRequest := func(compress string) {
		t.Helper()
		m := nats.NewMsg("$SYS.REQ.ACCOUNT.PING.CONNZ")
		m.Header.Add("Accept-Encoding", compress)
		resp, err := nc.RequestMsg(m, time.Second)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		buf := resp.Data

		// Make sure we have an encoding header.
		ce := resp.Header.Get("Content-Encoding")
		switch strings.ToLower(ce) {
		case "gzip":
			zr, err := gzip.NewReader(bytes.NewReader(buf))
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}
			defer zr.Close()
			buf, err = io.ReadAll(zr)
			if err != nil && err != io.ErrUnexpectedEOF {
				t.Fatalf("Unexpected error: %v", err)
			}
		case "snappy", "s2":
			sr := s2.NewReader(bytes.NewReader(buf))
			buf, err = io.ReadAll(sr)
			if err != nil && err != io.ErrUnexpectedEOF {
				t.Fatalf("Unexpected error: %v", err)
			}
		default:
			t.Fatalf("Unknown content-encoding of %q", ce)
		}

		var cz ServerAPIConnzResponse
		if err := json.Unmarshal(buf, &cz); err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if cz.Error != nil {
			t.Fatalf("Unexpected error: %+v", cz.Error)
		}
	}

	doRequest("gzip")
	doRequest("snappy")
	doRequest("s2")
}

func TestNoRaceJetStreamFileStoreCompaction(t *testing.T) {
	s := RunBasicJetStreamServer(t)
	defer s.Shutdown()

	nc, js := jsClientConnect(t, s)
	defer nc.Close()

	cfg := &nats.StreamConfig{
		Name:              "KV",
		Subjects:          []string{"KV.>"},
		MaxMsgsPerSubject: 1,
	}
	if _, err := js.AddStream(cfg); err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	toSend := 10_000
	data := make([]byte, 4*1024)
	rand.Read(data)

	// First one.
	js.PublishAsync("KV.FM", data)

	for i := 0; i < toSend; i++ {
		js.PublishAsync(fmt.Sprintf("KV.%d", i+1), data)
	}
	// Do again and overwrite the previous batch.
	for i := 0; i < toSend; i++ {
		js.PublishAsync(fmt.Sprintf("KV.%d", i+1), data)
	}

	select {
	case <-js.PublishAsyncComplete():
	case <-time.After(time.Second):
		t.Fatalf("Did not receive completion signal")
	}

	// Now check by hand the utilization level.
	mset, err := s.GlobalAccount().lookupStream("KV")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	total, used, _ := mset.Store().Utilization()
	if pu := 100.0 * float32(used) / float32(total); pu < 80.0 {
		t.Fatalf("Utilization is less than 80%%, got %.2f", pu)
	}
}

func TestNoRaceJetStreamEncryptionEnabledOnRestartWithExpire(t *testing.T) {
	conf := createConfFile(t, []byte(`
		listen: 127.0.0.1:-1
		jetstream: enabled
	`))

	s, _ := RunServerWithConfig(conf)
	defer s.Shutdown()

	config := s.JetStreamConfig()
	if config == nil {
		t.Fatalf("Expected config but got none")
	}
	defer removeDir(t, config.StoreDir)

	nc, js := jsClientConnect(t, s)
	defer nc.Close()

	toSend := 10_000

	cfg := &nats.StreamConfig{
		Name:     "TEST",
		Subjects: []string{"foo", "bar"},
		MaxMsgs:  int64(toSend),
	}
	if _, err := js.AddStream(cfg); err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	data := make([]byte, 4*1024) // 4K payload
	rand.Read(data)

	for i := 0; i < toSend; i++ {
		js.PublishAsync("foo", data)
		js.PublishAsync("bar", data)
	}
	select {
	case <-js.PublishAsyncComplete():
	case <-time.After(5 * time.Second):
		t.Fatalf("Did not receive completion signal")
	}

	_, err := js.AddConsumer("TEST", &nats.ConsumerConfig{Durable: "dlc", AckPolicy: nats.AckExplicitPolicy})
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Restart
	nc.Close()
	s.Shutdown()

	ncs := fmt.Sprintf("\nlisten: 127.0.0.1:-1\njetstream: {key: %q, store_dir: %q}\n", "s3cr3t!", config.StoreDir)
	conf = createConfFile(t, []byte(ncs))

	// Try to drain entropy to see if effects startup time.
	drain := make([]byte, 32*1024*1024) // Pull 32Mb of crypto rand.
	crand.Read(drain)

	start := time.Now()
	s, _ = RunServerWithConfig(conf)
	defer s.Shutdown()
	dd := time.Since(start)
	if dd > 5*time.Second {
		t.Fatalf("Restart took longer than expected: %v", dd)
	}
}

// This test was from Ivan K. and showed a bug in the filestore implementation.
// This is skipped by default since it takes >40s to run.
func TestNoRaceJetStreamOrderedConsumerMissingMsg(t *testing.T) {
	// Uncomment to run. Needs to be on a big machine. Do not want as part of Travis tests atm.
	skip(t)

	s := RunBasicJetStreamServer(t)
	defer s.Shutdown()

	nc, js := jsClientConnect(t, s)
	defer nc.Close()

	if _, err := js.AddStream(&nats.StreamConfig{
		Name:     "benchstream",
		Subjects: []string{"testsubject"},
		Replicas: 1,
	}); err != nil {
		t.Fatalf("add stream failed: %s", err)
	}

	total := 1_000_000

	numSubs := 10
	ch := make(chan struct{}, numSubs)
	wg := sync.WaitGroup{}
	wg.Add(numSubs)
	errCh := make(chan error, 1)
	for i := 0; i < numSubs; i++ {
		nc, js := jsClientConnect(t, s)
		defer nc.Close()
		go func(nc *nats.Conn, js nats.JetStreamContext) {
			defer wg.Done()
			received := 0
			_, err := js.Subscribe("testsubject", func(m *nats.Msg) {
				meta, _ := m.Metadata()
				if meta.Sequence.Consumer != meta.Sequence.Stream {
					nc.Close()
					errCh <- fmt.Errorf("Bad meta: %+v", meta)
				}
				received++
				if received == total {
					ch <- struct{}{}
				}
			}, nats.OrderedConsumer())
			if err != nil {
				select {
				case errCh <- fmt.Errorf("Error creating sub: %v", err):
				default:
				}

			}
		}(nc, js)
	}
	wg.Wait()
	select {
	case e := <-errCh:
		t.Fatal(e)
	default:
	}

	payload := make([]byte, 500)
	for i := 1; i <= total; i++ {
		js.PublishAsync("testsubject", payload)
	}
	select {
	case <-js.PublishAsyncComplete():
	case <-time.After(10 * time.Second):
		t.Fatalf("Did not send all messages")
	}

	// Now wait for consumers to be done:
	for i := 0; i < numSubs; i++ {
		select {
		case <-ch:
		case <-time.After(10 * time.Second):
			t.Fatal("Did not receive all messages for all consumers in time")
		}
	}

}

// There was a bug in the filestore compact code that would cause a store
// with JSExpectedLastSubjSeq to fail with "wrong last sequence: 0"
func TestNoRaceJetStreamLastSubjSeqAndFilestoreCompact(t *testing.T) {
	s := RunBasicJetStreamServer(t)
	defer s.Shutdown()

	// Client based API
	nc, js := jsClientConnect(t, s)
	defer nc.Close()

	_, err := js.AddStream(&nats.StreamConfig{
		Name:              "MQTT_sess",
		Subjects:          []string{"MQTT.sess.>"},
		Storage:           nats.FileStorage,
		Retention:         nats.LimitsPolicy,
		Replicas:          1,
		MaxMsgsPerSubject: 1,
	})
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	firstPayload := make([]byte, 40)
	secondPayload := make([]byte, 380)
	for iter := 0; iter < 2; iter++ {
		for i := 0; i < 4000; i++ {
			subj := "MQTT.sess." + getHash(fmt.Sprintf("client_%d", i))
			pa, err := js.Publish(subj, firstPayload)
			if err != nil {
				t.Fatalf("Error on publish: %v", err)
			}
			m := nats.NewMsg(subj)
			m.Data = secondPayload
			eseq := strconv.FormatInt(int64(pa.Sequence), 10)
			m.Header.Set(JSExpectedLastSubjSeq, eseq)
			if _, err := js.PublishMsg(m); err != nil {
				t.Fatalf("Error on publish (iter=%v seq=%v): %v", iter+1, pa.Sequence, err)
			}
		}
	}
}

func TestNoRaceJetStreamMemstoreWithLargeInteriorDeletes(t *testing.T) {
	s := RunBasicJetStreamServer(t)
	defer s.Shutdown()

	// Client for API requests.
	nc, js := jsClientConnect(t, s)
	defer nc.Close()

	_, err := js.AddStream(&nats.StreamConfig{
		Name:              "TEST",
		Subjects:          []string{"foo", "bar"},
		MaxMsgsPerSubject: 1,
		Storage:           nats.MemoryStorage,
	})
	require_NoError(t, err)

	acc, err := s.lookupAccount("$G")
	require_NoError(t, err)
	mset, err := acc.lookupStream("TEST")
	require_NoError(t, err)

	msg := []byte("Hello World!")
	if _, err := js.PublishAsync("foo", msg); err != nil {
		t.Fatalf("Unexpected publish error: %v", err)
	}
	for i := 1; i <= 1_000_000; i++ {
		if _, err := js.PublishAsync("bar", msg); err != nil {
			t.Fatalf("Unexpected publish error: %v", err)
		}
	}
	select {
	case <-js.PublishAsyncComplete():
	case <-time.After(5 * time.Second):
		t.Fatalf("Did not receive completion signal")
	}

	now := time.Now()
	ss := mset.stateWithDetail(true)
	// Before the fix the snapshot for this test would be > 200ms on my setup.
	if elapsed := time.Since(now); elapsed > 50*time.Millisecond {
		t.Fatalf("Took too long to snapshot: %v", elapsed)
	}

	if ss.Msgs != 2 || ss.FirstSeq != 1 || ss.LastSeq != 1_000_001 || ss.NumDeleted != 999999 {
		// To not print out on error.
		ss.Deleted = nil
		t.Fatalf("Bad State: %+v", ss)
	}
}

// This is related to an issue reported where we were exhausting threads by trying to
// cleanup too many consumers at the same time.
// https://github.com/nats-io/nats-server/issues/2742
func TestNoRaceJetStreamConsumerFileStoreConcurrentDiskIO(t *testing.T) {
	storeDir := t.TempDir()

	// Artificially adjust our environment for this test.
	gmp := runtime.GOMAXPROCS(32)
	defer runtime.GOMAXPROCS(gmp)

	maxT := debug.SetMaxThreads(1050) // 1024 now
	defer debug.SetMaxThreads(maxT)

	fs, err := newFileStore(FileStoreConfig{StoreDir: storeDir}, StreamConfig{Name: "MT", Storage: FileStorage})
	require_NoError(t, err)
	defer fs.Stop()

	startCh := make(chan bool)
	var wg sync.WaitGroup
	var swg sync.WaitGroup

	ts := time.Now().UnixNano()

	// Create 1000 consumerStores
	n := 1000
	swg.Add(n)

	for i := 1; i <= n; i++ {
		name := fmt.Sprintf("o%d", i)
		o, err := fs.ConsumerStore(name, &ConsumerConfig{AckPolicy: AckExplicit})
		require_NoError(t, err)
		wg.Add(1)
		swg.Done()

		go func() {
			defer wg.Done()
			// Will make everyone run concurrently.
			<-startCh
			o.UpdateDelivered(22, 22, 1, ts)
			buf, _ := o.(*consumerFileStore).encodeState()
			o.(*consumerFileStore).writeState(buf)
			o.Delete()
		}()
	}

	swg.Wait()
	close(startCh)
	wg.Wait()
}

// Test that we can receive larger messages with stream subject details.
// Also test that we will fail at some point and the user can fall back to
// an orderedconsumer like we do with watch for KV Keys() call.
func TestNoRaceJetStreamStreamInfoSubjectDetailsLimits(t *testing.T) {
	conf := createConfFile(t, []byte(`
		listen: 127.0.0.1:-1
		jetstream: enabled
		accounts: {
		  default: {
			jetstream: true
			users: [ {user: me, password: pwd} ]
			limits { max_payload: 256 }
		  }
		}
	`))

	s, _ := RunServerWithConfig(conf)
	if config := s.JetStreamConfig(); config != nil {
		defer removeDir(t, config.StoreDir)
	}
	defer s.Shutdown()

	nc, js := jsClientConnect(t, s, nats.UserInfo("me", "pwd"))
	defer nc.Close()

	// Make sure we cannot send larger than 256 bytes.
	// But we can receive larger.
	sub, err := nc.SubscribeSync("foo")
	require_NoError(t, err)
	err = nc.Publish("foo", []byte(strings.Repeat("A", 300)))
	require_Error(t, err, nats.ErrMaxPayload)
	sub.Unsubscribe()

	_, err = js.AddStream(&nats.StreamConfig{
		Name:     "TEST",
		Subjects: []string{"*", "X.*"},
	})
	require_NoError(t, err)

	n := JSMaxSubjectDetails
	for i := 0; i < n; i++ {
		_, err := js.PublishAsync(fmt.Sprintf("X.%d", i), []byte("OK"))
		require_NoError(t, err)
	}
	select {
	case <-js.PublishAsyncComplete():
	case <-time.After(5 * time.Second):
		t.Fatalf("Did not receive completion signal")
	}

	// Need to grab StreamInfo by hand for now.
	req, err := json.Marshal(&JSApiStreamInfoRequest{SubjectsFilter: "X.*"})
	require_NoError(t, err)
	resp, err := nc.Request(fmt.Sprintf(JSApiStreamInfoT, "TEST"), req, 5*time.Second)
	require_NoError(t, err)
	var si StreamInfo
	err = json.Unmarshal(resp.Data, &si)
	require_NoError(t, err)
	if len(si.State.Subjects) != n {
		t.Fatalf("Expected to get %d subject details, got %d", n, len(si.State.Subjects))
	}

	// Now add one more message to check pagination
	_, err = js.Publish("foo", []byte("TOO MUCH"))
	require_NoError(t, err)

	req, err = json.Marshal(&JSApiStreamInfoRequest{ApiPagedRequest: ApiPagedRequest{Offset: n}, SubjectsFilter: nats.AllKeys})
	require_NoError(t, err)
	resp, err = nc.Request(fmt.Sprintf(JSApiStreamInfoT, "TEST"), req, 5*time.Second)
	require_NoError(t, err)
	var sir JSApiStreamInfoResponse
	err = json.Unmarshal(resp.Data, &sir)
	require_NoError(t, err)
	if len(sir.State.Subjects) != 1 {
		t.Fatalf("Expected to get 1 extra subject detail, got %d", len(sir.State.Subjects))
	}
}

func TestNoRaceJetStreamSparseConsumers(t *testing.T) {
	s := RunBasicJetStreamServer(t)
	defer s.Shutdown()

	nc, js := jsClientConnect(t, s)
	defer nc.Close()

	msg := []byte("ok")

	cases := []struct {
		name    string
		mconfig *nats.StreamConfig
	}{
		{"MemoryStore", &nats.StreamConfig{Name: "TEST", Storage: nats.MemoryStorage, MaxMsgsPerSubject: 25_000_000,
			Subjects: []string{"*"}}},
		{"FileStore", &nats.StreamConfig{Name: "TEST", Storage: nats.FileStorage, MaxMsgsPerSubject: 25_000_000,
			Subjects: []string{"*"}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			js.DeleteStream("TEST")
			_, err := js.AddStream(c.mconfig)
			require_NoError(t, err)

			// We will purposely place foo msgs near the beginning, then in middle, then at the end.
			for n := 0; n < 2; n++ {
				_, err = js.PublishAsync("foo", msg)
				require_NoError(t, err)

				for i := 0; i < 1_000_000; i++ {
					_, err = js.PublishAsync("bar", msg)
					require_NoError(t, err)
				}
				_, err = js.PublishAsync("foo", msg)
				require_NoError(t, err)
			}
			select {
			case <-js.PublishAsyncComplete():
			case <-time.After(5 * time.Second):
				t.Fatalf("Did not receive completion signal")
			}

			// Now create a consumer on foo.
			ci, err := js.AddConsumer("TEST", &nats.ConsumerConfig{DeliverSubject: "x.x", FilterSubject: "foo", AckPolicy: nats.AckNonePolicy})
			require_NoError(t, err)

			done, received := make(chan bool), uint64(0)

			cb := func(m *nats.Msg) {
				received++
				if received >= ci.NumPending {
					done <- true
				}
			}

			sub, err := nc.Subscribe("x.x", cb)
			require_NoError(t, err)
			defer sub.Unsubscribe()
			start := time.Now()
			var elapsed time.Duration

			select {
			case <-done:
				elapsed = time.Since(start)
			case <-time.After(10 * time.Second):
				t.Fatal("Did not receive all messages for all consumers in time")
			}

			if elapsed > 500*time.Millisecond {
				t.Fatalf("Getting all messages took longer than expected: %v", elapsed)
			}
		})
	}
}

func TestNoRaceJetStreamConsumerFilterPerfDegradation(t *testing.T) {
	s := RunBasicJetStreamServer(t)
	defer s.Shutdown()

	nc, _ := jsClientConnect(t, s)
	defer nc.Close()

	js, err := nc.JetStream(nats.PublishAsyncMaxPending(256))
	require_NoError(t, err)

	_, err = js.AddStream(&nats.StreamConfig{
		Name:     "test",
		Subjects: []string{"test.*.subj"},
		Replicas: 1,
	})
	require_NoError(t, err)

	toSend := 50_000
	count := 0
	ch := make(chan struct{}, 6)
	_, err = js.Subscribe("test.*.subj", func(m *nats.Msg) {
		m.Ack()
		if count++; count == toSend {
			ch <- struct{}{}
		}
	}, nats.DeliverNew(), nats.ManualAck())
	require_NoError(t, err)

	msg := make([]byte, 1024)
	sent := int32(0)
	send := func() {
		defer func() { ch <- struct{}{} }()
		for i := 0; i < toSend/5; i++ {
			msgID := atomic.AddInt32(&sent, 1)
			_, err := js.Publish(fmt.Sprintf("test.%d.subj", msgID), msg)
			if err != nil {
				t.Error(err)
				return
			}
		}
	}
	for i := 0; i < 5; i++ {
		go send()
	}
	timeout := time.NewTimer(10 * time.Second)
	for i := 0; i < 6; i++ {
		select {
		case <-ch:
		case <-timeout.C:
			t.Fatal("Took too long")
		}
	}
}

func TestNoRaceJetStreamFileStoreKeyFileCleanup(t *testing.T) {
	storeDir := t.TempDir()

	prf := func(context []byte) ([]byte, error) {
		h := hmac.New(sha256.New, []byte("dlc22"))
		if _, err := h.Write(context); err != nil {
			return nil, err
		}
		return h.Sum(nil), nil
	}

	fs, err := newFileStoreWithCreated(
		FileStoreConfig{StoreDir: storeDir, BlockSize: 1024 * 1024},
		StreamConfig{Name: "TEST", Storage: FileStorage},
		time.Now(),
		prf)
	require_NoError(t, err)
	defer fs.Stop()

	n, msg := 10_000, []byte(strings.Repeat("Z", 1024))
	for i := 0; i < n; i++ {
		_, _, err := fs.StoreMsg(fmt.Sprintf("X.%d", i), nil, msg)
		require_NoError(t, err)
	}

	var seqs []uint64
	for i := 1; i <= n; i++ {
		seqs = append(seqs, uint64(i))
	}
	// Randomly delete msgs, make sure we cleanup as we empty the message blocks.
	rand.Shuffle(len(seqs), func(i, j int) { seqs[i], seqs[j] = seqs[j], seqs[i] })

	for _, seq := range seqs {
		_, err := fs.RemoveMsg(seq)
		require_NoError(t, err)
	}

	// We will have cleanup the main .blk and .idx sans the lmb, but we should not have any *.fss files.
	kms, err := filepath.Glob(filepath.Join(storeDir, msgDir, keyScanAll))
	require_NoError(t, err)

	if len(kms) > 1 {
		t.Fatalf("Expected to find only 1 key file, found %d", len(kms))
	}
}

func TestNoRaceJetStreamRebuildDeDupeAndMemoryPerf(t *testing.T) {
	skip(t)

	s := RunBasicJetStreamServer(t)
	defer s.Shutdown()

	nc, js := jsClientConnect(t, s)
	defer nc.Close()

	_, err := js.AddStream(&nats.StreamConfig{Name: "DD"})
	require_NoError(t, err)

	m := nats.NewMsg("DD")
	m.Data = []byte(strings.Repeat("Z", 2048))

	start := time.Now()

	n := 1_000_000
	for i := 0; i < n; i++ {
		m.Header.Set(JSMsgId, strconv.Itoa(i))
		_, err := js.PublishMsgAsync(m)
		require_NoError(t, err)
	}

	select {
	case <-js.PublishAsyncComplete():
	case <-time.After(20 * time.Second):
		t.Fatalf("Did not receive completion signal")
	}

	tt := time.Since(start)
	si, err := js.StreamInfo("DD")
	require_NoError(t, err)

	fmt.Printf("Took %v to send %d msgs\n", tt, n)
	fmt.Printf("%.0f msgs/s\n", float64(n)/tt.Seconds())
	fmt.Printf("%.0f mb/s\n\n", float64(si.State.Bytes/(1024*1024))/tt.Seconds())

	v, _ := s.Varz(nil)
	fmt.Printf("Memory AFTER SEND: %v\n", friendlyBytes(v.Mem))

	mset, err := s.GlobalAccount().lookupStream("DD")
	require_NoError(t, err)

	mset.mu.Lock()
	mset.ddloaded = false
	start = time.Now()
	mset.rebuildDedupe()
	fmt.Printf("TOOK %v to rebuild dd\n", time.Since(start))
	mset.mu.Unlock()

	v, _ = s.Varz(nil)
	fmt.Printf("Memory: %v\n", friendlyBytes(v.Mem))

	// Now do an ephemeral consumer and whip through every message. Doing same calculations.
	start = time.Now()
	received, done := 0, make(chan bool)
	sub, err := js.Subscribe("DD", func(m *nats.Msg) {
		received++
		if received >= n {
			done <- true
		}
	}, nats.OrderedConsumer())
	require_NoError(t, err)

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		if s.NumSlowConsumers() > 0 {
			t.Fatalf("Did not receive all large messages due to slow consumer status: %d of %d", received, n)
		}
		t.Fatalf("Failed to receive all large messages: %d of %d\n", received, n)
	}

	fmt.Printf("TOOK %v to receive all %d msgs\n", time.Since(start), n)
	sub.Unsubscribe()

	v, _ = s.Varz(nil)
	fmt.Printf("Memory: %v\n", friendlyBytes(v.Mem))
}

func TestNoRaceJetStreamMemoryUsageOnLimitedStreamWithMirror(t *testing.T) {
	skip(t)

	s := RunBasicJetStreamServer(t)
	defer s.Shutdown()

	nc, js := jsClientConnect(t, s)
	defer nc.Close()

	_, err := js.AddStream(&nats.StreamConfig{Name: "DD", Subjects: []string{"ORDERS.*"}, MaxMsgs: 10_000})
	require_NoError(t, err)

	_, err = js.AddStream(&nats.StreamConfig{
		Name:    "M",
		Mirror:  &nats.StreamSource{Name: "DD"},
		MaxMsgs: 10_000,
	})
	require_NoError(t, err)

	m := nats.NewMsg("ORDERS.0")
	m.Data = []byte(strings.Repeat("Z", 2048))

	start := time.Now()

	n := 1_000_000
	for i := 0; i < n; i++ {
		m.Subject = fmt.Sprintf("ORDERS.%d", i)
		m.Header.Set(JSMsgId, strconv.Itoa(i))
		_, err := js.PublishMsgAsync(m)
		require_NoError(t, err)
	}

	select {
	case <-js.PublishAsyncComplete():
	case <-time.After(20 * time.Second):
		t.Fatalf("Did not receive completion signal")
	}

	tt := time.Since(start)
	si, err := js.StreamInfo("DD")
	require_NoError(t, err)

	fmt.Printf("Took %v to send %d msgs\n", tt, n)
	fmt.Printf("%.0f msgs/s\n", float64(n)/tt.Seconds())
	fmt.Printf("%.0f mb/s\n\n", float64(si.State.Bytes/(1024*1024))/tt.Seconds())

	v, _ := s.Varz(nil)
	fmt.Printf("Memory AFTER SEND: %v\n", friendlyBytes(v.Mem))
}

func TestNoRaceJetStreamOrderedConsumerLongRTTPerformance(t *testing.T) {
	skip(t)

	s := RunBasicJetStreamServer(t)
	defer s.Shutdown()

	nc, _ := jsClientConnect(t, s)
	defer nc.Close()

	js, err := nc.JetStream(nats.PublishAsyncMaxPending(1000))
	require_NoError(t, err)

	_, err = js.AddStream(&nats.StreamConfig{Name: "OCP"})
	require_NoError(t, err)

	n, msg := 100_000, []byte(strings.Repeat("D", 30_000))

	for i := 0; i < n; i++ {
		_, err := js.PublishAsync("OCP", msg)
		require_NoError(t, err)
	}
	select {
	case <-js.PublishAsyncComplete():
	case <-time.After(5 * time.Second):
		t.Fatalf("Did not receive completion signal")
	}

	// Approximately 3GB
	si, err := js.StreamInfo("OCP")
	require_NoError(t, err)

	start := time.Now()
	received, done := 0, make(chan bool)
	sub, err := js.Subscribe("OCP", func(m *nats.Msg) {
		received++
		if received >= n {
			done <- true
		}
	}, nats.OrderedConsumer())
	require_NoError(t, err)
	defer sub.Unsubscribe()

	// Wait to receive all messages.
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatalf("Did not receive all of our messages")
	}

	tt := time.Since(start)
	fmt.Printf("Took %v to receive %d msgs\n", tt, n)
	fmt.Printf("%.0f msgs/s\n", float64(n)/tt.Seconds())
	fmt.Printf("%.0f mb/s\n\n", float64(si.State.Bytes/(1024*1024))/tt.Seconds())

	sub.Unsubscribe()

	rtt := 10 * time.Millisecond
	bw := 10 * 1024 * 1024 * 1024
	proxy := newNetProxy(rtt, bw, bw, s.ClientURL())
	defer proxy.stop()

	nc, err = nats.Connect(proxy.clientURL())
	require_NoError(t, err)
	defer nc.Close()
	js, err = nc.JetStream()
	require_NoError(t, err)

	start, received = time.Now(), 0
	sub, err = js.Subscribe("OCP", func(m *nats.Msg) {
		received++
		if received >= n {
			done <- true
		}
	}, nats.OrderedConsumer())
	require_NoError(t, err)
	defer sub.Unsubscribe()

	// Wait to receive all messages.
	select {
	case <-done:
	case <-time.After(60 * time.Second):
		t.Fatalf("Did not receive all of our messages")
	}

	tt = time.Since(start)
	fmt.Printf("Proxy RTT: %v, UP: %d, DOWN: %d\n", rtt, bw, bw)
	fmt.Printf("Took %v to receive %d msgs\n", tt, n)
	fmt.Printf("%.0f msgs/s\n", float64(n)/tt.Seconds())
	fmt.Printf("%.0f mb/s\n\n", float64(si.State.Bytes/(1024*1024))/tt.Seconds())
}

func TestNoRaceJetStreamFileStoreLargeKVAccessTiming(t *testing.T) {
	storeDir := t.TempDir()

	blkSize := uint64(4 * 1024)
	// Compensate for slower IO on MacOSX
	if runtime.GOOS == "darwin" {
		blkSize *= 4
	}

	fs, err := newFileStore(
		FileStoreConfig{StoreDir: storeDir, BlockSize: blkSize, CacheExpire: 30 * time.Second},
		StreamConfig{Name: "zzz", Subjects: []string{"KV.STREAM_NAME.*"}, Storage: FileStorage, MaxMsgsPer: 1},
	)
	require_NoError(t, err)
	defer fs.Stop()

	tmpl := "KV.STREAM_NAME.%d"
	nkeys, val := 100_000, bytes.Repeat([]byte("Z"), 1024)

	for i := 1; i <= nkeys; i++ {
		subj := fmt.Sprintf(tmpl, i)
		_, _, err := fs.StoreMsg(subj, nil, val)
		require_NoError(t, err)
	}

	first := fmt.Sprintf(tmpl, 1)
	last := fmt.Sprintf(tmpl, nkeys)

	start := time.Now()
	sm, err := fs.LoadLastMsg(last, nil)
	require_NoError(t, err)
	base := time.Since(start)

	if !bytes.Equal(sm.msg, val) {
		t.Fatalf("Retrieved value did not match")
	}

	start = time.Now()
	_, err = fs.LoadLastMsg(first, nil)
	require_NoError(t, err)
	slow := time.Since(start)

	if slow > 4*base || slow > time.Millisecond {
		t.Fatalf("Took too long to look up first key vs last: %v vs %v", base, slow)
	}

	// time first seq lookup for both as well.
	// Base will be first in this case.
	fs.mu.RLock()
	start = time.Now()
	fs.firstSeqForSubj(first)
	base = time.Since(start)
	start = time.Now()
	fs.firstSeqForSubj(last)
	slow = time.Since(start)
	fs.mu.RUnlock()

	if slow > 4*base || slow > time.Millisecond {
		t.Fatalf("Took too long to look up last key by subject vs first: %v vs %v", base, slow)
	}
}

func TestNoRaceJetStreamKVLock(t *testing.T) {
	s := RunBasicJetStreamServer(t)
	defer s.Shutdown()

	nc, js := jsClientConnect(t, s)
	defer nc.Close()

	_, err := js.CreateKeyValue(&nats.KeyValueConfig{Bucket: "LOCKS"})
	require_NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	start := make(chan bool)

	var tracker int64

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			nc, js := jsClientConnect(t, s)
			defer nc.Close()
			kv, err := js.KeyValue("LOCKS")
			require_NoError(t, err)

			<-start

			for {
				last, err := kv.Create("MY_LOCK", []byte("Z"))
				if err != nil {
					select {
					case <-time.After(10 * time.Millisecond):
						continue
					case <-ctx.Done():
						return
					}
				}

				if v := atomic.AddInt64(&tracker, 1); v != 1 {
					t.Logf("TRACKER NOT 1 -> %d\n", v)
					cancel()
				}

				time.Sleep(10 * time.Millisecond)
				if v := atomic.AddInt64(&tracker, -1); v != 0 {
					t.Logf("TRACKER NOT 0 AFTER RELEASE -> %d\n", v)
					cancel()
				}

				err = kv.Delete("MY_LOCK", nats.LastRevision(last))
				if err != nil {
					t.Logf("Could not unlock for last %d: %v", last, err)
				}

				if ctx.Err() != nil {
					return
				}
			}
		}()
	}

	close(start)
	wg.Wait()
}

// https://github.com/nats-io/nats-server/issues/3455
func TestNoRaceJetStreamConcurrentPullConsumerBatch(t *testing.T) {
	s := RunBasicJetStreamServer(t)
	defer s.Shutdown()

	nc, js := jsClientConnect(t, s)
	defer nc.Close()

	_, err := js.AddStream(&nats.StreamConfig{
		Name:      "TEST",
		Subjects:  []string{"ORDERS.*"},
		Storage:   nats.MemoryStorage,
		Retention: nats.WorkQueuePolicy,
	})
	require_NoError(t, err)

	toSend := int32(100_000)

	for i := 0; i < 100_000; i++ {
		subj := fmt.Sprintf("ORDERS.%d", i+1)
		js.PublishAsync(subj, []byte("BUY"))
	}
	select {
	case <-js.PublishAsyncComplete():
	case <-time.After(5 * time.Second):
		t.Fatalf("Did not receive completion signal")
	}

	_, err = js.AddConsumer("TEST", &nats.ConsumerConfig{
		Durable:       "PROCESSOR",
		AckPolicy:     nats.AckExplicitPolicy,
		MaxAckPending: 5000,
	})
	require_NoError(t, err)

	nc, js = jsClientConnect(t, s)
	defer nc.Close()

	sub1, err := js.PullSubscribe(_EMPTY_, _EMPTY_, nats.Bind("TEST", "PROCESSOR"))
	require_NoError(t, err)

	nc, js = jsClientConnect(t, s)
	defer nc.Close()

	sub2, err := js.PullSubscribe(_EMPTY_, _EMPTY_, nats.Bind("TEST", "PROCESSOR"))
	require_NoError(t, err)

	startCh := make(chan bool)

	var received int32

	wg := sync.WaitGroup{}

	fetchSize := 1000
	fetch := func(sub *nats.Subscription) {
		<-startCh
		defer wg.Done()

		for {
			msgs, err := sub.Fetch(fetchSize, nats.MaxWait(time.Second))
			if atomic.AddInt32(&received, int32(len(msgs))) >= toSend {
				break
			}
			// We should always receive a full batch here if not last competing fetch.
			if err != nil || len(msgs) != fetchSize {
				break
			}
			for _, m := range msgs {
				m.Ack()
			}
		}
	}

	wg.Add(2)

	go fetch(sub1)
	go fetch(sub2)

	close(startCh)

	wg.Wait()
	require_True(t, received == toSend)
}

func TestNoRaceJetStreamManyPullConsumersNeedAckOptimization(t *testing.T) {
	// Uncomment to run. Do not want as part of Travis tests atm.
	// Run with cpu and memory profiling to make sure we have improved.
	skip(t)

	s := RunBasicJetStreamServer(t)
	defer s.Shutdown()

	nc, js := jsClientConnect(t, s)
	defer nc.Close()

	_, err := js.AddStream(&nats.StreamConfig{
		Name:      "ORDERS",
		Subjects:  []string{"ORDERS.*"},
		Storage:   nats.MemoryStorage,
		Retention: nats.InterestPolicy,
	})
	require_NoError(t, err)

	toSend := 100_000
	numConsumers := 500

	// Create 500 consumers
	for i := 1; i <= numConsumers; i++ {
		_, err := js.AddConsumer("ORDERS", &nats.ConsumerConfig{
			Durable:       fmt.Sprintf("ORDERS_%d", i),
			FilterSubject: fmt.Sprintf("ORDERS.%d", i),
			AckPolicy:     nats.AckAllPolicy,
		})
		require_NoError(t, err)
	}

	for i := 1; i <= toSend; i++ {
		subj := fmt.Sprintf("ORDERS.%d", i%numConsumers+1)
		js.PublishAsync(subj, []byte("HELLO"))
	}
	select {
	case <-js.PublishAsyncComplete():
	case <-time.After(5 * time.Second):
		t.Fatalf("Did not receive completion signal")
	}

	sub, err := js.PullSubscribe("ORDERS.500", "ORDERS_500")
	require_NoError(t, err)

	fetchSize := toSend / numConsumers
	msgs, err := sub.Fetch(fetchSize, nats.MaxWait(time.Second))
	require_NoError(t, err)

	last := msgs[len(msgs)-1]
	last.AckSync()
}

// https://github.com/nats-io/nats-server/issues/3499
func TestNoRaceJetStreamDeleteConsumerWithInterestStreamAndHighSeqs(t *testing.T) {
	s := RunBasicJetStreamServer(t)
	defer s.Shutdown()

	// Client for API requests.
	nc, js := jsClientConnect(t, s)
	defer nc.Close()

	_, err := js.AddStream(&nats.StreamConfig{
		Name:      "TEST",
		Subjects:  []string{"log.>"},
		Retention: nats.InterestPolicy,
	})
	require_NoError(t, err)

	_, err = js.AddConsumer("TEST", &nats.ConsumerConfig{
		Durable:   "c",
		AckPolicy: nats.AckExplicitPolicy,
	})
	require_NoError(t, err)

	// Set baseline for time to delete so we can see linear increase as sequence numbers increase.
	start := time.Now()
	err = js.DeleteConsumer("TEST", "c")
	require_NoError(t, err)
	elapsed := time.Since(start)

	// Crank up sequence numbers.
	msg := []byte(strings.Repeat("ZZZ", 128))
	for i := 0; i < 5_000_000; i++ {
		nc.Publish("log.Z", msg)
	}
	nc.Flush()

	_, err = js.AddConsumer("TEST", &nats.ConsumerConfig{
		Durable:   "c",
		AckPolicy: nats.AckExplicitPolicy,
	})
	require_NoError(t, err)

	// We have a bug that spins unecessarily through all the sequences from this consumer's
	// ackfloor(0) and the last sequence for the stream. We will detect by looking for the time
	// to delete being 100x more. Should be the same since both times no messages exist in the stream.
	start = time.Now()
	err = js.DeleteConsumer("TEST", "c")
	require_NoError(t, err)

	if e := time.Since(start); e > 100*elapsed {
		t.Fatalf("Consumer delete took too long: %v vs baseline %v", e, elapsed)
	}
}

// Bug when we encode a timestamp that upon decode causes an error which causes server to panic.
// This can happen on consumer redelivery since they adjusted timstamps can be in the future, and result
// in a negative encoding. If that encoding was exactly -1 seconds, would cause decodeConsumerState to fail
// and the server to panic.
func TestNoRaceEncodeConsumerStateBug(t *testing.T) {
	for i := 0; i < 200_000; i++ {
		// Pretend we redelivered and updated the timestamp to reflect the new start time for expiration.
		// The bug will trip when time.Now() rounded to seconds in encode is 1 second below the truncated version
		// of pending.
		pending := Pending{Sequence: 1, Timestamp: time.Now().Add(time.Second).UnixNano()}
		state := ConsumerState{
			Delivered: SequencePair{Consumer: 1, Stream: 1},
			Pending:   map[uint64]*Pending{1: &pending},
		}
		buf := encodeConsumerState(&state)
		_, err := decodeConsumerState(buf)
		require_NoError(t, err)
	}
}

// Performance impact on stream ingress with large number of consumers.
func TestNoRaceJetStreamLargeNumConsumersPerfImpact(t *testing.T) {
	skip(t)

	s := RunBasicJetStreamServer(t)
	defer s.Shutdown()

	// Client for API requests.
	nc, js := jsClientConnect(t, s)
	defer nc.Close()

	_, err := js.AddStream(&nats.StreamConfig{
		Name:     "TEST",
		Subjects: []string{"foo"},
	})
	require_NoError(t, err)

	// Baseline with no consumers.
	toSend := 1_000_000
	start := time.Now()
	for i := 0; i < toSend; i++ {
		js.PublishAsync("foo", []byte("OK"))
	}
	<-js.PublishAsyncComplete()
	tt := time.Since(start)
	fmt.Printf("Base time is %v\n", tt)
	fmt.Printf("%.0f msgs/sec\n", float64(toSend)/tt.Seconds())

	err = js.PurgeStream("TEST")
	require_NoError(t, err)

	// Now add in 10 idle consumers.
	for i := 1; i <= 10; i++ {
		_, err := js.AddConsumer("TEST", &nats.ConsumerConfig{
			Durable:   fmt.Sprintf("d-%d", i),
			AckPolicy: nats.AckExplicitPolicy,
		})
		require_NoError(t, err)
	}

	start = time.Now()
	for i := 0; i < toSend; i++ {
		js.PublishAsync("foo", []byte("OK"))
	}
	<-js.PublishAsyncComplete()
	tt = time.Since(start)
	fmt.Printf("\n10 consumers time is %v\n", tt)
	fmt.Printf("%.0f msgs/sec\n", float64(toSend)/tt.Seconds())

	err = js.PurgeStream("TEST")
	require_NoError(t, err)

	// Now add in 90 more idle consumers.
	for i := 11; i <= 100; i++ {
		_, err := js.AddConsumer("TEST", &nats.ConsumerConfig{
			Durable:   fmt.Sprintf("d-%d", i),
			AckPolicy: nats.AckExplicitPolicy,
		})
		require_NoError(t, err)
	}

	start = time.Now()
	for i := 0; i < toSend; i++ {
		js.PublishAsync("foo", []byte("OK"))
	}
	<-js.PublishAsyncComplete()
	tt = time.Since(start)
	fmt.Printf("\n100 consumers time is %v\n", tt)
	fmt.Printf("%.0f msgs/sec\n", float64(toSend)/tt.Seconds())

	err = js.PurgeStream("TEST")
	require_NoError(t, err)

	// Now add in 900 more
	for i := 101; i <= 1000; i++ {
		_, err := js.AddConsumer("TEST", &nats.ConsumerConfig{
			Durable:   fmt.Sprintf("d-%d", i),
			AckPolicy: nats.AckExplicitPolicy,
		})
		require_NoError(t, err)
	}

	start = time.Now()
	for i := 0; i < toSend; i++ {
		js.PublishAsync("foo", []byte("OK"))
	}
	<-js.PublishAsyncComplete()
	tt = time.Since(start)
	fmt.Printf("\n1000 consumers time is %v\n", tt)
	fmt.Printf("%.0f msgs/sec\n", float64(toSend)/tt.Seconds())
}

// Performance impact on large number of consumers but sparse delivery.
func TestNoRaceJetStreamLargeNumConsumersSparseDelivery(t *testing.T) {
	skip(t)

	s := RunBasicJetStreamServer(t)
	defer s.Shutdown()

	// Client for API requests.
	nc, js := jsClientConnect(t, s)
	defer nc.Close()

	_, err := js.AddStream(&nats.StreamConfig{
		Name:     "TEST",
		Subjects: []string{"ID.*"},
	})
	require_NoError(t, err)

	// Now add in ~10k consumers on different subjects.
	for i := 3; i <= 10_000; i++ {
		_, err := js.AddConsumer("TEST", &nats.ConsumerConfig{
			Durable:       fmt.Sprintf("d-%d", i),
			FilterSubject: fmt.Sprintf("ID.%d", i),
			AckPolicy:     nats.AckNonePolicy,
		})
		require_NoError(t, err)
	}

	toSend := 100_000

	// Bind a consumer to ID.2.
	var received int
	done := make(chan bool)

	nc, js = jsClientConnect(t, s)
	defer nc.Close()

	mh := func(m *nats.Msg) {
		received++
		if received >= toSend {
			close(done)
		}
	}
	_, err = js.Subscribe("ID.2", mh)
	require_NoError(t, err)

	last := make(chan bool)
	_, err = js.Subscribe("ID.1", func(_ *nats.Msg) { close(last) })
	require_NoError(t, err)

	nc, _ = jsClientConnect(t, s)
	defer nc.Close()
	js, err = nc.JetStream(nats.PublishAsyncMaxPending(8 * 1024))
	require_NoError(t, err)

	start := time.Now()
	for i := 0; i < toSend; i++ {
		js.PublishAsync("ID.2", []byte("ok"))
	}
	// Check latency for this one message.
	// This will show the issue better than throughput which can bypass signal processing.
	js.PublishAsync("ID.1", []byte("ok"))

	select {
	case <-done:
		break
	case <-time.After(10 * time.Second):
		t.Fatalf("Failed to receive all messages: %d of %d\n", received, toSend)
	}

	tt := time.Since(start)
	fmt.Printf("Took %v to receive %d msgs\n", tt, toSend)
	fmt.Printf("%.0f msgs/s\n", float64(toSend)/tt.Seconds())

	select {
	case <-last:
		break
	case <-time.After(30 * time.Second):
		t.Fatalf("Failed to receive last message\n")
	}
	lt := time.Since(start)

	fmt.Printf("Took %v to receive last msg\n", lt)
}

func TestNoRaceJetStreamEndToEndLatency(t *testing.T) {
	s := RunBasicJetStreamServer(t)
	defer s.Shutdown()

	// Client for API requests.
	nc, js := jsClientConnect(t, s)
	defer nc.Close()

	_, err := js.AddStream(&nats.StreamConfig{
		Name:     "TEST",
		Subjects: []string{"foo"},
	})
	require_NoError(t, err)

	nc, js = jsClientConnect(t, s)
	defer nc.Close()

	var sent time.Time
	var max time.Duration
	next := make(chan struct{})

	mh := func(m *nats.Msg) {
		received := time.Now()
		tt := received.Sub(sent)
		if max == 0 || tt > max {
			max = tt
		}
		next <- struct{}{}
	}
	sub, err := js.Subscribe("foo", mh)
	require_NoError(t, err)

	nc, js = jsClientConnect(t, s)
	defer nc.Close()

	toSend := 50_000
	for i := 0; i < toSend; i++ {
		sent = time.Now()
		js.Publish("foo", []byte("ok"))
		<-next
	}
	sub.Unsubscribe()

	if max > 250*time.Millisecond {
		t.Fatalf("Expected max latency to be < 250ms, got %v", max)
	}
}

func TestNoRaceFileStoreStreamMaxAgePerformance(t *testing.T) {
	// Uncomment to run.
	skip(t)

	storeDir := t.TempDir()
	maxAge := 5 * time.Second

	fs, err := newFileStore(
		FileStoreConfig{StoreDir: storeDir},
		StreamConfig{Name: "MA",
			Subjects: []string{"foo.*"},
			MaxAge:   maxAge,
			Storage:  FileStorage},
	)
	require_NoError(t, err)
	defer fs.Stop()

	// Simulate a callback similar to consumers decrementing.
	var mu sync.RWMutex
	var pending int64

	fs.RegisterStorageUpdates(func(md, bd int64, seq uint64, subj string) {
		mu.Lock()
		defer mu.Unlock()
		pending += md
	})

	start, num, subj := time.Now(), 0, "foo.foo"

	timeout := start.Add(maxAge)
	for time.Now().Before(timeout) {
		// We will store in blocks of 100.
		for i := 0; i < 100; i++ {
			_, _, err := fs.StoreMsg(subj, nil, []byte("Hello World"))
			require_NoError(t, err)
			num++
		}
	}
	elapsed := time.Since(start)
	fmt.Printf("Took %v to store %d\n", elapsed, num)
	fmt.Printf("%.0f msgs/sec\n", float64(num)/elapsed.Seconds())

	// Now keep running for 2x longer knowing we are expiring messages in the background.
	// We want to see the effect on performance.

	start = time.Now()
	timeout = start.Add(maxAge * 2)

	for time.Now().Before(timeout) {
		// We will store in blocks of 100.
		for i := 0; i < 100; i++ {
			_, _, err := fs.StoreMsg(subj, nil, []byte("Hello World"))
			require_NoError(t, err)
			num++
		}
	}
	elapsed = time.Since(start)
	fmt.Printf("Took %v to store %d\n", elapsed, num)
	fmt.Printf("%.0f msgs/sec\n", float64(num)/elapsed.Seconds())
}

// Test for consumer create when the subject cardinality is high and the
// consumer is filtered with a wildcard that forces linear scans.
// We have an optimization to use in memory structures in filestore to speed up.
// Only if asking to scan all (DeliverAll).
func TestNoRaceJetStreamConsumerCreateTimeNumPending(t *testing.T) {
	s := RunBasicJetStreamServer(t)
	defer s.Shutdown()

	nc, js := jsClientConnect(t, s)
	defer nc.Close()

	_, err := js.AddStream(&nats.StreamConfig{
		Name:     "TEST",
		Subjects: []string{"events.>"},
	})
	require_NoError(t, err)

	n := 500_000
	msg := bytes.Repeat([]byte("X"), 8*1024)

	for i := 0; i < n; i++ {
		subj := fmt.Sprintf("events.%d", rand.Intn(100_000))
		js.PublishAsync(subj, msg)
	}
	select {
	case <-js.PublishAsyncComplete():
	case <-time.After(5 * time.Second):
	}

	// Should stay under 5ms now, but for Travis variability say 50ms.
	threshold := 50 * time.Millisecond

	start := time.Now()
	_, err = js.PullSubscribe("events.*", "dlc")
	require_NoError(t, err)
	if elapsed := time.Since(start); elapsed > threshold {
		t.Fatalf("Consumer create took longer than expected, %v vs %v", elapsed, threshold)
	}

	start = time.Now()
	_, err = js.PullSubscribe("events.99999", "xxx")
	require_NoError(t, err)
	if elapsed := time.Since(start); elapsed > threshold {
		t.Fatalf("Consumer create took longer than expected, %v vs %v", elapsed, threshold)
	}

	start = time.Now()
	_, err = js.PullSubscribe(">", "zzz")
	require_NoError(t, err)
	if elapsed := time.Since(start); elapsed > threshold {
		t.Fatalf("Consumer create took longer than expected, %v vs %v", elapsed, threshold)
	}
}

func TestNoRaceFileStoreNumPending(t *testing.T) {
	// No need for all permutations here.
	storeDir := t.TempDir()
	fcfg := FileStoreConfig{
		StoreDir:  storeDir,
		BlockSize: 2 * 1024, // Create many blocks on purpose.
	}
	fs, err := newFileStore(fcfg, StreamConfig{Name: "zzz", Subjects: []string{"*.*.*.*"}, Storage: FileStorage})
	require_NoError(t, err)
	defer fs.Stop()

	tokens := []string{"foo", "bar", "baz"}
	genSubj := func() string {
		return fmt.Sprintf("%s.%s.%s.%s",
			tokens[rand.Intn(len(tokens))],
			tokens[rand.Intn(len(tokens))],
			tokens[rand.Intn(len(tokens))],
			tokens[rand.Intn(len(tokens))],
		)
	}

	for i := 0; i < 50_000; i++ {
		subj := genSubj()
		_, _, err := fs.StoreMsg(subj, nil, []byte("Hello World"))
		require_NoError(t, err)
	}

	state := fs.State()

	// Scan one by one for sanity check against other calculations.
	sanityCheck := func(sseq uint64, filter string) SimpleState {
		t.Helper()
		var ss SimpleState
		var smv StoreMsg
		// For here we know 0 is invalid, set to 1.
		if sseq == 0 {
			sseq = 1
		}
		for seq := sseq; seq <= state.LastSeq; seq++ {
			sm, err := fs.LoadMsg(seq, &smv)
			if err != nil {
				t.Logf("Encountered error %v loading sequence: %d", err, seq)
				continue
			}
			if subjectIsSubsetMatch(sm.subj, filter) {
				ss.Msgs++
				ss.Last = seq
				if ss.First == 0 || seq < ss.First {
					ss.First = seq
				}
			}
		}
		return ss
	}

	check := func(sseq uint64, filter string) {
		t.Helper()
		np, lvs := fs.NumPending(sseq, filter, false)
		ss := fs.FilteredState(sseq, filter)
		sss := sanityCheck(sseq, filter)
		if lvs != state.LastSeq {
			t.Fatalf("Expected NumPending to return valid through last of %d but got %d", state.LastSeq, lvs)
		}
		if ss.Msgs != np {
			t.Fatalf("NumPending of %d did not match ss.Msgs of %d", np, ss.Msgs)
		}
		if ss != sss {
			t.Fatalf("Failed sanity check, expected %+v got %+v", sss, ss)
		}
	}

	sanityCheckLastOnly := func(sseq uint64, filter string) SimpleState {
		t.Helper()
		var ss SimpleState
		var smv StoreMsg
		// For here we know 0 is invalid, set to 1.
		if sseq == 0 {
			sseq = 1
		}
		seen := make(map[string]bool)
		for seq := state.LastSeq; seq >= sseq; seq-- {
			sm, err := fs.LoadMsg(seq, &smv)
			if err != nil {
				t.Logf("Encountered error %v loading sequence: %d", err, seq)
				continue
			}
			if !seen[sm.subj] && subjectIsSubsetMatch(sm.subj, filter) {
				ss.Msgs++
				if ss.Last == 0 {
					ss.Last = seq
				}
				if ss.First == 0 || seq < ss.First {
					ss.First = seq
				}
				seen[sm.subj] = true
			}
		}
		return ss
	}

	checkLastOnly := func(sseq uint64, filter string) {
		t.Helper()
		np, lvs := fs.NumPending(sseq, filter, true)
		ss := sanityCheckLastOnly(sseq, filter)
		if lvs != state.LastSeq {
			t.Fatalf("Expected NumPending to return valid through last of %d but got %d", state.LastSeq, lvs)
		}
		if ss.Msgs != np {
			t.Fatalf("NumPending of %d did not match ss.Msgs of %d", np, ss.Msgs)
		}
	}

	startSeqs := []uint64{0, 1, 2, 200, 444, 555, 2222, 8888, 12_345, 28_222, 33_456, 44_400, 49_999}
	checkSubs := []string{"foo.>", "*.bar.>", "foo.bar.*.baz", "*.bar.>", "*.foo.bar.*", "foo.foo.bar.baz"}

	for _, filter := range checkSubs {
		for _, start := range startSeqs {
			check(start, filter)
			checkLastOnly(start, filter)
		}
	}
}

func TestNoRaceParallelStreamAndConsumerCreation(t *testing.T) {
	s := RunBasicJetStreamServer(t)
	defer s.Shutdown()

	// stream config.
	scfg := &StreamConfig{
		Name:     "TEST",
		Subjects: []string{"foo", "bar"},
		MaxMsgs:  10,
		Storage:  FileStorage,
		Replicas: 1,
	}

	// Will do these direct against the low level API to really make
	// sure parallel creation ok.
	np := 1000
	startCh := make(chan bool)
	errCh := make(chan error, np)
	wg := sync.WaitGroup{}
	wg.Add(np)

	var streams sync.Map

	for i := 0; i < np; i++ {
		go func() {
			defer wg.Done()

			// Make them all fire at once.
			<-startCh

			if mset, err := s.GlobalAccount().addStream(scfg); err != nil {
				t.Logf("Stream create got an error: %v", err)
				errCh <- err
			} else {
				streams.Store(mset, true)
			}
		}()
	}
	time.Sleep(100 * time.Millisecond)
	close(startCh)
	wg.Wait()

	// Check for no errors.
	if len(errCh) > 0 {
		t.Fatalf("Expected no errors, got %d", len(errCh))
	}

	// Now make sure we really only created one stream.
	var numStreams int
	streams.Range(func(k, v any) bool {
		numStreams++
		return true
	})
	if numStreams > 1 {
		t.Fatalf("Expected only one stream to be really created, got %d out of %d attempts", numStreams, np)
	}

	// Also make sure we cleanup the inflight entries for streams.
	gacc := s.GlobalAccount()
	_, jsa, err := gacc.checkForJetStream()
	require_NoError(t, err)
	var numEntries int
	jsa.inflight.Range(func(k, v any) bool {
		numEntries++
		return true
	})
	if numEntries > 0 {
		t.Fatalf("Expected no inflight entries to be left over, got %d", numEntries)
	}

	// Now do consumers.
	mset, err := gacc.lookupStream("TEST")
	require_NoError(t, err)

	cfg := &ConsumerConfig{
		DeliverSubject: "to",
		Name:           "DLC",
		AckPolicy:      AckExplicit,
	}

	startCh = make(chan bool)
	errCh = make(chan error, np)
	wg.Add(np)

	var consumers sync.Map

	for i := 0; i < np; i++ {
		go func() {
			defer wg.Done()

			// Make them all fire at once.
			<-startCh

			if _, err = mset.addConsumer(cfg); err != nil {
				t.Logf("Consumer create got an error: %v", err)
				errCh <- err
			} else {
				consumers.Store(mset, true)
			}
		}()
	}
	time.Sleep(100 * time.Millisecond)
	close(startCh)
	wg.Wait()

	// Check for no errors.
	if len(errCh) > 0 {
		t.Fatalf("Expected no errors, got %d", len(errCh))
	}

	// Now make sure we really only created one stream.
	var numConsumers int
	consumers.Range(func(k, v any) bool {
		numConsumers++
		return true
	})
	if numConsumers > 1 {
		t.Fatalf("Expected only one consumer to be really created, got %d out of %d attempts", numConsumers, np)
	}
}

// This test ensures that outbound queues don't cause a run on
// memory when sending something to lots of clients.
func TestNoRaceClientOutboundQueueMemory(t *testing.T) {
	opts := DefaultOptions()
	s := RunServer(opts)
	defer s.Shutdown()

	var before runtime.MemStats
	var after runtime.MemStats

	var err error
	clients := make([]*nats.Conn, 50000)
	wait := &sync.WaitGroup{}
	wait.Add(len(clients))

	for i := 0; i < len(clients); i++ {
		clients[i], err = nats.Connect(fmt.Sprintf("nats://%s:%d", opts.Host, opts.Port), nats.InProcessServer(s))
		if err != nil {
			t.Fatalf("Error on connect: %v", err)
		}
		defer clients[i].Close()

		clients[i].Subscribe("test", func(m *nats.Msg) {
			wait.Done()
		})
	}

	runtime.GC()
	runtime.ReadMemStats(&before)

	nc, err := nats.Connect(fmt.Sprintf("nats://%s:%d", opts.Host, opts.Port), nats.InProcessServer(s))
	if err != nil {
		t.Fatalf("Error on connect: %v", err)
	}
	defer nc.Close()

	var m [48000]byte
	if err = nc.Publish("test", m[:]); err != nil {
		t.Fatal(err)
	}

	wait.Wait()

	runtime.GC()
	runtime.ReadMemStats(&after)

	hb, ha := float64(before.HeapAlloc), float64(after.HeapAlloc)
	ms := float64(len(m))
	diff := float64(ha) - float64(hb)
	inc := (diff / float64(hb)) * 100

	if inc > 10 {
		t.Logf("Message size:       %.1fKB\n", ms/1024)
		t.Logf("Subscribed clients: %d\n", len(clients))
		t.Logf("Heap allocs before: %.1fMB\n", hb/1024/1024)
		t.Logf("Heap allocs after:  %.1fMB\n", ha/1024/1024)
		t.Logf("Heap allocs delta:  %.1f%%\n", inc)

		t.Fatalf("memory increase was %.1f%% (should be <= 10%%)", inc)
	}
}

func TestNoRaceCheckAckFloorWithVeryLargeFirstSeqAndNewConsumers(t *testing.T) {
	s := RunBasicJetStreamServer(t)
	defer s.Shutdown()

	nc, _ := jsClientConnect(t, s)
	defer nc.Close()

	// Make sure to time bound here for the acksync call below.
	js, err := nc.JetStream(nats.MaxWait(200 * time.Millisecond))
	require_NoError(t, err)

	_, err = js.AddStream(&nats.StreamConfig{
		Name:      "TEST",
		Subjects:  []string{"wq-req"},
		Retention: nats.WorkQueuePolicy,
	})
	require_NoError(t, err)

	largeFirstSeq := uint64(1_200_000_000)
	err = js.PurgeStream("TEST", &nats.StreamPurgeRequest{Sequence: largeFirstSeq})
	require_NoError(t, err)
	si, err := js.StreamInfo("TEST")
	require_NoError(t, err)
	require_True(t, si.State.FirstSeq == largeFirstSeq)

	// Add a simple request to the stream.
	sendStreamMsg(t, nc, "wq-req", "HELP")

	sub, err := js.PullSubscribe("wq-req", "dlc")
	require_NoError(t, err)

	msgs, err := sub.Fetch(1)
	require_NoError(t, err)
	require_True(t, len(msgs) == 1)

	// The bug is around the checkAckFloor walking the sequences from current ackfloor
	// to the first sequence of the stream. We time bound the max wait with the js context
	// to 200ms. Since checkAckFloor is spinning and holding up processing of acks this will fail.
	// We will short circuit new consumers to fix this one.
	require_NoError(t, msgs[0].AckSync())

	// Now do again so we move past the new consumer with no ack floor situation.
	err = js.PurgeStream("TEST", &nats.StreamPurgeRequest{Sequence: 2 * largeFirstSeq})
	require_NoError(t, err)
	si, err = js.StreamInfo("TEST")
	require_NoError(t, err)
	require_True(t, si.State.FirstSeq == 2*largeFirstSeq)

	sendStreamMsg(t, nc, "wq-req", "MORE HELP")

	// We check this one directly for this use case.
	mset, err := s.GlobalAccount().lookupStream("TEST")
	require_NoError(t, err)
	o := mset.lookupConsumer("dlc")
	require_True(t, o != nil)

	// Purge will move the stream floor by default, so force into the situation where it is back to largeFirstSeq.
	// This will not trigger the new consumer logic, but will trigger a walk of the sequence space.
	// Fix will be to walk the lesser of the two linear spaces.
	o.mu.Lock()
	o.asflr = largeFirstSeq
	o.mu.Unlock()

	done := make(chan bool)
	go func() {
		o.checkAckFloor()
		done <- true
	}()

	select {
	case <-done:
		return
	case <-time.After(time.Second):
		t.Fatalf("Check ack floor taking too long!")
	}
}
