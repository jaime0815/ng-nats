// Copyright 2017-2023 The NATS Authors
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
	"crypto/tls"
	"errors"
	"fmt"
	"net/url"
	"reflect"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/nats-io/jwt/v2"
)

// FlagSnapshot captures the server options as specified by CLI flags at
// startup. This should not be modified once the server has started.
var FlagSnapshot *Options

type reloadContext struct {
	oldClusterPerms *RoutePermissions
}

// option is a hot-swappable configuration setting.
type option interface {
	// Apply the server option.
	Apply(server *Server)

	// IsLoggingChange indicates if this option requires reloading the logger.
	IsLoggingChange() bool

	// IsTraceLevelChange indicates if this option requires reloading cached trace level.
	// Clients store trace level separately.
	IsTraceLevelChange() bool

	// IsAuthChange indicates if this option requires reloading authorization.
	IsAuthChange() bool

	// IsTLSChange indicates if this option requires reloading TLS.
	IsTLSChange() bool

	// IsClusterPermsChange indicates if this option requires reloading
	// cluster permissions.
	IsClusterPermsChange() bool

	// IsJetStreamChange inidicates a change in the servers config for JetStream.
	// Account changes will be handled separately in reloadAuthorization.
	IsJetStreamChange() bool

	// Indicates a change in the server that requires publishing the server's statz
	IsStatszChange() bool
}

// noopOption is a base struct that provides default no-op behaviors.
type noopOption struct{}

func (n noopOption) IsLoggingChange() bool {
	return false
}

func (n noopOption) IsTraceLevelChange() bool {
	return false
}

func (n noopOption) IsAuthChange() bool {
	return false
}

func (n noopOption) IsTLSChange() bool {
	return false
}

func (n noopOption) IsClusterPermsChange() bool {
	return false
}

func (n noopOption) IsJetStreamChange() bool {
	return false
}

func (n noopOption) IsStatszChange() bool {
	return false
}

// loggingOption is a base struct that provides default option behaviors for
// logging-related options.
type loggingOption struct {
	noopOption
}

func (l loggingOption) IsLoggingChange() bool {
	return true
}

// traceLevelOption is a base struct that provides default option behaviors for
// tracelevel-related options.
type traceLevelOption struct {
	loggingOption
}

func (l traceLevelOption) IsTraceLevelChange() bool {
	return true
}

// traceOption implements the option interface for the `trace` setting.
type traceOption struct {
	traceLevelOption
	newValue bool
}

// Apply is a no-op because logging will be reloaded after options are applied.
func (t *traceOption) Apply(server *Server) {
	server.Noticef("Reloaded: trace = %v", t.newValue)
}

// traceOption implements the option interface for the `trace` setting.
type traceVerboseOption struct {
	traceLevelOption
	newValue bool
}

// Apply is a no-op because logging will be reloaded after options are applied.
func (t *traceVerboseOption) Apply(server *Server) {
	server.Noticef("Reloaded: trace_verbose = %v", t.newValue)
}

// debugOption implements the option interface for the `debug` setting.
type debugOption struct {
	loggingOption
	newValue bool
}

// Apply is mostly a no-op because logging will be reloaded after options are applied.
// However we will kick the raft nodes if they exist to reload.
func (d *debugOption) Apply(server *Server) {
	server.Noticef("Reloaded: debug = %v", d.newValue)
}

// logtimeOption implements the option interface for the `logtime` setting.
type logtimeOption struct {
	loggingOption
	newValue bool
}

// Apply is a no-op because logging will be reloaded after options are applied.
func (l *logtimeOption) Apply(server *Server) {
	server.Noticef("Reloaded: logtime = %v", l.newValue)
}

// logfileOption implements the option interface for the `log_file` setting.
type logfileOption struct {
	loggingOption
	newValue string
}

// Apply is a no-op because logging will be reloaded after options are applied.
func (l *logfileOption) Apply(server *Server) {
	server.Noticef("Reloaded: log_file = %v", l.newValue)
}

// syslogOption implements the option interface for the `syslog` setting.
type syslogOption struct {
	loggingOption
	newValue bool
}

// Apply is a no-op because logging will be reloaded after options are applied.
func (s *syslogOption) Apply(server *Server) {
	server.Noticef("Reloaded: syslog = %v", s.newValue)
}

// remoteSyslogOption implements the option interface for the `remote_syslog`
// setting.
type remoteSyslogOption struct {
	loggingOption
	newValue string
}

// Apply is a no-op because logging will be reloaded after options are applied.
func (r *remoteSyslogOption) Apply(server *Server) {
	server.Noticef("Reloaded: remote_syslog = %v", r.newValue)
}

// tlsOption implements the option interface for the `tls` setting.
type tlsOption struct {
	noopOption
	newValue *tls.Config
}

// Apply the tls change.
func (t *tlsOption) Apply(server *Server) {
	server.mu.Lock()
	tlsRequired := t.newValue != nil
	server.info.TLSRequired = tlsRequired && !server.getOpts().AllowNonTLS
	message := "disabled"
	if tlsRequired {
		server.info.TLSVerify = (t.newValue.ClientAuth == tls.RequireAndVerifyClientCert)
		message = "enabled"
	}
	server.mu.Unlock()
	server.Noticef("Reloaded: tls = %s", message)
}

func (t *tlsOption) IsTLSChange() bool {
	return true
}

// tlsTimeoutOption implements the option interface for the tls `timeout`
// setting.
type tlsTimeoutOption struct {
	noopOption
	newValue float64
}

// Apply is a no-op because the timeout will be reloaded after options are
// applied.
func (t *tlsTimeoutOption) Apply(server *Server) {
	server.Noticef("Reloaded: tls timeout = %v", t.newValue)
}

// tlsPinnedCertOption implements the option interface for the tls `pinned_certs` setting.
type tlsPinnedCertOption struct {
	noopOption
	newValue PinnedCertSet
}

// Apply is a no-op because the pinned certs will be reloaded after options are  applied.
func (t *tlsPinnedCertOption) Apply(server *Server) {
	server.Noticef("Reloaded: %d pinned_certs", len(t.newValue))
}

// authOption is a base struct that provides default option behaviors.
type authOption struct {
	noopOption
}

func (o authOption) IsAuthChange() bool {
	return true
}

// usernameOption implements the option interface for the `username` setting.
type usernameOption struct {
	authOption
}

// Apply is a no-op because authorization will be reloaded after options are
// applied.
func (u *usernameOption) Apply(server *Server) {
	server.Noticef("Reloaded: authorization username")
}

// passwordOption implements the option interface for the `password` setting.
type passwordOption struct {
	authOption
}

// Apply is a no-op because authorization will be reloaded after options are
// applied.
func (p *passwordOption) Apply(server *Server) {
	server.Noticef("Reloaded: authorization password")
}

// authorizationOption implements the option interface for the `token`
// authorization setting.
type authorizationOption struct {
	authOption
}

// Apply is a no-op because authorization will be reloaded after options are
// applied.
func (a *authorizationOption) Apply(server *Server) {
	server.Noticef("Reloaded: authorization token")
}

// authTimeoutOption implements the option interface for the authorization
// `timeout` setting.
type authTimeoutOption struct {
	noopOption // Not authOption because this is a no-op; will be reloaded with options.
	newValue   float64
}

// Apply is a no-op because the timeout will be reloaded after options are
// applied.
func (a *authTimeoutOption) Apply(server *Server) {
	server.Noticef("Reloaded: authorization timeout = %v", a.newValue)
}

// tagsOption implements the option interface for the `tags` setting.
type tagsOption struct {
	noopOption // Not authOption because this is a no-op; will be reloaded with options.
}

func (u *tagsOption) Apply(server *Server) {
	server.Noticef("Reloaded: tags")
}

func (u *tagsOption) IsStatszChange() bool {
	return true
}

// usersOption implements the option interface for the authorization `users`
// setting.
type usersOption struct {
	authOption
}

func (u *usersOption) Apply(server *Server) {
	server.Noticef("Reloaded: authorization users")
}

// nkeysOption implements the option interface for the authorization `users`
// setting.
type nkeysOption struct {
	authOption
}

func (u *nkeysOption) Apply(server *Server) {
	server.Noticef("Reloaded: authorization nkey users")
}

// maxConnOption implements the option interface for the `max_connections`
// setting.
type maxConnOption struct {
	noopOption
	newValue int
}

// Apply the max connections change by closing random connections til we are
// below the limit if necessary.
func (m *maxConnOption) Apply(server *Server) {
	server.mu.Lock()
	var (
		clients = make([]*client, len(server.clients))
		i       = 0
	)
	// Map iteration is random, which allows us to close random connections.
	for _, client := range server.clients {
		clients[i] = client
		i++
	}
	server.mu.Unlock()

	if m.newValue > 0 && len(clients) > m.newValue {
		// Close connections til we are within the limit.
		var (
			numClose = len(clients) - m.newValue
			closed   = 0
		)
		for _, client := range clients {
			client.maxConnExceeded()
			closed++
			if closed >= numClose {
				break
			}
		}
		server.Noticef("Closed %d connections to fall within max_connections", closed)
	}
	server.Noticef("Reloaded: max_connections = %v", m.newValue)
}

// pidFileOption implements the option interface for the `pid_file` setting.
type pidFileOption struct {
	noopOption
	newValue string
}

// Apply the setting by logging the pid to the new file.
func (p *pidFileOption) Apply(server *Server) {
	if p.newValue == "" {
		return
	}
	if err := server.logPid(); err != nil {
		server.Errorf("Failed to write pidfile: %v", err)
	}
	server.Noticef("Reloaded: pid_file = %v", p.newValue)
}

// portsFileDirOption implements the option interface for the `portFileDir` setting.
type portsFileDirOption struct {
	noopOption
	oldValue string
	newValue string
}

func (p *portsFileDirOption) Apply(server *Server) {
	server.deletePortsFile(p.oldValue)
	server.logPorts()
	server.Noticef("Reloaded: ports_file_dir = %v", p.newValue)
}

// maxControlLineOption implements the option interface for the
// `max_control_line` setting.
type maxControlLineOption struct {
	noopOption
	newValue int32
}

// Apply the setting by updating each client.
func (m *maxControlLineOption) Apply(server *Server) {
	mcl := int32(m.newValue)
	server.mu.Lock()
	for _, client := range server.clients {
		atomic.StoreInt32(&client.mcl, mcl)
	}
	server.mu.Unlock()
	server.Noticef("Reloaded: max_control_line = %d", mcl)
}

// maxPayloadOption implements the option interface for the `max_payload`
// setting.
type maxPayloadOption struct {
	noopOption
	newValue int32
}

// Apply the setting by updating the server info and each client.
func (m *maxPayloadOption) Apply(server *Server) {
	server.mu.Lock()
	server.info.MaxPayload = m.newValue
	for _, client := range server.clients {
		atomic.StoreInt32(&client.mpay, int32(m.newValue))
	}
	server.mu.Unlock()
	server.Noticef("Reloaded: max_payload = %d", m.newValue)
}

// pingIntervalOption implements the option interface for the `ping_interval`
// setting.
type pingIntervalOption struct {
	noopOption
	newValue time.Duration
}

// Apply is a no-op because the ping interval will be reloaded after options
// are applied.
func (p *pingIntervalOption) Apply(server *Server) {
	server.Noticef("Reloaded: ping_interval = %s", p.newValue)
}

// maxPingsOutOption implements the option interface for the `ping_max`
// setting.
type maxPingsOutOption struct {
	noopOption
	newValue int
}

// Apply is a no-op because the ping interval will be reloaded after options
// are applied.
func (m *maxPingsOutOption) Apply(server *Server) {
	server.Noticef("Reloaded: ping_max = %d", m.newValue)
}

// writeDeadlineOption implements the option interface for the `write_deadline`
// setting.
type writeDeadlineOption struct {
	noopOption
	newValue time.Duration
}

// Apply is a no-op because the write deadline will be reloaded after options
// are applied.
func (w *writeDeadlineOption) Apply(server *Server) {
	server.Noticef("Reloaded: write_deadline = %s", w.newValue)
}

// clientAdvertiseOption implements the option interface for the `client_advertise` setting.
type clientAdvertiseOption struct {
	noopOption
	newValue string
}

// Apply the setting by updating the server info and regenerate the infoJSON byte array.
func (c *clientAdvertiseOption) Apply(server *Server) {
	server.mu.Lock()
	server.setInfoHostPort()
	server.mu.Unlock()
	server.Noticef("Reload: client_advertise = %s", c.newValue)
}

// accountsOption implements the option interface.
// Ensure that authorization code is executed if any change in accounts
type accountsOption struct {
	authOption
}

// Apply is a no-op. Changes will be applied in reloadAuthorization
func (a *accountsOption) Apply(s *Server) {
	s.Noticef("Reloaded: accounts")
}

// For changes to a server's config.
type jetStreamOption struct {
	noopOption
	newValue bool
}

func (a *jetStreamOption) Apply(s *Server) {
	s.Noticef("Reloaded: JetStream")
}

func (jso jetStreamOption) IsJetStreamChange() bool {
	return true
}

func (jso jetStreamOption) IsStatszChange() bool {
	return true
}

type ocspOption struct {
	noopOption
	newValue *OCSPConfig
}

func (a *ocspOption) Apply(s *Server) {
	s.Noticef("Reloaded: OCSP")
}

// connectErrorReports implements the option interface for the `connect_error_reports`
// setting.
type connectErrorReports struct {
	noopOption
	newValue int
}

// Apply is a no-op because the value will be reloaded after options are applied.
func (c *connectErrorReports) Apply(s *Server) {
	s.Noticef("Reloaded: connect_error_reports = %v", c.newValue)
}

// connectErrorReports implements the option interface for the `connect_error_reports`
// setting.
type reconnectErrorReports struct {
	noopOption
	newValue int
}

// Apply is a no-op because the value will be reloaded after options are applied.
func (r *reconnectErrorReports) Apply(s *Server) {
	s.Noticef("Reloaded: reconnect_error_reports = %v", r.newValue)
}

// maxTracedMsgLenOption implements the option interface for the `max_traced_msg_len` setting.
type maxTracedMsgLenOption struct {
	noopOption
	newValue int
}

// Apply the setting by updating the maximum traced message length.
func (m *maxTracedMsgLenOption) Apply(server *Server) {
	server.mu.Lock()
	defer server.mu.Unlock()
	server.opts.MaxTracedMsgLen = m.newValue
	server.Noticef("Reloaded: max_traced_msg_len = %d", m.newValue)
}

// Compares options and disconnects clients that are no longer listed in pinned certs. Lock must not be held.
func (s *Server) recheckPinnedCerts(curOpts *Options, newOpts *Options) {
	s.mu.Lock()
	disconnectClients := []*client{}
	protoToPinned := map[int]PinnedCertSet{}

	for _, c := range s.clients {
		if c.kind != CLIENT {
			continue
		}
		if pinned, ok := protoToPinned[c.clientType()]; ok {
			if !c.matchesPinnedCert(pinned) {
				disconnectClients = append(disconnectClients, c)
			}
		}
	}

	s.mu.Unlock()
	if len(disconnectClients) > 0 {
		s.Noticef("Disconnect %d clients due to pinned certs reload", len(disconnectClients))
		for _, c := range disconnectClients {
			c.closeConnection(TLSHandshakeError)
		}
	}
}

// Reload reads the current configuration file and calls out to ReloadOptions
// to apply the changes. This returns an error if the server was not started
// with a config file or an option which doesn't support hot-swapping was changed.
func (s *Server) Reload() error {
	s.mu.Lock()
	configFile := s.configFile
	s.mu.Unlock()
	if configFile == "" {
		return errors.New("can only reload config when a file is provided using -c or --config")
	}

	newOpts, err := ProcessConfigFile(configFile)
	if err != nil {
		// TODO: Dump previous good config to a .bak file?
		return err
	}
	return s.ReloadOptions(newOpts)
}

// ReloadOptions applies any supported options from the provided Option
// type. This returns an error if an option which doesn't support
// hot-swapping was changed.
func (s *Server) ReloadOptions(newOpts *Options) error {
	s.mu.Lock()

	curOpts := s.getOpts()

	// Wipe trusted keys if needed when we have an operator.
	if len(curOpts.TrustedOperators) > 0 && len(curOpts.TrustedKeys) > 0 {
		curOpts.TrustedKeys = nil
	}

	clientOrgPort := curOpts.Port

	s.mu.Unlock()

	// Apply flags over config file settings.
	newOpts = MergeOptions(newOpts, FlagSnapshot)

	// Need more processing for boolean flags...
	if FlagSnapshot != nil {
		applyBoolFlags(newOpts, FlagSnapshot)
	}

	setBaselineOptions(newOpts)

	// setBaselineOptions sets Port to 0 if set to -1 (RANDOM port)
	// If that's the case, set it to the saved value when the accept loop was
	// created.
	if newOpts.Port == 0 {
		newOpts.Port = clientOrgPort
	}

	if err := s.reloadOptions(curOpts, newOpts); err != nil {
		return err
	}

	s.recheckPinnedCerts(curOpts, newOpts)

	s.mu.Lock()
	s.configTime = time.Now().UTC()
	s.updateVarzConfigReloadableFields(s.varz)
	s.mu.Unlock()
	return nil
}
func applyBoolFlags(newOpts, flagOpts *Options) {
	// Reset fields that may have been set to `true` in
	// MergeOptions() when some of the flags default to `true`
	// but have not been explicitly set and therefore value
	// from config file should take precedence.
	for name, val := range newOpts.inConfig {
		f := reflect.ValueOf(newOpts).Elem()
		names := strings.Split(name, ".")
		for _, name := range names {
			f = f.FieldByName(name)
		}
		f.SetBool(val)
	}
	// Now apply value (true or false) from flags that have
	// been explicitly set in command line
	for name, val := range flagOpts.inCmdLine {
		f := reflect.ValueOf(newOpts).Elem()
		names := strings.Split(name, ".")
		for _, name := range names {
			f = f.FieldByName(name)
		}
		f.SetBool(val)
	}
}

// reloadOptions reloads the server config with the provided options. If an
// option that doesn't support hot-swapping is changed, this returns an error.
func (s *Server) reloadOptions(curOpts, newOpts *Options) error {
	// Apply to the new options some of the options that may have been set
	// that can't be configured in the config file (this can happen in
	// applications starting NATS Server programmatically).
	newOpts.CustomClientAuthentication = curOpts.CustomClientAuthentication
	newOpts.CustomRouterAuthentication = curOpts.CustomRouterAuthentication

	changed, err := s.diffOptions(newOpts)
	if err != nil {
		return err
	}

	if len(changed) != 0 {
		if err := validateOptions(newOpts); err != nil {
			return err
		}
	}

	// while applying the new options.
	s.setOpts(newOpts)
	s.applyOptions(changed)
	return nil
}

// For the purpose of comparing, impose a order on slice data types where order does not matter
func imposeOrder(value interface{}) error {
	switch value := value.(type) {
	case []*Account:
		sort.Slice(value, func(i, j int) bool {
			return value[i].Name < value[j].Name
		})
		for _, a := range value {
			sort.Slice(a.imports.streams, func(i, j int) bool {
				return a.imports.streams[i].acc.Name < a.imports.streams[j].acc.Name
			})
		}
	case []*User:
		sort.Slice(value, func(i, j int) bool {
			return value[i].Username < value[j].Username
		})
	case []*NkeyUser:
		sort.Slice(value, func(i, j int) bool {
			return value[i].Nkey < value[j].Nkey
		})
	case []*url.URL:
		sort.Slice(value, func(i, j int) bool {
			return value[i].String() < value[j].String()
		})
	case []string:
		sort.Strings(value)
	case []*jwt.OperatorClaims:
		sort.Slice(value, func(i, j int) bool {
			return value[i].Issuer < value[j].Issuer
		})
	case string, bool, uint8, int, int32, int64, time.Duration, float64, nil, *tls.Config, PinnedCertSet,
		*URLAccResolver, *MemAccResolver, *DirAccResolver, *CacheDirAccResolver, Authentication, jwt.TagList,
		*OCSPConfig, map[string]string, JSLimitOpts, StoreCipher:
		// explicitly skipped types
	default:
		// this will fail during unit tests
		return fmt.Errorf("OnReload, sort or explicitly skip type: %s",
			reflect.TypeOf(value))
	}
	return nil
}

// diffOptions returns a slice containing options which have been changed. If
// an option that doesn't support hot-swapping is changed, this returns an
// error.
func (s *Server) diffOptions(newOpts *Options) ([]option, error) {
	var (
		oldConfig = reflect.ValueOf(s.getOpts()).Elem()
		newConfig = reflect.ValueOf(newOpts).Elem()
		diffOpts  = []option{}

		// Need to keep track of whether JS is being disabled
		// to prevent changing limits at runtime.
		jsEnabled           = s.JetStreamEnabled()
		disableJS           bool
		jsMemLimitsChanged  bool
		jsFileLimitsChanged bool
		jsStoreDirChanged   bool
	)
	for i := 0; i < oldConfig.NumField(); i++ {
		field := oldConfig.Type().Field(i)
		// field.PkgPath is empty for exported fields, and is not for unexported ones.
		// We skip the unexported fields.
		if field.PkgPath != _EMPTY_ {
			continue
		}
		var (
			oldValue = oldConfig.Field(i).Interface()
			newValue = newConfig.Field(i).Interface()
		)
		if err := imposeOrder(oldValue); err != nil {
			return nil, err
		}
		if err := imposeOrder(newValue); err != nil {
			return nil, err
		}

		optName := strings.ToLower(field.Name)
		// accounts and users (referencing accounts) will always differ as accounts
		// contain internal state, say locks etc..., so we don't bother here.
		// This also avoids races with atomic stats counters
		if optName != "accounts" && optName != "users" {
			if changed := !reflect.DeepEqual(oldValue, newValue); !changed {
				// Check to make sure we are running JetStream if we think we should be.
				if optName == "jetstream" && newValue.(bool) {
					if !jsEnabled {
						diffOpts = append(diffOpts, &jetStreamOption{newValue: true})
					}
				}
				continue
			}
		}
		switch optName {
		case "traceverbose":
			diffOpts = append(diffOpts, &traceVerboseOption{newValue: newValue.(bool)})
		case "trace":
			diffOpts = append(diffOpts, &traceOption{newValue: newValue.(bool)})
		case "debug":
			diffOpts = append(diffOpts, &debugOption{newValue: newValue.(bool)})
		case "logtime":
			diffOpts = append(diffOpts, &logtimeOption{newValue: newValue.(bool)})
		case "logfile":
			diffOpts = append(diffOpts, &logfileOption{newValue: newValue.(string)})
		case "syslog":
			diffOpts = append(diffOpts, &syslogOption{newValue: newValue.(bool)})
		case "remotesyslog":
			diffOpts = append(diffOpts, &remoteSyslogOption{newValue: newValue.(string)})
		case "tlsconfig":
			diffOpts = append(diffOpts, &tlsOption{newValue: newValue.(*tls.Config)})
		case "tlstimeout":
			diffOpts = append(diffOpts, &tlsTimeoutOption{newValue: newValue.(float64)})
		case "tlspinnedcerts":
			diffOpts = append(diffOpts, &tlsPinnedCertOption{newValue: newValue.(PinnedCertSet)})
		case "username":
			diffOpts = append(diffOpts, &usernameOption{})
		case "password":
			diffOpts = append(diffOpts, &passwordOption{})
		case "tags":
			diffOpts = append(diffOpts, &tagsOption{})
		case "authorization":
			diffOpts = append(diffOpts, &authorizationOption{})
		case "authtimeout":
			diffOpts = append(diffOpts, &authTimeoutOption{newValue: newValue.(float64)})
		case "users":
			diffOpts = append(diffOpts, &usersOption{})
		case "nkeys":
			diffOpts = append(diffOpts, &nkeysOption{})
		case "maxconn":
			diffOpts = append(diffOpts, &maxConnOption{newValue: newValue.(int)})
		case "pidfile":
			diffOpts = append(diffOpts, &pidFileOption{newValue: newValue.(string)})
		case "portsfiledir":
			diffOpts = append(diffOpts, &portsFileDirOption{newValue: newValue.(string), oldValue: oldValue.(string)})
		case "maxcontrolline":
			diffOpts = append(diffOpts, &maxControlLineOption{newValue: newValue.(int32)})
		case "maxpayload":
			diffOpts = append(diffOpts, &maxPayloadOption{newValue: newValue.(int32)})
		case "pinginterval":
			diffOpts = append(diffOpts, &pingIntervalOption{newValue: newValue.(time.Duration)})
		case "maxpingsout":
			diffOpts = append(diffOpts, &maxPingsOutOption{newValue: newValue.(int)})
		case "writedeadline":
			diffOpts = append(diffOpts, &writeDeadlineOption{newValue: newValue.(time.Duration)})
		case "clientadvertise":
			cliAdv := newValue.(string)
			if cliAdv != "" {
				// Validate ClientAdvertise syntax
				if _, _, err := parseHostPort(cliAdv, 0); err != nil {
					return nil, fmt.Errorf("invalid ClientAdvertise value of %s, err=%v", cliAdv, err)
				}
			}
			diffOpts = append(diffOpts, &clientAdvertiseOption{newValue: cliAdv})
		case "accounts":
			diffOpts = append(diffOpts, &accountsOption{})
		case "resolver", "accountresolver", "accountsresolver":
			// We can't move from no resolver to one. So check for that.
			if (oldValue == nil && newValue != nil) ||
				(oldValue != nil && newValue == nil) {
				return nil, fmt.Errorf("config reload does not support moving to or from an account resolver")
			}
			diffOpts = append(diffOpts, &accountsOption{})
		case "accountresolvertlsconfig":
			diffOpts = append(diffOpts, &accountsOption{})
		case "jetstream":
			new := newValue.(bool)
			old := oldValue.(bool)
			if new != old {
				diffOpts = append(diffOpts, &jetStreamOption{newValue: new})
			}

			// Mark whether JS will be disabled.
			disableJS = !new
		case "storedir":
			new := newValue.(string)
			old := oldValue.(string)
			modified := new != old

			// Check whether JS is being disabled and/or storage dir attempted to change.
			if jsEnabled && modified {
				if new == _EMPTY_ {
					// This means that either JS is being disabled or it is using an temp dir.
					// Allow the change but error in case JS was not disabled.
					jsStoreDirChanged = true
				} else {
					return nil, fmt.Errorf("config reload not supported for jetstream storage directory")
				}
			}
		case "jetstreammaxmemory", "jetstreammaxstore":
			old := oldValue.(int64)
			new := newValue.(int64)

			// Check whether JS is being disabled and/or limits are being changed.
			var (
				modified  = new != old
				fromUnset = old == -1
				fromSet   = !fromUnset
				toUnset   = new == -1
				toSet     = !toUnset
			)
			if jsEnabled && modified {
				// Cannot change limits from dynamic storage at runtime.
				switch {
				case fromSet && toUnset:
					// Limits changed but it may mean that JS is being disabled,
					// keep track of the change and error in case it is not.
					switch optName {
					case "jetstreammaxmemory":
						jsMemLimitsChanged = true
					case "jetstreammaxstore":
						jsFileLimitsChanged = true
					default:
						return nil, fmt.Errorf("config reload not supported for jetstream max memory and store")
					}
				case fromUnset && toSet:
					// Prevent changing from dynamic max memory / file at runtime.
					return nil, fmt.Errorf("config reload not supported for jetstream dynamic max memory and store")
				default:
					return nil, fmt.Errorf("config reload not supported for jetstream max memory and store")
				}
			}

		case "connecterrorreports":
			diffOpts = append(diffOpts, &connectErrorReports{newValue: newValue.(int)})
		case "reconnecterrorreports":
			diffOpts = append(diffOpts, &reconnectErrorReports{newValue: newValue.(int)})
		case "nolog", "nosigs":
			// Ignore NoLog and NoSigs options since they are not parsed and only used in
			// testing.
			continue
		case "disableshortfirstping":
			newOpts.DisableShortFirstPing = oldValue.(bool)
			continue
		case "maxtracedmsglen":
			diffOpts = append(diffOpts, &maxTracedMsgLenOption{newValue: newValue.(int)})
		case "port":
			// check to see if newValue == 0 and continue if so.
			if newValue == 0 {
				// ignore RANDOM_PORT
				continue
			}
			fallthrough
		case "noauthuser":
			if oldValue != _EMPTY_ && newValue == _EMPTY_ {
				for _, user := range newOpts.Users {
					if user.Username == oldValue {
						return nil, fmt.Errorf("config reload not supported for %s: old=%v, new=%v",
							field.Name, oldValue, newValue)
					}
				}
			} else {
				return nil, fmt.Errorf("config reload not supported for %s: old=%v, new=%v",
					field.Name, oldValue, newValue)
			}
		case "systemaccount":
			if oldValue != DEFAULT_SYSTEM_ACCOUNT || newValue != _EMPTY_ {
				return nil, fmt.Errorf("config reload not supported for %s: old=%v, new=%v",
					field.Name, oldValue, newValue)
			}
		case "ocspconfig":
			diffOpts = append(diffOpts, &ocspOption{newValue: newValue.(*OCSPConfig)})
		default:
			// TODO(ik): Implement String() on those options to have a nice print.
			// %v is difficult to figure what's what, %+v print private fields and
			// would print passwords. Tried json.Marshal but it is too verbose for
			// the URL array.

			// Bail out if attempting to reload any unsupported options.
			return nil, fmt.Errorf("config reload not supported for %s: old=%v, new=%v",
				field.Name, oldValue, newValue)
		}
	}

	// If not disabling JS but limits have changed then it is an error.
	if !disableJS {
		if jsMemLimitsChanged || jsFileLimitsChanged {
			return nil, fmt.Errorf("config reload not supported for jetstream max memory and max store")
		}
		if jsStoreDirChanged {
			return nil, fmt.Errorf("config reload not supported for jetstream storage dir")
		}
	}

	return diffOpts, nil
}

func (s *Server) applyOptions(opts []option) {
	var (
		reloadLogging      = false
		reloadAuth         = false
		reloadClientTrcLvl = false
		reloadJetstream    = false
		jsEnabled          = false
		reloadTLS          = false
		isStatszChange     = false
	)
	for _, opt := range opts {
		opt.Apply(s)
		if opt.IsLoggingChange() {
			reloadLogging = true
		}
		if opt.IsTraceLevelChange() {
			reloadClientTrcLvl = true
		}
		if opt.IsAuthChange() {
			reloadAuth = true
		}
		if opt.IsTLSChange() {
			reloadTLS = true
		}
		if opt.IsJetStreamChange() {
			reloadJetstream = true
			jsEnabled = opt.(*jetStreamOption).newValue
		}
		if opt.IsStatszChange() {
			isStatszChange = true
		}
	}

	if reloadLogging {
		s.ConfigureLogger()
	}
	if reloadClientTrcLvl {
		s.reloadClientTraceLevel()
	}
	if reloadAuth {
		s.reloadAuthorization()
	}

	if reloadJetstream {
		if !jsEnabled {
			s.DisableJetStream()
		} else if !s.JetStreamEnabled() {
			if err := s.restartJetStream(); err != nil {
				s.Warnf("Can't start JetStream: %v", err)
			}
		}
		// Make sure to reset the internal loop's version of JS.
		s.resetInternalLoopInfo()
	}
	if isStatszChange {
		s.sendStatszUpdate()
	}

	if reloadTLS {
		// Restart OCSP monitoring.
		if err := s.reloadOCSP(); err != nil {
			s.Warnf("Can't restart OCSP Stapling: %v", err)
		}
	}

	s.Noticef("Reloaded server configuration")
}

// This will send a reset to the internal send loop.
func (s *Server) resetInternalLoopInfo() {
	var resetCh chan struct{}
	s.mu.Lock()
	if s.sys != nil {
		// can't hold the lock as go routine reading it may be waiting for lock as well
		resetCh = s.sys.resetCh
	}
	s.mu.Unlock()

	if resetCh != nil {
		resetCh <- struct{}{}
	}
}

// Update all cached debug and trace settings for every client
func (s *Server) reloadClientTraceLevel() {
	opts := s.getOpts()

	if opts.NoLog {
		return
	}

	// Create a list of all clients.
	// Update their trace level when not holding server or gateway lock

	s.mu.Lock()
	clientCnt := 1 + len(s.clients) + len(s.grTmpClients)
	s.mu.Unlock()

	clients := make([]*client, 0, clientCnt)

	s.mu.Lock()
	if s.eventsEnabled() {
		clients = append(clients, s.sys.client)
	}

	cMaps := []map[uint64]*client{s.clients, s.grTmpClients}
	for _, m := range cMaps {
		for _, c := range m {
			clients = append(clients, c)
		}
	}
	s.mu.Unlock()

	for _, c := range clients {
		// client.trace is commonly read while holding the lock
		c.mu.Lock()
		c.setTraceLevel()
		c.mu.Unlock()
	}
}

// reloadAuthorization reconfigures the server authorization settings,
// disconnects any clients who are no longer authorized, and removes any
// unauthorized subscriptions.
func (s *Server) reloadAuthorization() {
	// This map will contain the names of accounts that have their streams
	// import configuration changed.
	var awcsti map[string]struct{}
	checkJetStream := false
	opts := s.getOpts()
	s.mu.Lock()

	deletedAccounts := make(map[string]*Account)

	// This can not be changed for now so ok to check server's trustedKeys unlocked.
	// If plain configured accounts, process here.
	if s.trustedKeys == nil {
		// Make a map of the configured account names so we figure out the accounts
		// that should be removed later on.
		configAccs := make(map[string]struct{}, len(opts.Accounts))
		for _, acc := range opts.Accounts {
			configAccs[acc.GetName()] = struct{}{}
		}
		// Now range over existing accounts and keep track of the ones deleted
		// so some cleanup can be made after releasing the server lock.
		s.accounts.Range(func(k, v interface{}) bool {
			an, acc := k.(string), v.(*Account)
			// Exclude default and system account from this test since those
			// may not actually be in opts.Accounts.
			if an == DEFAULT_GLOBAL_ACCOUNT || an == DEFAULT_SYSTEM_ACCOUNT {
				return true
			}
			// Check check if existing account is still in opts.Accounts.
			if _, ok := configAccs[an]; !ok {
				deletedAccounts[an] = acc
				s.accounts.Delete(k)
			}
			return true
		})
		// This will update existing and add new ones.
		awcsti, _ = s.configureAccounts(true)
		s.configureAuthorization()
		// Double check any JetStream configs.
		checkJetStream = s.js != nil
	} else if opts.AccountResolver != nil {
		s.configureResolver()
		if _, ok := s.accResolver.(*MemAccResolver); ok {
			// Check preloads so we can issue warnings etc if needed.
			s.checkResolvePreloads()
			// With a memory resolver we want to do something similar to configured accounts.
			// We will walk the accounts and delete them if they are no longer present via fetch.
			// If they are present we will force a claim update to process changes.
			s.accounts.Range(func(k, v interface{}) bool {
				acc := v.(*Account)
				// Skip global account.
				if acc == s.gacc {
					return true
				}
				accName := acc.GetName()
				// Release server lock for following actions
				s.mu.Unlock()
				accClaims, claimJWT, _ := s.fetchAccountClaims(accName)
				if accClaims != nil {
					if err := s.updateAccountWithClaimJWT(acc, claimJWT); err != nil {
						s.Noticef("Reloaded: deleting account [bad claims]: %q", accName)
						s.accounts.Delete(k)
					}
				} else {
					s.Noticef("Reloaded: deleting account [removed]: %q", accName)
					s.accounts.Delete(k)
				}
				// Regrab server lock.
				s.mu.Lock()
				return true
			})
		}
	}

	var (
		cclientsa [64]*client
		cclients  = cclientsa[:0]
		clientsa  [64]*client
		clients   = clientsa[:0]
	)

	// Gather clients that changed accounts. We will close them and they
	// will reconnect, doing the right thing.
	for _, client := range s.clients {
		if s.clientHasMovedToDifferentAccount(client) {
			cclients = append(cclients, client)
		} else {
			clients = append(clients, client)
		}
	}

	// Check here for any system/internal clients which will not be in the servers map of normal clients.
	if s.sys != nil && s.sys.account != nil && !opts.NoSystemAccount {
		s.accounts.Store(s.sys.account.Name, s.sys.account)
	}

	s.accounts.Range(func(k, v interface{}) bool {
		acc := v.(*Account)
		acc.mu.RLock()
		// Check for sysclients accounting, ignore the system account.
		if acc.sysclients > 0 && (s.sys == nil || s.sys.account != acc) {
			for c := range acc.clients {
				if c.kind != CLIENT {
					clients = append(clients, c)
				}
			}
		}
		acc.mu.RUnlock()
		return true
	})

	var resetCh chan struct{}
	if s.sys != nil {
		// can't hold the lock as go routine reading it may be waiting for lock as well
		resetCh = s.sys.resetCh
	}
	s.mu.Unlock()

	// Clear some timers and remove service import subs for deleted accounts.
	for _, acc := range deletedAccounts {
		acc.mu.Lock()
		clearTimer(&acc.etmr)
		clearTimer(&acc.ctmr)
		for _, se := range acc.exports.services {
			se.clearResponseThresholdTimer()
		}
		acc.mu.Unlock()
		acc.removeAllServiceImportSubs()
	}

	if resetCh != nil {
		resetCh <- struct{}{}
	}

	// Close clients that have moved accounts
	for _, client := range cclients {
		client.closeConnection(ClientClosed)
	}

	for _, c := range clients {
		// Disconnect any unauthorized clients.
		// Ignore internal clients.
		if c.kind == CLIENT && !s.isClientAuthorized(c) {
			c.authViolation()
			continue
		}
		// Check to make sure account is correct.
		c.swapAccountAfterReload()
		// Remove any unauthorized subscriptions and check for account imports.
		c.processSubsOnConfigReload(awcsti)
	}

	if res := s.AccountResolver(); res != nil {
		res.Reload()
	}

	// We will double check all JetStream configs on a reload.
	if checkJetStream {
		if err := s.enableJetStreamAccounts(); err != nil {
			s.Errorf(err.Error())
		}
	}
}

// Returns true if given client current account has changed (or user
// no longer exist) in the new config, false if the user did not
// change accounts.
// Server lock is held on entry.
func (s *Server) clientHasMovedToDifferentAccount(c *client) bool {
	var (
		nu *NkeyUser
		u  *User
	)
	if c.opts.Nkey != "" {
		if s.nkeys != nil {
			nu = s.nkeys[c.opts.Nkey]
		}
	} else if c.opts.Username != "" {
		if s.users != nil {
			u = s.users[c.opts.Username]
		}
	} else {
		return false
	}
	// Get the current account name
	c.mu.Lock()
	var curAccName string
	if c.acc != nil {
		curAccName = c.acc.Name
	}
	c.mu.Unlock()
	if nu != nil && nu.Account != nil {
		return curAccName != nu.Account.Name
	} else if u != nil && u.Account != nil {
		return curAccName != u.Account.Name
	}
	// user/nkey no longer exists.
	return true
}
