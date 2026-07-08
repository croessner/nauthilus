// Copyright (C) 2026 Christian Roessner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

package main

import (
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	pluginapi "github.com/croessner/nauthilus/v3/pluginapi/v1"
	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/lualib/smtp"
	"github.com/croessner/nauthilus/v3/server/pluginregistry"
	"github.com/croessner/nauthilus/v3/server/pluginruntime"
	"github.com/croessner/nauthilus/v3/server/rediscli"

	"github.com/go-redis/redismock/v9"
)

const (
	testAPIBaseURL    = "https://hibp.example.test/range/"
	testAccount       = "alice@example.test"
	testSecret        = "correct horse battery staple"
	testRedisPool     = "legacy_pool"
	testResponseBody  = "secret-response-body"
	testRedisCount    = 23
	testHTTPCount     = 42
	testMissingSuffix = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
	testMailSubject   = "Password leak detected"
	testMailBody      = "rendered mail body"
	testMailRawError  = "transport leaked alice@example.test smtp-secret rendered mail body"
)

func TestPluginMetadataAndRegistrationExposePostActionTarget(t *testing.T) {
	metadata := NewPlugin().Metadata()
	if metadata.Name != pluginName {
		t.Fatalf("metadata name = %q, want %q", metadata.Name, pluginName)
	}

	if metadata.APIVersion != pluginapi.APIVersion {
		t.Fatalf("metadata API version = %q, want %q", metadata.APIVersion, pluginapi.APIVersion)
	}

	if !slices.Contains(metadata.Features, pluginapi.Feature("post_action")) {
		t.Fatalf("metadata features = %#v, want post_action", metadata.Features)
	}

	if !slices.Contains(metadata.Capabilities, pluginapi.CapabilityCredentials) {
		t.Fatalf("metadata capabilities = %#v, want credentials", metadata.Capabilities)
	}

	if !slices.Contains(metadata.Capabilities, pluginapi.CapabilityMail) {
		t.Fatalf("metadata capabilities = %#v, want mail", metadata.Capabilities)
	}

	registry, _, _ := registerTestPlugin(t, testModule(map[string]any{}, true))
	targets := registry.PostActionTargets()

	if len(targets) != 1 {
		t.Fatalf("post-action targets = %d, want 1", len(targets))
	}

	if targets[0].QualifiedName != "haveibeenpwnd.post_action" {
		t.Fatalf("qualified target = %q, want haveibeenpwnd.post_action", targets[0].QualifiedName)
	}
}

func TestRegisterRequiresCredentialsCapability(t *testing.T) {
	registry := pluginregistry.NewRegistry()
	registrar := registry.NewRegistrar(testModule(map[string]any{}, false))

	if err := NewPlugin().Register(registrar); err == nil {
		t.Fatal("Register() error = nil, want credentials capability error")
	}

	registry = pluginregistry.NewRegistry()
	registrar = registry.NewRegistrar(testModule(map[string]any{}, true))

	if err := NewPlugin().Register(registrar); err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	capabilities := registrar.Capabilities()
	if len(capabilities) != 1 || capabilities[0] != pluginapi.CapabilityCredentials {
		t.Fatalf("Capabilities() = %#v, want credentials", capabilities)
	}
}

func TestRegisterRequiresMailCapabilityOnlyWhenMailEnabled(t *testing.T) {
	moduleConfig := map[string]any{
		"mail": map[string]any{"enabled": true},
	}

	registry := pluginregistry.NewRegistry()
	registrar := registry.NewRegistrar(testModule(moduleConfig, true))

	if err := NewPlugin().Register(registrar); err == nil {
		t.Fatal("Register() error = nil, want mail capability error")
	}

	registry = pluginregistry.NewRegistry()
	registrar = registry.NewRegistrar(testModuleWithCapabilities(
		moduleConfig,
		pluginapi.CapabilityCredentials,
		pluginapi.CapabilityMail,
	))

	if err := NewPlugin().Register(registrar); err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	capabilities := registrar.Capabilities()
	if !slices.Equal(capabilities, []pluginapi.Capability{pluginapi.CapabilityCredentials, pluginapi.CapabilityMail}) {
		t.Fatalf("Capabilities() = %#v, want credentials and mail", capabilities)
	}
}

func TestReconfigureCannotEnableMailWithoutActiveCapability(t *testing.T) {
	_, plugin, _ := registerTestPlugin(t, testModule(map[string]any{}, true))

	err := plugin.Reconfigure(context.Background(), pluginregistry.NewConfigView(map[string]any{
		"mail": map[string]any{"enabled": true},
	}))
	if !errors.Is(err, errMailCapabilityNotActive) {
		t.Fatalf("Reconfigure() error = %v, want errMailCapabilityNotActive", err)
	}
}

func TestConfigDefaultsAndBuiltinMailTemplate(t *testing.T) {
	cfg, err := decodeModuleConfig(pluginregistry.NewConfigView(nil))
	if err != nil {
		t.Fatalf("decodeModuleConfig(defaults) error = %v", err)
	}

	if cfg.APIBaseURL != defaultAPIBaseURL || cfg.RedisPool != defaultRedisPool || cfg.HTTPTimeout != defaultHTTPTimeout {
		t.Fatalf("defaults = %#v", cfg)
	}

	if cfg.Mail.Enabled {
		t.Fatal("default mail enabled = true, want false")
	}

	assertRenderedMail(t, cfg.Mail, mailTemplateData{
		Account:    testAccount,
		HashPrefix: "abcde",
		Count:      testHTTPCount,
		Website:    "https://ssp.example.test",
		Timestamp:  time.Unix(1, 0).UTC(),
	}, []string{
		"Hello,",
		"Account: " + testAccount,
		"Hash: abcde",
		"Count: 42",
		"website: https://ssp.example.test",
	}, "Password leak detected for your account <"+testAccount+">")
}

func TestConfigValidationAndCustomSubjectTemplate(t *testing.T) {
	valid, err := decodeModuleConfig(pluginregistry.NewConfigView(map[string]any{
		"redis_pool":              testRedisPool,
		"api_base_url":            "https://hibp.example.test/range",
		"http_timeout":            "250ms",
		"http_max_response_bytes": int64(512),
		"cache_positive_ttl":      "2h",
		"cache_negative_ttl":      "15m",
		"redis_positive_ttl":      "3h",
		"redis_negative_ttl":      "48h",
		"gate_ttl":                "45s",
		"mail": map[string]any{
			"enabled":          false,
			"use_lmtp":         true,
			"server":           "mail.example.test",
			"port":             2525,
			"helo_name":        "nauthilus.example.test",
			"tls":              true,
			"starttls":         true,
			"username":         "smtp-user",
			"password":         "smtp-secret",
			"mail_from":        "postmaster@example.test",
			"website":          "https://ssp.example.test",
			"subject_template": "Leaked password for {{ .Account }}",
		},
	}))
	if err != nil {
		t.Fatalf("decodeModuleConfig(valid) error = %v", err)
	}

	if valid.RedisPool != testRedisPool || valid.APIBaseURL != testAPIBaseURL || valid.Mail.Port != 2525 {
		t.Fatalf("valid config = %#v", valid)
	}

	if valid.Mail.Enabled {
		t.Fatal("valid mail enabled = true, want false")
	}

	assertRenderedMail(t, valid.Mail, mailTemplateData{Account: testAccount}, nil, "Leaked password for "+testAccount)
}

func TestConfigMailEnabledNoLongerFailsDecode(t *testing.T) {
	enabled, err := decodeModuleConfig(pluginregistry.NewConfigView(map[string]any{
		"mail": map[string]any{"enabled": true},
	}))
	if err != nil {
		t.Fatalf("decodeModuleConfig(mail enabled) error = %v", err)
	}

	if !enabled.Mail.Enabled {
		t.Fatal("enabled mail config did not enable mail")
	}
}

func TestCustomTemplatePathIsParsedBeforeConfigSwap(t *testing.T) {
	templatePath := writeMailTemplate(t, "custom {{ .Account }} {{ .HashPrefix }} {{ .Count }} {{ .Website }}")
	plugin := NewPlugin()
	module := testModuleWithCapabilities(map[string]any{
		"mail": map[string]any{
			"enabled":       true,
			"template_path": templatePath,
			"website":       "https://initial.example.test",
		},
	}, pluginapi.CapabilityCredentials, pluginapi.CapabilityMail)

	registry := pluginregistry.NewRegistry()

	registrar := registry.NewRegistrar(module)
	if err := plugin.Register(registrar); err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	state := plugin.snapshot()
	assertRenderedMail(t, state.config.Mail, mailTemplateData{
		Account:    testAccount,
		HashPrefix: "abcde",
		Count:      testHTTPCount,
		Website:    state.config.Mail.Website,
		Timestamp:  time.Unix(1, 0).UTC(),
	}, []string{"custom " + testAccount + " abcde 42 https://initial.example.test"}, "Password leak detected for your account <"+testAccount+">")

	missingPath := filepath.Join(t.TempDir(), "missing.tmpl")

	err := plugin.Reconfigure(context.Background(), pluginregistry.NewConfigView(map[string]any{
		"mail": map[string]any{
			"enabled":       true,
			"template_path": missingPath,
			"website":       "https://bad.example.test",
		},
	}))
	if err == nil {
		t.Fatal("Reconfigure() error = nil, want template path error")
	}

	if strings.Contains(err.Error(), missingPath) {
		t.Fatalf("Reconfigure() leaked template path in error: %v", err)
	}

	if got := plugin.snapshot().config.Mail.Website; got != "https://initial.example.test" {
		t.Fatalf("mail website after failed reconfigure = %q, want initial value", got)
	}
}

func TestMailTemplateDataOnlyContainsBoundedFields(t *testing.T) {
	dataType := reflect.TypeOf(mailTemplateData{})
	wantFields := []string{"Account", "HashPrefix", "Count", "Website", "Timestamp"}

	if dataType.NumField() != len(wantFields) {
		t.Fatalf("mailTemplateData field count = %d, want %d", dataType.NumField(), len(wantFields))
	}

	for _, fieldName := range wantFields {
		if _, ok := dataType.FieldByName(fieldName); !ok {
			t.Fatalf("mailTemplateData missing field %s", fieldName)
		}
	}
}

func TestUnauthenticatedAndNoAuthRequestsSkipWithoutHTTP(t *testing.T) {
	harness := startTestPlugin(t, map[string]any{"api_base_url": testAPIBaseURL}, testPluginOptions{})
	defer harness.stop(t)

	cases := []requestOptions{
		{authenticated: false},
		{authenticated: true, noAuth: true},
	}
	for _, tc := range cases {
		result, err := harness.target.enqueueWithCredentials(context.Background(), testRequest(t, tc), testCredentials(testSecret))
		if err != nil {
			t.Fatalf("enqueueWithCredentials(%#v) error = %v", tc, err)
		}

		if result.Enqueued {
			t.Fatalf("enqueueWithCredentials(%#v) enqueued skipped request", tc)
		}
	}

	if got := len(harness.transport.requests); got != 0 {
		t.Fatalf("HTTP calls = %d, want 0", got)
	}
}

func TestNilOrZeroCredentialsSkipWithoutHTTP(t *testing.T) {
	harness := startTestPlugin(t, map[string]any{"api_base_url": testAPIBaseURL}, testPluginOptions{})
	defer harness.stop(t)

	cases := []pluginapi.CredentialProvider{
		nil,
		testCredentials(""),
	}
	for _, credentials := range cases {
		result, err := harness.target.enqueueWithCredentials(context.Background(), testRequest(t, requestOptions{authenticated: true}), credentials)
		if err != nil {
			t.Fatalf("enqueueWithCredentials() error = %v", err)
		}

		if result.Enqueued {
			t.Fatal("zero credential request was enqueued")
		}
	}

	if got := len(harness.transport.requests); got != 0 {
		t.Fatalf("HTTP calls = %d, want 0", got)
	}
}

func TestPublicPostActionUsesRequestCredentials(t *testing.T) {
	prefix, _ := testHashParts(testSecret)

	harness := startTestPlugin(t, map[string]any{"api_base_url": testAPIBaseURL}, testPluginOptions{})
	defer harness.stop(t)

	cache := testCache(t, harness.host)
	cache.Set(context.Background(), localCacheKey(testAccount, prefix), 17, time.Minute)

	request := testRequest(t, requestOptions{authenticated: true})
	request.Credentials = testCredentials(testSecret)

	result, err := harness.target.Enqueue(context.Background(), request)
	if err != nil {
		t.Fatalf("Enqueue() error = %v", err)
	}

	assertResultLog(t, result, resultCachePositive)
	assertResultLog(t, result, publicLogResultLeaked)

	if !result.Enqueued {
		t.Fatal("public post-action did not enqueue with request credentials")
	}

	if got := len(harness.transport.requests); got != 0 {
		t.Fatalf("HTTP calls = %d, want 0", got)
	}
}

func TestLocalPositiveCacheReturnsLeakedResultWithoutHTTP(t *testing.T) {
	prefix, _ := testHashParts(testSecret)

	harness := startTestPlugin(t, map[string]any{"api_base_url": testAPIBaseURL}, testPluginOptions{})
	defer harness.stop(t)

	cache := testCache(t, harness.host)
	cache.Set(context.Background(), localCacheKey(testAccount, prefix), 17, time.Minute)

	result, err := harness.target.enqueueWithCredentials(context.Background(), testRequest(t, requestOptions{authenticated: true}), testCredentials(testSecret))
	if err != nil {
		t.Fatalf("enqueueWithCredentials() error = %v", err)
	}

	assertResultLog(t, result, resultCachePositive)
	assertResultLog(t, result, publicLogResultLeaked)

	if !result.Enqueued {
		t.Fatal("cache positive result was not enqueued")
	}

	if got := len(harness.transport.requests); got != 0 {
		t.Fatalf("HTTP calls = %d, want 0", got)
	}
}

func TestPositiveResultPublishesHIBPRuntimeDelta(t *testing.T) {
	prefix, _ := testHashParts(testSecret)

	harness := startTestPlugin(t, map[string]any{"api_base_url": testAPIBaseURL}, testPluginOptions{})
	defer harness.stop(t)

	cache := testCache(t, harness.host)
	cache.Set(context.Background(), localCacheKey(testAccount, prefix), 17, time.Minute)

	result, err := harness.target.enqueueWithCredentials(context.Background(), testRequest(t, requestOptions{authenticated: true}), testCredentials(testSecret))
	if err != nil {
		t.Fatalf("enqueueWithCredentials() error = %v", err)
	}

	if got := result.RuntimeDelta.Set[runtimeKeyHIBPHashInfo]; got != prefix+"17" {
		t.Fatalf("RuntimeDelta[%s] = %#v, want %q", runtimeKeyHIBPHashInfo, got, prefix+"17")
	}

	if _, exists := result.RuntimeDelta.Set[runtimeKeyLegacyRT]; exists {
		t.Fatalf("RuntimeDelta unexpectedly restored legacy rt marker: %#v", result.RuntimeDelta.Set[runtimeKeyLegacyRT])
	}
}

func TestRedisPositivePathSeedsLocalCacheAndReturnsLeakedResult(t *testing.T) {
	prefix, _ := testHashParts(testSecret)
	redisKey := redisKeyPrefix + md5Hex(testAccount)
	db, mock := redismock.NewClientMock()
	mock.ExpectHGet(redisKey, prefix).SetVal("23")

	harness := startTestPlugin(t, map[string]any{"api_base_url": testAPIBaseURL}, testPluginOptions{
		redis: pluginruntime.NewRedisFacade(rediscli.NewTestClient(db)),
	})
	defer harness.stop(t)

	result, err := harness.target.enqueueWithCredentials(context.Background(), testRequest(t, requestOptions{authenticated: true}), testCredentials(testSecret))
	if err != nil {
		t.Fatalf("enqueueWithCredentials() error = %v", err)
	}

	assertResultLog(t, result, resultRedisPositive)
	assertResultLog(t, result, publicLogResultLeaked)
	assertCacheCount(t, harness.host, localCacheKey(testAccount, prefix), testRedisCount)

	if got := len(harness.transport.requests); got != 0 {
		t.Fatalf("HTTP calls = %d, want 0", got)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("Redis expectations were not met: %v", err)
	}
}

func TestRedisGateDuplicateSkipsHTTP(t *testing.T) {
	prefix, _ := testHashParts(testSecret)
	redisKey := redisKeyPrefix + md5Hex(testAccount)
	gateKey := redisGateKeyPrefix + md5Hex(testAccount) + ":" + prefix
	db, mock := redismock.NewClientMock()
	mock.ExpectHGet(redisKey, prefix).RedisNil()
	mock.ExpectSetNX(gateKey, "1", defaultGateTTL).SetVal(false)

	harness := startTestPlugin(t, map[string]any{"api_base_url": testAPIBaseURL}, testPluginOptions{
		redis: pluginruntime.NewRedisFacade(rediscli.NewTestClient(db)),
	})
	defer harness.stop(t)

	result, err := harness.target.enqueueWithCredentials(context.Background(), testRequest(t, requestOptions{authenticated: true}), testCredentials(testSecret))
	if err != nil {
		t.Fatalf("enqueueWithCredentials() error = %v", err)
	}

	assertResultLog(t, result, resultGateSkipped)

	if result.Enqueued {
		t.Fatal("duplicate gate result was enqueued")
	}

	if got := len(harness.transport.requests); got != 0 {
		t.Fatalf("HTTP calls = %d, want 0", got)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("Redis expectations were not met: %v", err)
	}
}

func TestHTTPPositivePathWritesRedisSeedsCacheAndReturnsLeakedData(t *testing.T) {
	prefix, suffix := testHashParts(testSecret)
	redisKey := redisKeyPrefix + md5Hex(testAccount)
	gateKey := redisGateKeyPrefix + md5Hex(testAccount) + ":" + prefix
	db, mock := redismock.NewClientMock()
	mock.ExpectHGet(redisKey, prefix).RedisNil()
	mock.ExpectSetNX(gateKey, "1", defaultGateTTL).SetVal(true)
	mock.ExpectHSet(redisKey, prefix, testHTTPCount).SetVal(1)
	mock.ExpectExpire(redisKey, defaultRedisPositiveTTL).SetVal(true)

	body := "00000000000000000000000000000000000:1\n" + strings.ToUpper(suffix) + ":42\n"

	harness := startTestPlugin(t, map[string]any{"api_base_url": testAPIBaseURL}, testPluginOptions{
		redis:     pluginruntime.NewRedisFacade(rediscli.NewTestClient(db)),
		transport: &recordingTransport{statusCode: http.StatusOK, body: body},
	})
	defer harness.stop(t)

	called := false

	result, err := harness.target.enqueueWithCredentials(
		context.Background(),
		testRequest(t, requestOptions{authenticated: true}),
		testCredentialProvider{secret: recordingSecret{value: []byte(testSecret), called: &called}},
	)
	if err != nil {
		t.Fatalf("enqueueWithCredentials() error = %v", err)
	}

	if !called {
		t.Fatal("credential secret closure was not used")
	}

	assertResultLog(t, result, resultHTTPPositive)
	assertResultLog(t, result, publicLogResultLeaked)
	assertCacheCount(t, harness.host, localCacheKey(testAccount, prefix), testHTTPCount)

	request := harness.transport.onlyRequest()
	if !strings.HasSuffix(request.url, "/"+prefix) {
		t.Fatalf("HIBP URL = %q, want suffix /%s", request.url, prefix)
	}

	if got := request.header.Get(headerAccept); got != headerValueAny {
		t.Fatalf("Accept header = %q, want %q", got, headerValueAny)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("Redis expectations were not met: %v", err)
	}
}

func TestHTTPPositivePathWithMailEnabledSendsAndExtendsRedisExpiration(t *testing.T) {
	prefix, suffix := testHashParts(testSecret)
	redisKey := redisKeyPrefix + md5Hex(testAccount)
	gateKey := redisGateKeyPrefix + md5Hex(testAccount) + ":" + prefix
	db, mock := redismock.NewClientMock()
	mock.ExpectHGet(redisKey, prefix).RedisNil()
	mock.ExpectSetNX(gateKey, "1", defaultGateTTL).SetVal(true)
	mock.ExpectHSet(redisKey, prefix, testHTTPCount).SetVal(1)
	mock.ExpectExpire(redisKey, defaultRedisPositiveTTL).SetVal(true)
	mock.ExpectHSetNX(redisKey, redisHashFieldSendMail, "1").SetVal(true)
	mock.ExpectExpire(redisKey, defaultRedisNegativeTTL).SetVal(true)

	body := strings.ToUpper(suffix) + ":42\n"
	mailSender := &recordingPluginMailSender{}
	metrics := newHIBPRecordingMetrics()

	harness := startTestPlugin(t, mailEnabledConfig(map[string]any{
		"subject_template": "Leak {{ .HashPrefix }} {{ .Count }}",
		"website":          "https://ssp.example.test",
	}), testPluginOptions{
		allowMail:  true,
		mailSender: mailSender,
		metrics:    metrics,
		redis:      pluginruntime.NewRedisFacade(rediscli.NewTestClient(db)),
		transport:  &recordingTransport{statusCode: http.StatusOK, body: body},
	})
	defer harness.stop(t)

	result, err := harness.target.enqueueWithCredentials(context.Background(), testRequest(t, requestOptions{authenticated: true}), testCredentials(testSecret))
	if err != nil {
		t.Fatalf("enqueueWithCredentials() error = %v", err)
	}

	assertResultLog(t, result, resultHTTPPositive)
	assertResultLog(t, result, publicLogResultLeaked)
	assertMailMetric(t, metrics, resultMailSent)
	assertCacheCount(t, harness.host, localCacheKey(testAccount, prefix), testHTTPCount)

	options := mailSender.singleCall(t)
	if options.Server != "mail.example.test" || options.Port != 2525 || options.From != "postmaster@example.test" {
		t.Fatalf("mail options = %#v, want configured transport fields", options)
	}

	if len(options.To) != 1 || options.To[0] != testAccount {
		t.Fatalf("mail recipients = %#v, want account recipient", options.To)
	}

	if options.Subject != "Leak "+prefix+" 42" {
		t.Fatalf("mail subject = %q, want rendered subject", options.Subject)
	}

	for _, want := range []string{testAccount, "Hash: " + prefix, "Count: 42", "https://ssp.example.test"} {
		if !strings.Contains(options.Body, want) {
			t.Fatalf("mail body missing %q: %s", want, options.Body)
		}
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("Redis expectations were not met: %v", err)
	}
}

func TestHTTPPositiveMailGateDuplicateSkipsSend(t *testing.T) {
	prefix, suffix := testHashParts(testSecret)
	redisKey := redisKeyPrefix + md5Hex(testAccount)
	gateKey := redisGateKeyPrefix + md5Hex(testAccount) + ":" + prefix
	db, mock := redismock.NewClientMock()
	mock.ExpectHGet(redisKey, prefix).RedisNil()
	mock.ExpectSetNX(gateKey, "1", defaultGateTTL).SetVal(true)
	mock.ExpectHSet(redisKey, prefix, testHTTPCount).SetVal(1)
	mock.ExpectExpire(redisKey, defaultRedisPositiveTTL).SetVal(true)
	mock.ExpectHSetNX(redisKey, redisHashFieldSendMail, "1").SetVal(false)

	mailSender := &recordingPluginMailSender{}
	metrics := newHIBPRecordingMetrics()

	harness := startTestPlugin(t, mailEnabledConfig(nil), testPluginOptions{
		allowMail:  true,
		mailSender: mailSender,
		metrics:    metrics,
		redis:      pluginruntime.NewRedisFacade(rediscli.NewTestClient(db)),
		transport:  &recordingTransport{statusCode: http.StatusOK, body: strings.ToUpper(suffix) + ":42\n"},
	})
	defer harness.stop(t)

	result, err := harness.target.enqueueWithCredentials(context.Background(), testRequest(t, requestOptions{authenticated: true}), testCredentials(testSecret))
	if err != nil {
		t.Fatalf("enqueueWithCredentials() error = %v", err)
	}

	assertResultLog(t, result, resultHTTPPositive)
	assertMailMetric(t, metrics, resultMailGateSkipped)

	if mailSender.calls != 0 {
		t.Fatalf("mail calls = %d, want none", mailSender.calls)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("Redis expectations were not met: %v", err)
	}
}

func TestHTTPPositiveMailSendErrorIsRedactedAndReturned(t *testing.T) {
	var logs bytes.Buffer

	logger := slog.New(slog.NewJSONHandler(&logs, nil))
	prefix, suffix := testHashParts(testSecret)
	fullHash := sha1Hex(testSecret)
	redisKey := redisKeyPrefix + md5Hex(testAccount)
	gateKey := redisGateKeyPrefix + md5Hex(testAccount) + ":" + prefix
	db, mock := redismock.NewClientMock()
	mock.ExpectHGet(redisKey, prefix).RedisNil()
	mock.ExpectSetNX(gateKey, "1", defaultGateTTL).SetVal(true)
	mock.ExpectHSet(redisKey, prefix, testHTTPCount).SetVal(1)
	mock.ExpectExpire(redisKey, defaultRedisPositiveTTL).SetVal(true)
	mock.ExpectHSetNX(redisKey, redisHashFieldSendMail, "1").SetVal(true)

	mailSender := &recordingPluginMailSender{err: &secretMailError{text: testMailRawError}}
	metrics := newHIBPRecordingMetrics()

	harness := startTestPlugin(t, mailEnabledConfig(map[string]any{
		"password":         "smtp-secret",
		"subject_template": testMailSubject + " {{ .Account }}",
		"template_path":    writeMailTemplate(t, testMailBody+" {{ .Account }}"),
	}), testPluginOptions{
		allowMail:  true,
		logger:     logger,
		mailSender: mailSender,
		metrics:    metrics,
		redis:      pluginruntime.NewRedisFacade(rediscli.NewTestClient(db)),
		transport:  &recordingTransport{statusCode: http.StatusOK, body: strings.ToUpper(suffix) + ":42\n"},
	})
	defer harness.stop(t)

	_, err := harness.target.enqueueWithCredentials(context.Background(), testRequest(t, requestOptions{authenticated: true}), testCredentials(testSecret))
	if err == nil {
		t.Fatal("enqueueWithCredentials() error = nil, want mail send error")
	}

	assertMailMetric(t, metrics, resultMailSendError)
	assertRedactedHIBPMailText(t, err.Error(), fullHash)
	assertRedactedHIBPMailText(t, logs.String(), fullHash)

	if mailSender.calls != 1 {
		t.Fatalf("mail calls = %d, want one", mailSender.calls)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("Redis expectations were not met: %v", err)
	}
}

func TestHTTPPositiveMailTemplateRenderErrorSkipsSend(t *testing.T) {
	prefix, suffix := testHashParts(testSecret)
	redisKey := redisKeyPrefix + md5Hex(testAccount)
	gateKey := redisGateKeyPrefix + md5Hex(testAccount) + ":" + prefix
	db, mock := redismock.NewClientMock()
	mock.ExpectHGet(redisKey, prefix).RedisNil()
	mock.ExpectSetNX(gateKey, "1", defaultGateTTL).SetVal(true)
	mock.ExpectHSet(redisKey, prefix, testHTTPCount).SetVal(1)
	mock.ExpectExpire(redisKey, defaultRedisPositiveTTL).SetVal(true)
	mock.ExpectHSetNX(redisKey, redisHashFieldSendMail, "1").SetVal(true)

	mailSender := &recordingPluginMailSender{}
	metrics := newHIBPRecordingMetrics()

	harness := startTestPlugin(t, mailEnabledConfig(map[string]any{
		"subject_template": "{{ .MissingField }}",
	}), testPluginOptions{
		allowMail:  true,
		mailSender: mailSender,
		metrics:    metrics,
		redis:      pluginruntime.NewRedisFacade(rediscli.NewTestClient(db)),
		transport:  &recordingTransport{statusCode: http.StatusOK, body: strings.ToUpper(suffix) + ":42\n"},
	})
	defer harness.stop(t)

	_, err := harness.target.enqueueWithCredentials(context.Background(), testRequest(t, requestOptions{authenticated: true}), testCredentials(testSecret))
	if err == nil {
		t.Fatal("enqueueWithCredentials() error = nil, want template render error")
	}

	assertMailMetric(t, metrics, resultMailTemplateError)

	if mailSender.calls != 0 {
		t.Fatalf("mail calls = %d, want none", mailSender.calls)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("Redis expectations were not met: %v", err)
	}
}

func TestHTTPNegativePathWritesRedisAndSeedsNegativeCache(t *testing.T) {
	prefix, _ := testHashParts(testSecret)
	redisKey := redisKeyPrefix + md5Hex(testAccount)
	gateKey := redisGateKeyPrefix + md5Hex(testAccount) + ":" + prefix
	db, mock := redismock.NewClientMock()
	mock.ExpectHGet(redisKey, prefix).RedisNil()
	mock.ExpectSetNX(gateKey, "1", defaultGateTTL).SetVal(true)
	mock.ExpectHSet(redisKey, prefix, 0).SetVal(1)
	mock.ExpectExpire(redisKey, defaultRedisNegativeTTL).SetVal(true)

	harness := startTestPlugin(t, map[string]any{"api_base_url": testAPIBaseURL}, testPluginOptions{
		redis:     pluginruntime.NewRedisFacade(rediscli.NewTestClient(db)),
		transport: &recordingTransport{statusCode: http.StatusOK, body: testMissingSuffix + ":7\n"},
	})
	defer harness.stop(t)

	result, err := harness.target.enqueueWithCredentials(context.Background(), testRequest(t, requestOptions{authenticated: true}), testCredentials(testSecret))
	if err != nil {
		t.Fatalf("enqueueWithCredentials() error = %v", err)
	}

	assertResultLog(t, result, resultHTTPNegative)
	assertCacheCount(t, harness.host, localCacheKey(testAccount, prefix), 0)

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("Redis expectations were not met: %v", err)
	}
}

func TestHTTPStatusErrorDoesNotLeakResponseBody(t *testing.T) {
	var logs bytes.Buffer

	logger := slog.New(slog.NewJSONHandler(&logs, nil))
	prefix, _ := testHashParts(testSecret)
	redisKey := redisKeyPrefix + md5Hex(testAccount)
	gateKey := redisGateKeyPrefix + md5Hex(testAccount) + ":" + prefix
	db, mock := redismock.NewClientMock()
	mock.ExpectHGet(redisKey, prefix).RedisNil()
	mock.ExpectSetNX(gateKey, "1", defaultGateTTL).SetVal(true)

	harness := startTestPlugin(t, map[string]any{"api_base_url": testAPIBaseURL}, testPluginOptions{
		logger:    logger,
		redis:     pluginruntime.NewRedisFacade(rediscli.NewTestClient(db)),
		transport: &recordingTransport{statusCode: http.StatusInternalServerError, body: testResponseBody},
	})
	defer harness.stop(t)

	_, err := harness.target.enqueueWithCredentials(context.Background(), testRequest(t, requestOptions{authenticated: true}), testCredentials(testSecret))
	if err == nil {
		t.Fatal("enqueueWithCredentials() error = nil, want status error")
	}

	if strings.Contains(err.Error(), testResponseBody) {
		t.Fatalf("error leaked response body: %v", err)
	}

	if strings.Contains(logs.String(), testResponseBody) || strings.Contains(logs.String(), testSecret) {
		t.Fatalf("logs leaked secret material: %s", logs.String())
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("Redis expectations were not met: %v", err)
	}
}

func TestStartRegistersBoundedConnectionTarget(t *testing.T) {
	targets := &recordingConnectionTargetRegistrar{}

	harness := startTestPlugin(t, map[string]any{"api_base_url": testAPIBaseURL}, testPluginOptions{targets: targets})
	defer harness.stop(t)

	if len(targets.records) != 1 {
		t.Fatalf("connection target records = %#v, want one", targets.records)
	}

	record := targets.records[0]
	if record.address != "hibp.example.test:443" || record.direction != string(pluginapi.ConnectionTargetDirectionRemote) {
		t.Fatalf("connection target = %#v, want remote hibp.example.test:443", record)
	}
}

type testPluginOptions struct {
	transport  *recordingTransport
	mailSender *recordingPluginMailSender
	metrics    *hibpRecordingMetrics
	redis      pluginapi.Redis
	logger     *slog.Logger
	targets    *recordingConnectionTargetRegistrar
	allowMail  bool
}

type testHarness struct {
	plugin    *Plugin
	host      *pluginruntime.Host
	transport *recordingTransport
	target    postActionTarget
}

// startTestPlugin registers, starts, and returns a HIBP plugin harness.
func startTestPlugin(t *testing.T, pluginConfig map[string]any, options testPluginOptions) testHarness {
	t.Helper()

	transport := options.transport

	if transport == nil {
		transport = &recordingTransport{statusCode: http.StatusOK}
	}

	targets := options.targets
	if targets == nil {
		targets = &recordingConnectionTargetRegistrar{}
	}

	mailSender := options.mailSender
	if mailSender == nil {
		mailSender = &recordingPluginMailSender{}
	}

	metrics := options.metrics
	if metrics == nil {
		metrics = newHIBPRecordingMetrics()
	}

	capabilities := []pluginapi.Capability{pluginapi.CapabilityCredentials}
	if options.allowMail {
		capabilities = append(capabilities, pluginapi.CapabilityMail)
	}

	_, plugin, _ := registerTestPlugin(t, testModuleWithCapabilities(pluginConfig, capabilities...))
	hostOptions := []pluginruntime.HostOption{
		pluginruntime.WithHTTPClient(&http.Client{Transport: transport}),
		pluginruntime.WithConnectionTargets(pluginruntime.NewConnectionTargetFacade(targets)),
		pluginruntime.WithMailSender(mailSender),
		pluginruntime.WithMetricsFactory(func(string) pluginapi.Metrics {
			return metrics
		}),
	}
	if options.redis != nil {
		hostOptions = append(hostOptions, pluginruntime.WithRedis(options.redis))
	}

	if options.logger != nil {
		hostOptions = append(hostOptions, pluginruntime.WithLogger(options.logger))
	}

	host := pluginruntime.NewHost(hostOptions...)
	if err := plugin.Start(context.Background(), host); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	return testHarness{
		plugin:    plugin,
		host:      host,
		transport: transport,
		target:    postActionTarget{plugin: plugin},
	}
}

// stop stops a started plugin.
func (h testHarness) stop(t *testing.T) {
	t.Helper()

	if err := h.plugin.Stop(context.Background()); err != nil {
		t.Fatalf("Stop() error = %v", err)
	}
}

// registerTestPlugin registers a HIBP plugin in the real component registry.
func registerTestPlugin(t *testing.T, module config.PluginModule) (*pluginregistry.Registry, *Plugin, *pluginregistry.Registrar) {
	t.Helper()

	registry := pluginregistry.NewRegistry()
	plugin := NewPlugin()
	registrar := registry.NewRegistrar(module)

	if err := plugin.Register(registrar); err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	if err := registrar.Commit(); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}

	return registry, plugin, registrar
}

// testModule returns a native HIBP plugin module config for tests.
func testModule(pluginConfig map[string]any, allowCredentials bool) config.PluginModule {
	if !allowCredentials {
		return testModuleWithCapabilities(pluginConfig)
	}

	return testModuleWithCapabilities(pluginConfig, pluginapi.CapabilityCredentials)
}

// testModuleWithCapabilities returns a native HIBP test module with explicit capability allowlist.
func testModuleWithCapabilities(pluginConfig map[string]any, capabilities ...pluginapi.Capability) config.PluginModule {
	module := config.PluginModule{
		Config: pluginConfig,
		Name:   pluginName,
		Type:   config.PluginModuleTypeGo,
		Path:   "/plugins/haveibeenpwnd.so",
	}
	if len(capabilities) > 0 {
		module.AllowCapabilities = append([]pluginapi.Capability(nil), capabilities...)
	}

	return module
}

type requestOptions struct {
	authenticated bool
	noAuth        bool
}

// testRequest builds one representative post-action request.
func testRequest(t *testing.T, options requestOptions) pluginapi.PostActionRequest {
	t.Helper()

	runtimeContext, err := pluginruntime.NewRuntimeContext(nil)
	if err != nil {
		t.Fatalf("NewRuntimeContext() error = %v", err)
	}

	return pluginapi.PostActionRequest{
		Snapshot: pluginapi.RequestSnapshot{
			Account: testAccount,
			Runtime: pluginapi.RuntimeFlags{
				Authenticated: options.authenticated,
				NoAuth:        options.noAuth,
			},
		},
		Runtime: runtimeContext,
	}
}

type recordedHTTPRequest struct {
	header http.Header
	body   []byte
	url    string
}

type recordingTransport struct {
	err        error
	body       string
	requests   []recordedHTTPRequest
	statusCode int
}

// RoundTrip records requests and returns the configured response.
func (t *recordingTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	body, _ := io.ReadAll(request.Body)
	t.requests = append(t.requests, recordedHTTPRequest{
		header: request.Header.Clone(),
		url:    request.URL.String(),
		body:   append([]byte(nil), body...),
	})

	if t.err != nil {
		return nil, t.err
	}

	statusCode := t.statusCode
	if statusCode == 0 {
		statusCode = http.StatusOK
	}

	return &http.Response{
		StatusCode: statusCode,
		Header:     http.Header{},
		Body:       io.NopCloser(strings.NewReader(t.body)),
		Request:    request,
	}, nil
}

// onlyRequest returns the single captured request or fails the test.
func (t *recordingTransport) onlyRequest() recordedHTTPRequest {
	if len(t.requests) != 1 {
		panic("expected exactly one captured HTTP request")
	}

	return t.requests[0]
}

type testCredentialProvider struct {
	secret pluginapi.Secret
}

// Password returns the configured test secret.
func (p testCredentialProvider) Password(context.Context) (pluginapi.Secret, bool) {
	if p.secret == nil {
		return nil, false
	}

	return p.secret, true
}

type recordingSecret struct {
	called *bool
	value  []byte
}

// WithBytes exposes temporary secret bytes to the callback.
func (s recordingSecret) WithBytes(fn func([]byte) error) error {
	if s.called != nil {
		*s.called = true
	}

	if fn == nil {
		return nil
	}

	return fn(s.value)
}

// IsZero reports whether the test secret is empty.
func (s recordingSecret) IsZero() bool {
	return len(s.value) == 0
}

// testCredentials returns a credential provider for one plain text secret.
func testCredentials(value string) pluginapi.CredentialProvider {
	return testCredentialProvider{secret: recordingSecret{value: []byte(value)}}
}

// testHashParts returns the HIBP prefix and suffix for one plain text password.
func testHashParts(value string) (string, string) {
	return hashParts(sha1Hex(value))
}

// sha1Hex returns the lower-case SHA-1 digest for one test password.
func sha1Hex(value string) string {
	sum := sha1.Sum([]byte(value))

	return hex.EncodeToString(sum[:])
}

// testCache returns the module-local cache.
func testCache(t *testing.T, host *pluginruntime.Host) pluginapi.Cache {
	t.Helper()

	cache, err := host.Cache(pluginName)
	if err != nil {
		t.Fatalf("Cache(%s) error = %v", pluginName, err)
	}

	return cache
}

// assertCacheCount checks one cached HIBP count.
func assertCacheCount(t *testing.T, host *pluginruntime.Host, key string, want int) {
	t.Helper()

	value, ok := testCache(t, host).Get(context.Background(), key)
	if !ok {
		t.Fatalf("cache key %q not found", key)
	}

	got, ok := countFromAny(value)
	if !ok || got != want {
		t.Fatalf("cache[%q] = %#v, want %d", key, value, want)
	}
}

// assertResultLog checks whether a result log value is present.
func assertResultLog(t *testing.T, result pluginapi.PostActionEnqueueResult, want string) {
	t.Helper()

	for _, field := range result.Logs {
		if field.Value == want {
			return
		}
	}

	t.Fatalf("logs = %#v, want value %q", result.Logs, want)
}

// writeMailTemplate stores one test mail template and returns its path.
func writeMailTemplate(t *testing.T, body string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "mail.tmpl")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("WriteFile(%s) error = %v", path, err)
	}

	return path
}

// assertRenderedMail checks configured templates without exposing request-time transport.
func assertRenderedMail(t *testing.T, config mailConfig, data mailTemplateData, bodyParts []string, subject string) {
	t.Helper()

	message, err := renderMailMessage(config, data, testAccount)
	if err != nil {
		t.Fatalf("renderMailMessage() error = %v", err)
	}

	if message.Subject != subject {
		t.Fatalf("subject = %q, want %q", message.Subject, subject)
	}

	for _, bodyPart := range bodyParts {
		if !strings.Contains(message.Body, bodyPart) {
			t.Fatalf("body missing %q: %s", bodyPart, message.Body)
		}
	}
}

// mailEnabledConfig returns a complete enabled mail config for request-time tests.
func mailEnabledConfig(overrides map[string]any) map[string]any {
	mail := map[string]any{
		"enabled":   true,
		"use_lmtp":  true,
		"server":    "mail.example.test",
		"port":      2525,
		"helo_name": "nauthilus.example.test",
		"tls":       true,
		"starttls":  false,
		"username":  "smtp-user",
		"password":  "smtp-secret",
		"mail_from": "postmaster@example.test",
		"website":   "https://ssp.example.test",
	}
	for key, value := range overrides {
		mail[key] = value
	}

	return map[string]any{"api_base_url": testAPIBaseURL, "mail": mail}
}

// assertMailMetric verifies that a bounded mail result was recorded.
func assertMailMetric(t *testing.T, metrics *hibpRecordingMetrics, want string) {
	t.Helper()

	if metrics.observationCount(metricMailAttempts, want) == 0 {
		t.Fatalf("mail metric %q result %q was not recorded: %#v", metricMailAttempts, want, metrics.observations)
	}
}

// assertRedactedHIBPMailText checks HIBP mail errors and logs for secret-bearing values.
func assertRedactedHIBPMailText(t *testing.T, text string, fullHash string) {
	t.Helper()

	for _, secret := range []string{
		testAccount,
		testSecret,
		"smtp-secret",
		testMailSubject,
		testMailBody,
		testMailRawError,
		fullHash,
	} {
		if strings.Contains(text, secret) {
			t.Fatalf("mail text leaked %q: %s", secret, text)
		}
	}
}

type recordingPluginMailSender struct {
	last  *smtp.MailOptions
	err   error
	calls int
}

// SendMail records a cloned SMTP option set before returning the configured error.
func (s *recordingPluginMailSender) SendMail(options *smtp.MailOptions) error {
	s.calls++
	s.last = cloneSMTPMailOptions(options)

	return s.err
}

// singleCall returns the only recorded mail send options.
func (s *recordingPluginMailSender) singleCall(t *testing.T) *smtp.MailOptions {
	t.Helper()

	if s.calls != 1 {
		t.Fatalf("mail calls = %d, want one", s.calls)
	}

	if s.last == nil {
		t.Fatal("mail sender did not record options")
	}

	return s.last
}

// cloneSMTPMailOptions copies mutable SMTP option slices for stable assertions.
func cloneSMTPMailOptions(options *smtp.MailOptions) *smtp.MailOptions {
	if options == nil {
		return nil
	}

	cloned := *options
	cloned.To = append([]string(nil), options.To...)

	return &cloned
}

type secretMailError struct {
	text string
}

// Error returns secret-bearing text used to prove logs and returned errors are redacted.
func (err *secretMailError) Error() string {
	return err.text
}

type hibpRecordingMetrics struct {
	observations []hibpMetricObservation
}

type hibpMetricObservation struct {
	name   string
	result string
}

// newHIBPRecordingMetrics creates a bounded metrics fake for HIBP tests.
func newHIBPRecordingMetrics() *hibpRecordingMetrics {
	return &hibpRecordingMetrics{}
}

// Counter returns a recording counter.
func (m *hibpRecordingMetrics) Counter(definition pluginapi.MetricDefinition) (pluginapi.Counter, error) {
	return hibpRecordingMetric{name: definition.Name, metrics: m}, nil
}

// Gauge returns a recording gauge.
func (m *hibpRecordingMetrics) Gauge(definition pluginapi.MetricDefinition) (pluginapi.Gauge, error) {
	return hibpRecordingMetric{name: definition.Name, metrics: m}, nil
}

// Histogram returns a recording histogram.
func (m *hibpRecordingMetrics) Histogram(definition pluginapi.MetricDefinition) (pluginapi.Histogram, error) {
	return hibpRecordingMetric{name: definition.Name, metrics: m}, nil
}

// Summary returns a recording summary.
func (m *hibpRecordingMetrics) Summary(definition pluginapi.MetricDefinition) (pluginapi.Summary, error) {
	return hibpRecordingMetric{name: definition.Name, metrics: m}, nil
}

// observationCount returns the number of observations with a given metric name and result label.
func (m *hibpRecordingMetrics) observationCount(name string, result string) int {
	count := 0

	for _, observation := range m.observations {
		if observation.name == name && observation.result == result {
			count++
		}
	}

	return count
}

type hibpRecordingMetric struct {
	metrics *hibpRecordingMetrics
	name    string
}

// Add records counter and gauge observations.
func (m hibpRecordingMetric) Add(_ context.Context, _ float64, labels ...pluginapi.LabelValue) {
	m.record(labels...)
}

// Set records gauge observations.
func (m hibpRecordingMetric) Set(_ context.Context, _ float64, labels ...pluginapi.LabelValue) {
	m.record(labels...)
}

// Observe records histogram and summary observations.
func (m hibpRecordingMetric) Observe(_ context.Context, _ float64, labels ...pluginapi.LabelValue) {
	m.record(labels...)
}

// record stores one bounded metric observation.
func (m hibpRecordingMetric) record(labels ...pluginapi.LabelValue) {
	result := ""

	for _, label := range labels {
		if label.Name == metricLabelResult {
			result = label.Value
		}
	}

	m.metrics.observations = append(m.metrics.observations, hibpMetricObservation{name: m.name, result: result})
}

type connectionRecord struct {
	address     string
	direction   string
	description string
}

type recordingConnectionTargetRegistrar struct {
	records []connectionRecord
}

// Register records one connection target registration.
func (r *recordingConnectionTargetRegistrar) Register(_ context.Context, address string, direction string, description string) {
	r.records = append(r.records, connectionRecord{
		address:     address,
		direction:   direction,
		description: description,
	})
}

// Count returns no live connection count in tests.
func (r *recordingConnectionTargetRegistrar) Count(string) (int, bool) {
	return 0, false
}
