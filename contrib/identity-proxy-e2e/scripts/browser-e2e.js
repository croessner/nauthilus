#!/usr/bin/env node
'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const https = require('node:https');
const path = require('node:path');

let chromium;
try {
  ({chromium} = require('playwright'));
} catch (error) {
  console.error('Missing Playwright. Run: npm --prefix contrib/identity-proxy-e2e install');
  throw error;
}

const edgeA = process.env.NAUTHILUS_E2E_EDGE_A || 'https://split.example.test:18080';
const edgeB = process.env.NAUTHILUS_E2E_EDGE_B || 'https://split.example.test:18082';
const edgeAAPI = process.env.NAUTHILUS_E2E_EDGE_A_API || 'https://127.0.0.1:18080';
const callbackBindHost = process.env.NAUTHILUS_E2E_CALLBACK_BIND_HOST || '127.0.0.1';
const callbackPublicHost = process.env.NAUTHILUS_E2E_CALLBACK_PUBLIC_HOST || 'split.example.test';
const callbackPort = Number.parseInt(process.env.NAUTHILUS_E2E_CALLBACK_PORT || '19094', 10);
const callbackTimeoutMS = Number.parseInt(process.env.NAUTHILUS_E2E_CALLBACK_TIMEOUT_MS || '90000', 10);
const callbackCert = process.env.NAUTHILUS_E2E_CALLBACK_CERT
  || path.join(__dirname, '..', '.work', 'certs', 'edge-http.crt');
const callbackKey = process.env.NAUTHILUS_E2E_CALLBACK_KEY
  || path.join(__dirname, '..', '.work', 'certs', 'edge-http.key');
const username = process.env.NAUTHILUS_E2E_USERNAME || 'split-user@example.test';
const password = process.env.NAUTHILUS_E2E_PASSWORD || 'split-password';
const mfaUsername = `${username}.mfa`;
const selfServiceUsername = `${username}.self-service`;
const masterUsername = `${username}.master`;
const masterWithoutMFAUsername = `${username}.master-no-mfa`;
const masterUserLogin = `${mfaUsername}*${masterUsername}`;
const masterUserWithoutMFALogin = `${mfaUsername}*${masterWithoutMFAUsername}`;
const defaultSAMLLoginURL = 'https://localhost:19095/saml/login';
const samlLoginURL = Object.prototype.hasOwnProperty.call(process.env, 'NAUTHILUS_E2E_SAML_URL')
  ? process.env.NAUTHILUS_E2E_SAML_URL
  : defaultSAMLLoginURL;

if (process.env.NAUTHILUS_E2E_STRICT_TLS !== '1') {
  process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
}

const browserClient = {
  id: 'split-e2e-browser',
  secret: 'split-e2e-browser-secret',
};

const mfaClient = {
  id: 'split-e2e-mfa',
  secret: 'split-e2e-mfa-secret',
};

const delayedMFAClient = {
  id: 'split-e2e-mfa-delayed',
  secret: 'split-e2e-mfa-delayed-secret',
};

const consentClient = {
  id: 'split-e2e-consent',
  secret: 'split-e2e-consent-secret',
};

const deviceAttackerClient = {
  id: 'split-e2e-device-attacker',
  secret: 'split-e2e-device-attacker-secret',
};

async function main() {
  const browser = await chromium.launch({
    headless: process.env.NAUTHILUS_E2E_HEADED !== '1',
    args: ['--host-resolver-rules=MAP split.example.test 127.0.0.1,MAP authority.example.test 127.0.0.1'],
  });

  try {
    await runAuthorizationCodeFlow(browser);
    await runNegativeIDPChecks(browser);
    await runDeviceCodeFlow(browser);
    const webAuthnCredentials = await runRequiredMFAFlows(browser);
    await runMultiEdgeContinuity(browser);
    await runMultiEdgeWebAuthnContinuity(browser, webAuthnCredentials);
    await maybeRunSAMLFlow(browser);
  } finally {
    await browser.close();
  }
}

async function runAuthorizationCodeFlow(browser) {
  const context = await newBrowserContext(browser, edgeA);
  const page = await context.newPage();
  const callback = await withPageState(page, 'authorization-code flow', async () =>
    withCallbackServer('authorization-code flow', async (redirectURI, callbackPromise) => {
      await page.goto(buildAuthorizeURL(edgeA, browserClient.id, redirectURI, 'openid profile email groups'));
      await submitPasswordLogin(page, username, password);

      return callbackPromise;
    }));

  const token = await exchangeCode(edgeAAPI, browserClient, callback.code, callback.redirectURI);
  assert.ok(token.access_token, 'authorization-code flow returned an access token');
  assert.ok(token.id_token, 'authorization-code flow returned an ID token');
  console.log('ok oidc-authorization-code-login');
  await context.close();
}

async function runNegativeIDPChecks(browser) {
  await runAuthorizeParameterFailures(browser);
  await runDirectLoginFailure(browser);
  await runPasswordLoginFailure(browser);
  await runConsentDenied(browser);
  await runCSRFAndSessionAttackFailures(browser);
  await runTokenEndpointFailures(browser);
  await runUserInfoFailures();
  await runDeviceEndpointFailures(browser);
}

async function runAuthorizeParameterFailures(browser) {
  await expectTextResponse(
    buildAuthorizeURL(edgeAAPI, browserClient.id, defaultRedirectURI(), 'openid', {response_type: 'token'}),
    400,
    /Only response_type=code is supported/,
    'oidc-authorize-invalid-response-type',
  );

  await expectTextResponse(
    buildAuthorizeURL(edgeAAPI, 'missing-client', defaultRedirectURI(), 'openid'),
    400,
    /Invalid client_id/,
    'oidc-authorize-invalid-client',
  );

  await expectTextResponse(
    buildAuthorizeURL(edgeAAPI, browserClient.id, 'https://evil.example.test/callback', 'openid'),
    400,
    /Invalid redirect_uri/,
    'oidc-authorize-invalid-redirect-uri',
  );

  await expectTextResponse(
    buildAuthorizeURL(edgeAAPI, browserClient.id, '//evil.example.test/callback', 'openid'),
    400,
    /Invalid redirect_uri/,
    'oidc-authorize-protocol-relative-redirect-uri',
  );

  await expectTextResponse(
    buildAuthorizeURL(edgeAAPI, browserClient.id, '%2F%2Fevil.example.test%2Fcallback', 'openid'),
    400,
    /Invalid redirect_uri/,
    'oidc-authorize-encoded-redirect-smuggling-rejected',
  );

  await expectTextResponse(
    buildAuthorizeURL(edgeAAPI, browserClient.id, '%252F%252Fevil.example.test%252Fcallback', 'openid'),
    400,
    /Invalid redirect_uri/,
    'oidc-authorize-double-encoded-redirect-rejected',
  );

  await expectTextResponse(
    buildAuthorizeURL(edgeAAPI, browserClient.id, 'https:\\\\evil.example.test\\callback', 'openid'),
    400,
    /Invalid redirect_uri/,
    'oidc-authorize-backslash-redirect-rejected',
  );

  await expectTextResponse(
    buildAuthorizeURL(edgeAAPI, browserClient.id, 'https://SPLIT.EXAMPLE.TEST:19094/callback', 'openid'),
    400,
    /Invalid redirect_uri/,
    'oidc-authorize-mixed-case-host-redirect-rejected',
  );

  await expectTextResponse(
    buildAuthorizeURL(edgeAAPI, browserClient.id, 'https://split.example.test.:19094/callback', 'openid'),
    400,
    /Invalid redirect_uri/,
    'oidc-authorize-trailing-dot-host-redirect-rejected',
  );

  await expectTextResponse(
    buildAuthorizeURL(edgeAAPI, browserClient.id, 'https://split.example.test:19094@evil.example.test/callback', 'openid'),
    400,
    /Invalid redirect_uri/,
    'oidc-authorize-userinfo-redirect-rejected',
  );

  await expectTextResponse(
    buildAuthorizeURL(edgeAAPI, browserClient.id, 'https://split.example.test:19094/callback/../evil', 'openid'),
    400,
    /Invalid redirect_uri/,
    'oidc-authorize-dot-segment-redirect-rejected',
  );

  const duplicateRedirectURL = new URL(buildAuthorizeURL(edgeAAPI, browserClient.id, defaultRedirectURI(), 'openid'));
  duplicateRedirectURL.searchParams.append('redirect_uri', 'https://evil.example.test/callback');
  await expectTextResponse(
    duplicateRedirectURL.toString(),
    400,
    /duplicate parameter: redirect_uri/,
    'oidc-authorize-duplicate-redirect-uri-rejected',
  );

  await expectTextResponse(
    buildAuthorizeURL(edgeAAPI, browserClient.id, defaultRedirectURI(), 'openid', {response_type: 'code token'}),
    400,
    /Only response_type=code is supported/,
    'oidc-authorize-response-type-mix-rejected',
  );

  await expectTextResponse(
    buildAuthorizeURL(edgeAAPI, browserClient.id, defaultRedirectURI(), 'openid', {response_type: 'none'}),
    400,
    /Only response_type=code is supported/,
    'oidc-authorize-response-type-none-rejected',
  );

  await expectTextResponse(
    buildAuthorizeURL(edgeAAPI, browserClient.id, defaultRedirectURI(), 'openid', {response_type: 'id_token'}),
    400,
    /Only response_type=code is supported/,
    'oidc-authorize-response-type-id-token-rejected',
  );

  await expectTextResponse(
    buildAuthorizeURL(edgeAAPI, browserClient.id, defaultRedirectURI(), 'openid', {
      code_challenge: pkceChallenge(pkceVerifier()),
      code_challenge_method: 'plain',
    }),
    400,
    /unsupported code_challenge_method/,
    'oidc-authorize-pkce-plain-rejected',
  );

  const context = await newBrowserContext(browser, edgeA);
  const page = await context.newPage();
  const callback = await withPageState(page, 'prompt none login-required check', async () =>
    withCallbackServer('prompt none login-required check', async (redirectURI, callbackPromise) => {
      await page.goto(buildAuthorizeURL(edgeA, browserClient.id, redirectURI, 'openid', {prompt: 'none'}));

      return callbackPromise;
    }));

  assert.equal(callback.error, 'login_required', 'prompt=none without a session must return login_required');
  assert.ok(callback.state, 'prompt=none error callback must preserve state');
  console.log('ok oidc-authorize-prompt-none-login-required');
  await context.close();
}

async function runDirectLoginFailure(browser) {
  const context = await newBrowserContext(browser, edgeA);
  const page = await context.newPage();
  const response = await page.goto(`${edgeA}/login`);

  assert.equal(response.status(), 400, 'direct /login access without flow must be rejected');
  await expectPageText(page, /Invalid Request/);
  await expectPageText(page, /valid OIDC or SAML2 authentication flow/);
  console.log('ok oidc-login-direct-access-rejected');
  await context.close();
}

async function runPasswordLoginFailure(browser) {
  const context = await newBrowserContext(browser, edgeA);
  const page = await context.newPage();

  await withPageState(page, 'invalid password login check', async () =>
    withCallbackServer('invalid password login check', async (redirectURI) => {
      await page.goto(buildAuthorizeURL(edgeA, browserClient.id, redirectURI, 'openid profile email'));
      await submitPasswordLogin(page, username, `${password}-wrong`);
      assert.match(page.url(), /\/login/, 'invalid password must keep the user on the login flow');
      await expectPageText(page, /Invalid login or password/);
    }));

  console.log('ok oidc-login-invalid-password');
  await context.close();
}

async function runConsentDenied(browser) {
  const context = await newBrowserContext(browser, edgeA);
  const page = await context.newPage();

  await withPageState(page, 'consent denial check', async () =>
    withCallbackServer('consent denial check', async (redirectURI) => {
      await page.goto(buildAuthorizeURL(edgeA, consentClient.id, redirectURI, 'openid profile email'));
      await submitPasswordLogin(page, username, password);
      await page.waitForURL(/\/oidc\/consent/, {timeout: 15000});

      const denyResponsePromise = page.waitForResponse((response) =>
        response.url().includes('/oidc/consent') && response.request().method() === 'POST',
      {timeout: 15000});
      await page.click('button[name="submit"][value="deny"]');
      const denyResponse = await denyResponsePromise;

      assert.equal(denyResponse.status(), 403, 'consent denial must return HTTP 403');
      await expectPageText(page, /Consent denied/);
    }));

  console.log('ok oidc-consent-denied');
  await context.close();
}

async function runCSRFAndSessionAttackFailures(browser) {
  await runLoginCSRFMissing(browser);
  await runLoginCSRFForeignToken(browser);
  await runConsentCSRFMissing(browser);
  await runConsentCSRFForeignToken(browser);
  await runTamperedSessionCookie(browser);
  await runSessionFixationIgnored(browser);
  await runFlowReplayAfterCallback(browser);
}

async function runLoginCSRFMissing(browser) {
  const context = await newBrowserContext(browser, edgeA);
  const page = await context.newPage();

  await page.goto(buildAuthorizeURL(edgeA, browserClient.id, defaultRedirectURI(), 'openid profile email'));
  const result = await submitSameOriginForm(page, '/login', {
    username,
    password,
  });

  assert.equal(result.status, 400, `login without CSRF token must fail: ${result.text}`);
  console.log('ok oidc-login-csrf-missing-rejected');
  await context.close();
}

async function runLoginCSRFForeignToken(browser) {
  const contextA = await newBrowserContext(browser, edgeA);
  const pageA = await contextA.newPage();
  await pageA.goto(buildAuthorizeURL(edgeA, browserClient.id, defaultRedirectURI(), 'openid profile email'));
  const foreignToken = await extractCSRFToken(pageA);

  const contextB = await newBrowserContext(browser, edgeA);
  const pageB = await contextB.newPage();
  await pageB.goto(buildAuthorizeURL(edgeA, browserClient.id, defaultRedirectURI(), 'openid profile email'));
  const result = await submitSameOriginForm(pageB, '/login', {
    csrf_token: foreignToken,
    username,
    password,
  });

  assert.equal(result.status, 400, `login with a foreign CSRF token must fail: ${result.text}`);
  console.log('ok oidc-login-csrf-foreign-token-rejected');
  await contextA.close();
  await contextB.close();
}

async function runConsentCSRFMissing(browser) {
  const context = await newBrowserContext(browser, edgeA);
  const page = await context.newPage();

  await openOIDCConsentPage(page);
  const challenge = await page.locator('input[name="consent_challenge"]').inputValue();
  const result = await submitSameOriginForm(page, '/oidc/consent', {
    consent_challenge: challenge,
    submit: 'deny',
  });

  assert.equal(result.status, 400, `consent without CSRF token must fail: ${result.text}`);
  console.log('ok oidc-consent-csrf-missing-rejected');
  await context.close();
}

async function runConsentCSRFForeignToken(browser) {
  const contextA = await newBrowserContext(browser, edgeA);
  const pageA = await contextA.newPage();
  await openOIDCConsentPage(pageA);
  const foreignToken = await extractCSRFToken(pageA);

  const contextB = await newBrowserContext(browser, edgeA);
  const pageB = await contextB.newPage();
  await openOIDCConsentPage(pageB);
  const challenge = await pageB.locator('input[name="consent_challenge"]').inputValue();
  const result = await submitSameOriginForm(pageB, '/oidc/consent', {
    csrf_token: foreignToken,
    consent_challenge: challenge,
    submit: 'deny',
  });

  assert.equal(result.status, 400, `consent with a foreign CSRF token must fail: ${result.text}`);
  console.log('ok oidc-consent-csrf-foreign-token-rejected');
  await contextA.close();
  await contextB.close();
}

async function runTamperedSessionCookie(browser) {
  const context = await newBrowserContext(browser, edgeA);
  await context.addCookies([{
    name: 'secure_data',
    value: 'not-valid-cookie-data',
    domain: 'split.example.test',
    path: '/',
    secure: true,
    httpOnly: true,
    sameSite: 'Lax',
  }]);

  const page = await context.newPage();
  const response = await page.goto(`${edgeA}/login`);

  assert.equal(response.status(), 400, 'tampered session cookie must not create a valid IdP flow');
  await expectPageText(page, /Invalid Request/);
  console.log('ok oidc-session-tampered-cookie-rejected');
  await context.close();
}

async function runSessionFixationIgnored(browser) {
  const context = await newBrowserContext(browser, edgeA);
  await context.addCookies([{
    name: 'secure_data',
    value: 'attacker-fixed-cookie',
    domain: 'split.example.test',
    path: '/',
    secure: true,
    httpOnly: true,
    sameSite: 'Lax',
  }]);
  const page = await context.newPage();

  const callback = await withPageState(page, 'session fixation check', async () =>
    withCallbackServer('session fixation check', async (redirectURI, callbackPromise) => {
      await page.goto(buildAuthorizeURL(edgeA, browserClient.id, redirectURI, 'openid profile email'));
      await submitPasswordLogin(page, `${username}.session-fixation`, password);

      return callbackPromise;
    }));

  assert.ok(callback.code, 'login with an attacker-fixed invalid cookie must still create fresh flow state');
  console.log('ok oidc-session-fixation-cookie-ignored');
  await context.close();
}

async function runFlowReplayAfterCallback(browser) {
  const context = await newBrowserContext(browser, edgeA);
  const page = await context.newPage();

  const callback = await withPageState(page, 'flow replay check', async () =>
    withCallbackServer('flow replay check', async (redirectURI, callbackPromise) => {
      await page.goto(buildAuthorizeURL(edgeA, browserClient.id, redirectURI, 'openid profile email'));
      await submitPasswordLogin(page, `${username}.flow-replay`, password);

      return callbackPromise;
    }));

  assert.ok(callback.code, 'flow replay setup must complete a real OIDC callback');

  const replayA = await page.goto(`${edgeA}/login`);
  assert.equal(replayA.status(), 400, 'completed OIDC flow must not leave reusable /login state on edge-a');
  console.log('ok oidc-flow-replay-after-callback-rejected');

  const replayB = await page.goto(`${edgeB}/login`);
  assert.equal(replayB.status(), 400, 'completed OIDC flow must not leave reusable /login state on edge-b');
  console.log('ok oidc-cross-edge-flow-replay-after-callback-rejected');
  await context.close();
}

async function openOIDCConsentPage(page) {
  await page.goto(buildAuthorizeURL(edgeA, consentClient.id, defaultRedirectURI(), 'openid profile email'));
  await submitPasswordLogin(page, `${username}.consent-csrf`, password);
  await page.waitForURL(/\/oidc\/consent/, {timeout: 15000});
}

async function runTokenEndpointFailures(browser) {
  await expectFormError(`${edgeAAPI}/oidc/token`, {
    grant_type: 'authorization_code',
    client_id: browserClient.id,
    client_secret: `${browserClient.secret}-wrong`,
    code: 'invalid-code',
    redirect_uri: defaultRedirectURI(),
  }, 401, 'invalid_client', 'oidc-token-invalid-client-secret');

  await expectFormError(`${edgeAAPI}/oidc/token`, {
    grant_type: 'authorization_code',
    client_id: browserClient.id,
    client_secret: browserClient.secret,
    code: 'invalid-code',
    redirect_uri: defaultRedirectURI(),
  }, 400, 'invalid_grant', 'oidc-token-invalid-code');

  await expectFormError(`${edgeAAPI}/oidc/token`, {
    grant_type: 'password',
    client_id: browserClient.id,
    client_secret: browserClient.secret,
    username,
    password,
  }, 400, 'unsupported_grant_type', 'oidc-token-unsupported-grant');

  await expectJSONBodyOAuthError(`${edgeAAPI}/oidc/token`, {
    grant_type: 'authorization_code',
    client_id: browserClient.id,
    client_secret: browserClient.secret,
    code: 'invalid-code',
    redirect_uri: defaultRedirectURI(),
  }, 401, 'invalid_client', 'oidc-token-json-body-rejected');

  for (const [duplicateKey, okName] of [
    ['client_id', 'oidc-token-duplicate-client-id-rejected'],
    ['code', 'oidc-token-duplicate-code-rejected'],
    ['redirect_uri', 'oidc-token-duplicate-redirect-uri-rejected'],
  ]) {
    await expectFormError(
      `${edgeAAPI}/oidc/token`,
      duplicateTokenForm(duplicateKey),
      400,
      'invalid_request',
      okName,
    );
  }

  await expectFormError(`${edgeAAPI}/oidc/token`, {
    grant_type: 'authorization_code',
    client_id: browserClient.id,
    client_secret: browserClient.secret,
    code: 'invalid-code',
    redirect_uri: defaultRedirectURI(),
  }, 401, 'invalid_client', 'oidc-token-combined-client-auth-rejected', {
    headers: {
      authorization: `Basic ${Buffer.from(`${browserClient.id}:${browserClient.secret}`).toString('base64')}`,
    },
  });

  const redirectMismatchCode = await issueAuthorizationCode(browser, browserClient, `${username}.redirect-mismatch`);
  await expectFormError(`${edgeAAPI}/oidc/token`, {
    grant_type: 'authorization_code',
    client_id: browserClient.id,
    client_secret: browserClient.secret,
    code: redirectMismatchCode.code,
    redirect_uri: 'https://split.example.test:19094/other-callback',
  }, 400, 'invalid_grant', 'oidc-token-redirect-mismatch-rejected');

  const missingVerifier = pkceVerifier();
  const missingVerifierCode = await issueAuthorizationCode(
    browser,
    browserClient,
    `${username}.pkce-missing`,
    {authOptions: {code_challenge: pkceChallenge(missingVerifier), code_challenge_method: 'S256'}},
  );
  await expectFormError(`${edgeAAPI}/oidc/token`, {
    grant_type: 'authorization_code',
    client_id: browserClient.id,
    client_secret: browserClient.secret,
    code: missingVerifierCode.code,
    redirect_uri: missingVerifierCode.redirectURI,
  }, 400, 'invalid_grant', 'oidc-token-pkce-missing-verifier-rejected');

  const wrongVerifier = pkceVerifier();
  const wrongVerifierCode = await issueAuthorizationCode(
    browser,
    browserClient,
    `${username}.pkce-wrong`,
    {authOptions: {code_challenge: pkceChallenge(wrongVerifier), code_challenge_method: 'S256'}},
  );
  await expectFormError(`${edgeAAPI}/oidc/token`, {
    grant_type: 'authorization_code',
    client_id: browserClient.id,
    client_secret: browserClient.secret,
    code: wrongVerifierCode.code,
    redirect_uri: wrongVerifierCode.redirectURI,
    code_verifier: pkceVerifier(),
  }, 400, 'invalid_grant', 'oidc-token-pkce-wrong-verifier-rejected');

  const clientConfusionCode = await issueAuthorizationCode(browser, browserClient, `${username}.client-confusion`);
  await expectFormError(`${edgeAAPI}/oidc/token`, {
    grant_type: 'authorization_code',
    client_id: consentClient.id,
    client_secret: consentClient.secret,
    code: clientConfusionCode.code,
    redirect_uri: clientConfusionCode.redirectURI,
  }, 400, 'invalid_grant', 'oidc-token-code-client-confusion-rejected');

  const reusableCode = await issueAuthorizationCode(browser, browserClient, `${username}.code-reuse`);
  const token = await exchangeCode(edgeAAPI, browserClient, reusableCode.code, reusableCode.redirectURI);
  assert.ok(token.access_token, 'first exchange for code-reuse check must succeed');
  await expectFormError(`${edgeAAPI}/oidc/token`, {
    grant_type: 'authorization_code',
    client_id: browserClient.id,
    client_secret: browserClient.secret,
    code: reusableCode.code,
    redirect_uri: reusableCode.redirectURI,
  }, 400, 'invalid_grant', 'oidc-token-code-reuse-rejected');

  const refreshMismatchToken = await issueRefreshToken(browser, `${username}.refresh-mismatch`);
  await expectFormError(`${edgeAAPI}/oidc/token`, {
    grant_type: 'refresh_token',
    client_id: consentClient.id,
    client_secret: consentClient.secret,
    refresh_token: refreshMismatchToken.refresh_token,
  }, 400, 'invalid_grant', 'oidc-token-refresh-client-mismatch-rejected');

  const refreshReuseToken = await issueRefreshToken(browser, `${username}.refresh-reuse`);
  const rotatedRefresh = await postForm(`${edgeAAPI}/oidc/token`, {
    grant_type: 'refresh_token',
    client_id: browserClient.id,
    client_secret: browserClient.secret,
    refresh_token: refreshReuseToken.refresh_token,
  });
  assert.ok(rotatedRefresh.access_token, 'refresh-token reuse setup must return a new access token');
  await expectFormError(`${edgeAAPI}/oidc/token`, {
    grant_type: 'refresh_token',
    client_id: browserClient.id,
    client_secret: browserClient.secret,
    refresh_token: refreshReuseToken.refresh_token,
  }, 400, 'invalid_grant', 'oidc-token-refresh-reuse-rejected');

  const logoutToken = await issueRefreshToken(browser, `${username}.refresh-logout`);
  await fetch(`${edgeAAPI}/oidc/logout?id_token_hint=${encodeURIComponent(logoutToken.id_token)}`);
  await expectFormError(`${edgeAAPI}/oidc/token`, {
    grant_type: 'refresh_token',
    client_id: browserClient.id,
    client_secret: browserClient.secret,
    refresh_token: logoutToken.refresh_token,
  }, 400, 'invalid_grant', 'oidc-token-refresh-after-logout-rejected');

  await runIntrospectionAndMetadataFailures();
}

async function runUserInfoFailures() {
  await expectJSONError(`${edgeAAPI}/oidc/userinfo`, {}, 401, 'missing_token', 'oidc-userinfo-missing-token');
  await expectJSONError(`${edgeAAPI}/oidc/userinfo`, {
    headers: {
      authorization: 'Bearer not-a-real-access-token',
    },
  }, 401, 'invalid_token', 'oidc-userinfo-invalid-token');
}

async function runIntrospectionAndMetadataFailures() {
  await expectFormError(`${edgeAAPI}/oidc/introspect`, {
    token: 'not-a-real-access-token',
    client_id: browserClient.id,
    client_secret: `${browserClient.secret}-wrong`,
  }, 401, 'invalid_client', 'oidc-introspect-invalid-client-secret');

  await expectIntrospectionInactive(
    unsignedJWT({alg: 'none', typ: 'JWT'}, {sub: 'attacker', aud: browserClient.id}),
    'oidc-introspect-alg-none-token-inactive',
  );

  await expectIntrospectionInactive(
    `${base64URLJSON({alg: 'RS256', typ: 'JWT', kid: 'unknown-kid'})}.${base64URLJSON({sub: 'attacker', aud: browserClient.id})}.signature`,
    'oidc-introspect-unknown-kid-token-inactive',
  );

  const revokeResponse = await fetch(`${edgeAAPI}/oidc/revoke`, {method: 'POST'});
  assert.equal(revokeResponse.status, 404, `unexpected revocation endpoint exposure: ${await revokeResponse.text()}`);
  console.log('ok oidc-revoke-endpoint-not-exposed');

  const discoveryResponse = await fetch(`${edgeAAPI}/.well-known/openid-configuration`);
  const discovery = await discoveryResponse.json();
  assert.equal(discoveryResponse.status, 200, 'OIDC discovery must be readable');
  assert.equal(discovery.issuer, edgeA, 'discovery issuer must stay on the public edge URL');
  assert.ok(discovery.authorization_endpoint.startsWith(edgeA), 'authorization endpoint must use the public edge URL');
  assert.ok(discovery.token_endpoint.startsWith(edgeA), 'token endpoint must use the public edge URL');
  assert.ok(discovery.code_challenge_methods_supported.includes('S256'), 'discovery must advertise S256 PKCE');
  assert.ok(!discovery.code_challenge_methods_supported.includes('plain'), 'discovery must not advertise PKCE plain');
  console.log('ok oidc-discovery-metadata-consistent');
}

async function runDeviceEndpointFailures(browser) {
  await expectFormError(`${edgeAAPI}/oidc/device`, {
    scope: 'openid',
  }, 400, 'invalid_request', 'oidc-device-missing-client');

  await expectFormError(`${edgeAAPI}/oidc/device`, {
    client_id: 'missing-client',
    scope: 'openid',
  }, 401, 'invalid_client', 'oidc-device-invalid-client');

  await expectFormError(`${edgeAAPI}/oidc/device`, {
    client_id: mfaClient.id,
    scope: 'openid',
  }, 400, 'unauthorized_client', 'oidc-device-unsupported-client');

  const device = await postForm(`${edgeAAPI}/oidc/device`, {
    client_id: browserClient.id,
    client_secret: browserClient.secret,
    scope: 'openid profile email',
  });

  await expectFormError(`${edgeAAPI}/oidc/token`, {
    grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
    client_id: browserClient.id,
    client_secret: browserClient.secret,
    device_code: device.device_code,
  }, 400, 'authorization_pending', 'oidc-device-token-authorization-pending');

  await expectFormError(`${edgeAAPI}/oidc/token`, {
    grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
    client_id: browserClient.id,
    client_secret: browserClient.secret,
    device_code: device.device_code,
  }, 400, 'slow_down', 'oidc-device-token-slow-down');

  await expectFormError(`${edgeAAPI}/oidc/token`, {
    grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
    client_id: browserClient.id,
    client_secret: browserClient.secret,
    device_code: 'expired-or-missing-device-code',
  }, 400, 'expired_token', 'oidc-device-token-expired-code');

  const clientMismatchDevice = await postForm(`${edgeAAPI}/oidc/device`, {
    client_id: browserClient.id,
    client_secret: browserClient.secret,
    scope: 'openid profile email',
  });
  await expectFormError(`${edgeAAPI}/oidc/token`, {
    grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
    client_id: deviceAttackerClient.id,
    client_secret: deviceAttackerClient.secret,
    device_code: clientMismatchDevice.device_code,
  }, 400, 'invalid_grant', 'oidc-device-token-client-mismatch-rejected');

  await runInvalidDeviceUserCodeAttempt(browser, 'INVALID1', 'oidc-device-invalid-user-code');
  await runInvalidDeviceUserCodeAttempt(browser, 'ＡＢＣＤＥＦＧＨ', 'oidc-device-unicode-user-code-rejected');

  for (const bruteCode of ['AAAA1111', 'BBBB2222', 'CCCC3333']) {
    await runInvalidDeviceUserCodeAttempt(browser, bruteCode, '', false);
  }
  console.log('ok oidc-device-user-code-bruteforce-rejected');

  const deniedDevice = await postForm(`${edgeAAPI}/oidc/device`, {
    client_id: consentClient.id,
    client_secret: consentClient.secret,
    scope: 'openid profile email',
  });
  const context = await newBrowserContext(browser, edgeA);
  const page = await context.newPage();
  await page.goto(deniedDevice.verification_uri || `${edgeA}/oidc/device/verify`);
  await page.fill('input[name="user_code"]', deniedDevice.user_code);
  await page.fill('input[name="username"]', username);
  await page.fill('input[name="password"]', password);
  await page.click('button[type="submit"]');
  await page.waitForURL(/\/oidc\/device\/consent/, {timeout: 15000});
  await page.click('button[name="submit"][value="deny"]');
  await expectPageText(page, /Authorization denied/);
  await expectFormError(`${edgeAAPI}/oidc/token`, {
    grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
    client_id: consentClient.id,
    client_secret: consentClient.secret,
    device_code: deniedDevice.device_code,
  }, 400, 'access_denied', 'oidc-device-token-consent-denied');
  console.log('ok oidc-device-consent-denied');
  await context.close();
}

async function runDeviceCodeFlow(browser) {
  const device = await postForm(`${edgeAAPI}/oidc/device`, {
    client_id: browserClient.id,
    client_secret: browserClient.secret,
    scope: 'openid profile email',
  });
  assert.ok(device.device_code, 'device flow returned device_code');
  assert.ok(device.user_code, 'device flow returned user_code');

  const context = await newBrowserContext(browser, edgeA);
  const page = await context.newPage();
  await page.goto(device.verification_uri || `${edgeA}/oidc/device/verify`);
  await page.fill('input[name="user_code"]', device.user_code);
  await page.fill('input[name="username"]', username);
  await page.fill('input[name="password"]', password);
  await page.click('button[type="submit"]');
  await page.waitForLoadState('networkidle');

  const token = await pollDeviceToken(edgeAAPI, browserClient, device.device_code);
  assert.ok(token.access_token, 'device-code flow returned an access token');
  console.log('ok oidc-device-code-login');
  await expectFormError(`${edgeAAPI}/oidc/token`, {
    grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
    client_id: browserClient.id,
    client_secret: browserClient.secret,
    device_code: device.device_code,
  }, 400, 'expired_token', 'oidc-device-token-reuse-rejected');
  await context.close();
}

async function withPageState(page, label, run) {
  try {
    return await run();
  } catch (error) {
    error.message = `${error.message}; ${label} ended at ${page.url()}`;
    throw error;
  }
}

// runRequiredMFAFlows exercises required MFA enrollment and all browser-visible MFA login variants.
async function runRequiredMFAFlows(browser) {
  const registration = await registerRequiredMFAProfile(browser, {
    user: mfaUsername,
    label: 'required MFA registration',
    totpOKName: 'totp-registration',
    webAuthnOKName: 'webauthn-registration',
  });
  const recoveryCodes = registration.recoveryCodes;
  const totpSecret = registration.totpSecret;
  console.log('ok recovery-code-generation');
  let webAuthnCredentials = registration.webAuthnCredentials;

  const masterMFA = await registerMasterUserMFA(browser, webAuthnCredentials);
  webAuthnCredentials = masterMFA.webAuthnCredentials;

  await runNegativeMFAChecks(browser, webAuthnCredentials);
  await runTOTPLogin(browser, mfaClient, mfaUsername, totpSecret, 'TOTP login', 'oidc-totp-login');
  await runTOTPLogin(
    browser,
    delayedMFAClient,
    mfaUsername,
    totpSecret,
    'Delayed-response TOTP login',
    'oidc-delayed-response-totp-login',
  );
  await runDelayedResponseTOTPFailure(
    browser,
    mfaUsername,
    totpSecret,
    'Delayed-response TOTP wrong password',
    'oidc-delayed-response-totp-wrong-password-rejected',
  );

  const webAuthnContext = await newBrowserContext(browser, edgeA);
  const webAuthnPage = await webAuthnContext.newPage();
  const webAuthnAuthenticator = await installVirtualAuthenticator(webAuthnPage);
  await importVirtualAuthenticatorCredentials(webAuthnAuthenticator, webAuthnCredentials);
  const webAuthnLogin = await withPageState(webAuthnPage, 'WebAuthn login', async () =>
    withCallbackServer('WebAuthn login', async (redirectURI, callbackPromise) => {
    await webAuthnPage.goto(buildAuthorizeURL(edgeA, mfaClient.id, redirectURI, 'openid profile email'));
    await submitPasswordLogin(webAuthnPage, mfaUsername, password);
    await completeWebAuthnLogin(webAuthnPage, edgeA);

    return callbackPromise;
  }));
  assert.ok(webAuthnLogin.code, 'WebAuthn login completed the OIDC flow');
  console.log('ok webauthn-login');
  let updatedWebAuthnCredentials = await exportVirtualAuthenticatorCredentials(webAuthnAuthenticator);
  await webAuthnContext.close();

  const delayedWebAuthnLogin = await runWebAuthnLogin(
    browser,
    delayedMFAClient,
    mfaUsername,
    updatedWebAuthnCredentials,
    'Delayed-response WebAuthn login',
    'oidc-delayed-response-webauthn-login',
  );
  updatedWebAuthnCredentials = delayedWebAuthnLogin.webAuthnCredentials;
  await runMasterUserTOTPLogin(browser, mfaClient, masterMFA.totpSecret, 'oidc-master-user-totp-login');
  await runMasterUserTOTPLogin(
    browser,
    delayedMFAClient,
    masterMFA.totpSecret,
    'oidc-delayed-response-master-user-totp-login',
  );
  await runDelayedResponseTOTPFailure(
    browser,
    masterUserLogin,
    masterMFA.totpSecret,
    'Delayed-response Master-User TOTP wrong password',
    'oidc-delayed-response-master-user-totp-wrong-password-rejected',
  );
  await runMasterUserWithoutMFAAllowed(browser, browserClient, 'oidc-master-user-without-mfa-login');
  await runMasterUserWithoutMFARejected(browser, mfaClient, 'oidc-master-user-without-mfa-require-mfa-rejected');
  await runMasterUserWithoutMFARejected(
    browser,
    delayedMFAClient,
    'oidc-delayed-response-master-user-without-mfa-require-mfa-rejected',
  );
  updatedWebAuthnCredentials = await runMasterUserWebAuthnLogin(
    browser,
    mfaClient,
    updatedWebAuthnCredentials,
    'oidc-master-user-webauthn-login',
  );
  updatedWebAuthnCredentials = await runMasterUserWebAuthnLogin(
    browser,
    delayedMFAClient,
    updatedWebAuthnCredentials,
    'oidc-delayed-response-master-user-webauthn-login',
  );
  updatedWebAuthnCredentials = await runWebAuthnAssertionReplay(browser, updatedWebAuthnCredentials);
  await runWebAuthnSignCountRollback(browser, webAuthnCredentials);

  await runRecoveryCodeMatrix(browser, {
    label: 'user recovery-code',
    login: mfaUsername,
    codes: recoveryCodes,
    normalLoginOK: 'oidc-recovery-code-login',
    delayedLoginOK: 'oidc-delayed-response-recovery-code-login',
    normalInvalidOK: 'oidc-recovery-invalid-code',
    delayedInvalidOK: 'oidc-delayed-response-recovery-invalid-code',
    delayedWrongPasswordOK: 'oidc-delayed-response-recovery-wrong-password-rejected',
    reuseOK: 'oidc-recovery-code-reuse-rejected',
  });
  await runRecoveryCodeMatrix(browser, {
    label: 'Master-User recovery-code',
    login: masterUserLogin,
    codes: masterMFA.recoveryCodes,
    expectedPreferredUsername: mfaUsername,
    forbiddenPreferredUsername: masterUserLogin,
    normalLoginOK: 'oidc-master-user-recovery-code-login',
    delayedLoginOK: 'oidc-delayed-response-master-user-recovery-code-login',
    normalInvalidOK: 'oidc-master-user-recovery-invalid-code',
    delayedInvalidOK: 'oidc-delayed-response-master-user-recovery-invalid-code',
    delayedWrongPasswordOK: 'oidc-delayed-response-master-user-recovery-wrong-password-rejected',
    reuseOK: 'oidc-master-user-recovery-code-reuse-rejected',
  });
  await runMFASelfServiceStepUpChecks(browser);

  return updatedWebAuthnCredentials;
}

// runMFASelfServiceStepUpChecks proves browser self-service mutations require fresh MFA.
async function runMFASelfServiceStepUpChecks(browser) {
  const registration = await registerRequiredMFAProfile(browser, {
    user: selfServiceUsername,
    label: 'self-service MFA registration',
  });

  await runMFASelfServiceMissingStepUpRejected(browser);

  const context = await newBrowserContext(browser, edgeA);
  const page = await context.newPage();
  const authenticator = await installVirtualAuthenticator(page);
  await importVirtualAuthenticatorCredentials(authenticator, registration.webAuthnCredentials);

  await withPageState(page, 'self-service fresh step-up', async () =>
    withCallbackServer('self-service fresh step-up', async (redirectURI, callbackPromise) => {
      await page.goto(buildAuthorizeURL(edgeA, mfaClient.id, redirectURI, 'openid profile email'));
      await submitPasswordLogin(page, selfServiceUsername, password);
      await completeWebAuthnLogin(page, edgeA);

      return callbackPromise;
    }));

  await page.goto(`${edgeA}/mfa/register/home`);
  await expectPageText(page, /2FA Self-Service/);

  const recoveryResult = await submitSelfServiceMutation(page, 'POST', '/mfa/recovery/generate');
  assert.equal(recoveryResult.status, 200, `fresh step-up recovery regeneration failed: ${recoveryResult.text}`);
  assert.match(recoveryResult.text, /New recovery codes/i);
  console.log('ok mfa-self-service-recovery-regeneration-step-up');

  const totpResult = await submitSelfServiceMutation(page, 'DELETE', '/mfa/totp');
  assert.equal(totpResult.status, 200, `fresh step-up TOTP delete failed: ${totpResult.text}`);
  assert.match(totpResult.hxRedirect || '', /\/mfa\/register\/home/);
  console.log('ok mfa-self-service-totp-delete-step-up');

  await page.goto(`${edgeA}/mfa/webauthn/devices`);
  const deletePath = await page.locator('button[hx-delete^="/mfa/webauthn/device/"]').first().getAttribute('hx-delete');
  assert.ok(deletePath, 'self-service WebAuthn delete needs a registered device');
  const webAuthnResult = await submitSelfServiceMutation(page, 'DELETE', deletePath);
  assert.equal(webAuthnResult.status, 200, `fresh step-up WebAuthn delete failed: ${webAuthnResult.text}`);
  assert.match(webAuthnResult.hxRedirect || '', /\/mfa\/webauthn\/devices|\/mfa\/register\/home/);
  console.log('ok mfa-self-service-webauthn-delete-step-up');

  await context.close();
}

// runMFASelfServiceMissingStepUpRejected proves first-factor sessions cannot mutate MFA state.
async function runMFASelfServiceMissingStepUpRejected(browser) {
  const context = await newBrowserContext(browser, edgeA);
  const page = await context.newPage();

  await withPageState(page, 'self-service missing step-up rejection', async () =>
    withPassiveCallbackServer(async (redirectURI) => {
      await page.goto(buildAuthorizeURL(edgeA, browserClient.id, redirectURI, 'openid profile email'));
      await submitPasswordLogin(page, masterWithoutMFAUsername, password);

      await page.goto(`${edgeA}/mfa/register/home`);
      await expectPageText(page, /2FA Self-Service/);

      for (const mutation of [
        ['POST', '/mfa/recovery/generate'],
        ['DELETE', '/mfa/totp'],
        ['DELETE', '/mfa/webauthn/device/not-a-real-id'],
      ]) {
        const result = await submitSelfServiceMutation(page, mutation[0], mutation[1]);
        assert.equal(result.status, 200, `${mutation[0]} ${mutation[1]} returned unexpected status: ${result.text}`);
        assert.match(result.text, /Recent MFA verification required/i);
      }
    }));

  console.log('ok mfa-self-service-missing-step-up-rejected');
  await context.close();
}

// registerMasterUserMFA enrolls all MFA factors used by formatted Master-User logins.
async function registerMasterUserMFA(browser, webAuthnCredentials) {
  const registration = await registerRequiredMFAProfile(browser, {
    user: masterUsername,
    label: 'Master-User MFA registration',
    importWebAuthnCredentials: webAuthnCredentials,
  });
  console.log('ok master-user-mfa-registration');

  return {
    webAuthnCredentials: registration.webAuthnCredentials,
    recoveryCodes: registration.recoveryCodes,
    totpSecret: registration.totpSecret,
  };
}

// registerRequiredMFAProfile enrolls all MFA methods for a browser smoke user.
async function registerRequiredMFAProfile(browser, options) {
  const context = await newBrowserContext(browser, edgeA);
  const page = await context.newPage();
  const authenticator = await installVirtualAuthenticator(page);

  if (options.importWebAuthnCredentials) {
    await importVirtualAuthenticatorCredentials(authenticator, options.importWebAuthnCredentials);
  }

  let recoveryCodes = [];
  let totpSecret = '';
  const registration = await withPageState(page, options.label, async () =>
    withCallbackServer(options.label, async (redirectURI, callbackPromise) => {
      await page.goto(buildAuthorizeURL(edgeA, mfaClient.id, redirectURI, 'openid profile email'));
      await submitPasswordLogin(page, options.user, password);
      totpSecret = await completeTOTPRegistration(page);
      if (options.totpOKName) {
        console.log(`ok ${options.totpOKName}`);
      }

      await completeWebAuthnRegistration(page);
      if (options.webAuthnOKName) {
        console.log(`ok ${options.webAuthnOKName}`);
      }

      recoveryCodes = await completeRecoveryRegistration(page);

      return callbackPromise;
    }));
  assert.ok(registration.code, `${options.label} resumed the OIDC flow`);
  assert.ok(totpSecret, `${options.label} generated a TOTP secret`);
  assert.ok(recoveryCodes.length > 0, `${options.label} generated recovery codes`);

  const webAuthnCredentials = await exportVirtualAuthenticatorCredentials(authenticator);
  await context.close();

  return {
    webAuthnCredentials,
    recoveryCodes,
    totpSecret,
  };
}

async function runTOTPLogin(browser, client, user, secret, label, okName) {
  const context = await newBrowserContext(browser, edgeA);
  const page = await context.newPage();

  const callback = await withPageState(page, label, async () =>
    withCallbackServer(label, async (redirectURI, callbackPromise) => {
    await page.goto(buildAuthorizeURL(edgeA, client.id, redirectURI, 'openid profile email'));
    await submitPasswordLogin(page, user, password);
    await completeTOTPLogin(page, secret);

    return callbackPromise;
  }));
  assert.ok(callback.code, `${label} completed the OIDC flow`);
  console.log(`ok ${okName}`);
  await context.close();

  return callback;
}

async function runMasterUserTOTPLogin(browser, client, secret, okName) {
  const callback = await runTOTPLogin(
    browser,
    client,
    masterUserLogin,
    secret,
    'Master-User TOTP login',
    okName,
  );

  const token = await exchangeCode(edgeAAPI, client, callback.code, callback.redirectURI);
  assert.ok(token.id_token, 'Master-User TOTP login returned an ID token');

  const claims = decodeJWTClaims(token.id_token);
  assert.equal(claims.preferred_username, mfaUsername, 'Master-User TOTP login must issue the target username');
  assert.notEqual(claims.preferred_username, masterUserLogin, 'Master-User TOTP login must not leak the formatted login');
}

async function runDelayedResponseTOTPFailure(browser, user, secret, label, okName) {
  const context = await newBrowserContext(browser, edgeA);
  const page = await context.newPage();

  await withPageState(page, label, async () =>
    withCallbackServer(label, async (redirectURI) => {
      await page.goto(buildAuthorizeURL(edgeA, delayedMFAClient.id, redirectURI, 'openid profile email'));
      await submitPasswordLogin(page, user, `${password}-wrong`);
      await completeTOTPLogin(page, secret, {expectCallback: false});
      assert.match(page.url(), /\/login/, `${label} must return to the login flow`);
      await expectPageText(page, /Invalid login or password/);
    }));

  console.log(`ok ${okName}`);
  await context.close();
}

async function runMasterUserWithoutMFAAllowed(browser, client, okName) {
  const context = await newBrowserContext(browser, edgeA);
  const page = await context.newPage();

  const callback = await withPageState(page, 'Master-User without MFA login', async () =>
    withCallbackServer('Master-User without MFA login', async (redirectURI, callbackPromise) => {
      await page.goto(buildAuthorizeURL(edgeA, client.id, redirectURI, 'openid profile email'));
      await submitPasswordLogin(page, masterUserWithoutMFALogin, password);

      return callbackPromise;
    }));
  assert.ok(callback.code, 'Master-User without MFA completed the OIDC flow');

  const token = await exchangeCode(edgeAAPI, client, callback.code, callback.redirectURI);
  assert.ok(token.id_token, 'Master-User without MFA returned an ID token');

  const claims = decodeJWTClaims(token.id_token);
  assert.equal(claims.preferred_username, mfaUsername, 'Master-User without MFA must issue the target username');
  assert.notEqual(claims.preferred_username, masterUserWithoutMFALogin, 'Master-User without MFA must not leak the formatted login');
  console.log(`ok ${okName}`);
  await context.close();
}

// runMasterUserWithoutMFARejected proves require_mfa clients block master accounts without assurance.
async function runMasterUserWithoutMFARejected(browser, client, okName) {
  const context = await newBrowserContext(browser, edgeA);
  const page = await context.newPage();

  await withPageState(page, 'Master-User without MFA require_mfa rejection', async () =>
    withCallbackServer('Master-User without MFA require_mfa rejection', async (redirectURI) => {
      await page.goto(buildAuthorizeURL(edgeA, client.id, redirectURI, 'openid profile email'));
      await submitPasswordLogin(page, masterUserWithoutMFALogin, password);
      await page.waitForURL(/\/login\/(mfa|totp|webauthn|recovery)/, {timeout: 15000});
    }));

  console.log(`ok ${okName}`);
  await context.close();
}

async function runWebAuthnLogin(browser, client, user, webAuthnCredentials, label, okName) {
  const context = await newBrowserContext(browser, edgeA);
  const page = await context.newPage();
  const authenticator = await installVirtualAuthenticator(page);
  await importVirtualAuthenticatorCredentials(authenticator, webAuthnCredentials);

  const callback = await withPageState(page, label, async () =>
    withCallbackServer(label, async (redirectURI, callbackPromise) => {
    await page.goto(buildAuthorizeURL(edgeA, client.id, redirectURI, 'openid profile email'));
    await submitPasswordLogin(page, user, password);
    await completeWebAuthnLogin(page, edgeA);

    return callbackPromise;
  }));
  assert.ok(callback.code, `${label} completed the OIDC flow`);
  console.log(`ok ${okName}`);

  const updatedCredentials = await exportVirtualAuthenticatorCredentials(authenticator);
  await context.close();

  return {
    callback,
    webAuthnCredentials: updatedCredentials,
  };
}

async function runMasterUserWebAuthnLogin(browser, client, webAuthnCredentials, okName) {
  const login = await runWebAuthnLogin(browser, client, masterUserLogin, webAuthnCredentials, 'Master-User WebAuthn login', okName);

  const token = await exchangeCode(edgeAAPI, client, login.callback.code, login.callback.redirectURI);
  assert.ok(token.id_token, 'Master-User WebAuthn login returned an ID token');

  const claims = decodeJWTClaims(token.id_token);
  assert.equal(claims.preferred_username, mfaUsername, 'Master-User login must issue the target username');
  assert.notEqual(claims.preferred_username, masterUserLogin, 'Master-User login must not leak the formatted login');

  return login.webAuthnCredentials;
}

async function runNegativeMFAChecks(browser, webAuthnCredentials) {
  await runWebAuthnMissingCredential(browser);
  await runWebAuthnTamperedAssertion(browser, webAuthnCredentials);
  await runWebAuthnWrongChallenge(browser, webAuthnCredentials);
  await runWebAuthnWrongOrigin(browser, webAuthnCredentials);
  await runWebAuthnUnknownCredential(browser, webAuthnCredentials);
  await runInvalidTOTPCode(browser);
}

async function runWebAuthnMissingCredential(browser) {
  const context = await newBrowserContext(browser, edgeA);
  const page = await context.newPage();
  await installVirtualAuthenticator(page);

  await withPageState(page, 'missing WebAuthn credential check', async () =>
    withCallbackServer('missing WebAuthn credential check', async (redirectURI) => {
      await startMFAChallenge(page, redirectURI);
      if (!/\/login\/webauthn/.test(page.url())) {
        await page.goto(`${edgeA}/login/webauthn`);
      }

      await page.click('#login-button');
      await page.waitForSelector('#webauthn-error:not(.hidden)', {timeout: 15000});
      await expectWebAuthnError(page, /credential|not allowed|timed out|unknown/i);
    }));

  console.log('ok oidc-webauthn-missing-credential');
  await context.close();
}

async function runWebAuthnTamperedAssertion(browser, webAuthnCredentials) {
  await runWebAuthnTamperCase(
    browser,
    webAuthnCredentials,
    'tampered WebAuthn assertion check',
    'oidc-webauthn-tampered-assertion',
    (body) => {
      body.response = body.response || {};
      body.response.signature = base64URL(Buffer.from('tampered-signature'));
    },
    /signature|verification|invalid|error/i,
  );
}

async function runWebAuthnWrongChallenge(browser, webAuthnCredentials) {
  await runWebAuthnTamperCase(
    browser,
    webAuthnCredentials,
    'wrong WebAuthn challenge check',
    'oidc-webauthn-wrong-challenge',
    (body) => mutateWebAuthnClientData(body, (clientData) => {
      clientData.challenge = base64URL(crypto.randomBytes(32));
    }),
    /challenge|verification|invalid|error/i,
  );
}

async function runWebAuthnWrongOrigin(browser, webAuthnCredentials) {
  await runWebAuthnTamperCase(
    browser,
    webAuthnCredentials,
    'wrong WebAuthn origin check',
    'oidc-webauthn-wrong-origin',
    (body) => mutateWebAuthnClientData(body, (clientData) => {
      clientData.origin = 'https://evil.example.test';
    }),
    /origin|verification|invalid|error/i,
  );
}

async function runWebAuthnUnknownCredential(browser, webAuthnCredentials) {
  await runWebAuthnTamperCase(
    browser,
    webAuthnCredentials,
    'unknown WebAuthn credential check',
    'oidc-webauthn-unknown-credential',
    (body) => {
      const credentialID = base64URL(crypto.randomBytes(32));
      body.id = credentialID;
      body.rawId = credentialID;
    },
    /credential|verification|invalid|error/i,
  );
}

async function runWebAuthnTamperCase(browser, webAuthnCredentials, label, okName, mutateBody, pattern) {
  const context = await newBrowserContext(browser, edgeA);
  const page = await context.newPage();
  const authenticator = await installVirtualAuthenticator(page);
  await importVirtualAuthenticatorCredentials(authenticator, webAuthnCredentials);

  await withPageState(page, label, async () =>
    withCallbackServer(label, async (redirectURI) => {
      await startMFAChallenge(page, redirectURI);
      if (!/\/login\/webauthn/.test(page.url())) {
        await page.goto(`${edgeA}/login/webauthn`);
      }

      await page.route('**/login/webauthn/finish', async (route) => {
        const request = route.request();
        const body = JSON.parse(request.postData() || '{}');
        mutateBody(body);

        await route.continue({
          headers: {
            ...request.headers(),
            'content-type': 'application/json',
          },
          postData: JSON.stringify(body),
        });
      });

      const finishResponsePromise = page.waitForResponse((response) =>
        response.url().includes('/login/webauthn/finish') && response.request().method() === 'POST',
      {timeout: 15000});
      await page.click('#login-button');
      const finishResponse = await finishResponsePromise;

      assert.equal(finishResponse.status(), 400, `${okName} must fail closed`);
      await page.waitForSelector('#webauthn-error:not(.hidden)', {timeout: 15000});
      await expectWebAuthnError(page, pattern);
    }));

  console.log(`ok ${okName}`);
  await context.close();
}

async function runWebAuthnAssertionReplay(browser, webAuthnCredentials) {
  const context = await newBrowserContext(browser, edgeA);
  const page = await context.newPage();
  const authenticator = await installVirtualAuthenticator(page);
  await importVirtualAuthenticatorCredentials(authenticator, webAuthnCredentials);

  let capturedBody = '';
  let capturedCSRF = '';
  const callback = await withPageState(page, 'WebAuthn replay setup', async () =>
    withCallbackServer('WebAuthn replay setup', async (redirectURI, callbackPromise) => {
      await startMFAChallenge(page, redirectURI);
      if (!/\/login\/webauthn/.test(page.url())) {
        await page.goto(`${edgeA}/login/webauthn`);
      }

      await page.route('**/login/webauthn/finish', async (route) => {
        const request = route.request();
        const headers = request.headers();
        capturedBody = request.postData() || '';
        capturedCSRF = headers['x-csrf-token'] || headers['X-CSRF-Token'] || '';

        await route.continue();
      });

      await completeWebAuthnLogin(page, edgeA);

      return callbackPromise;
    }));

  assert.ok(callback.code, 'WebAuthn replay setup must complete the first login');
  assert.ok(capturedBody, 'WebAuthn replay setup captured an assertion body');
  await page.goto(`${edgeA}/login`);
  const replay = await page.evaluate(async ({body, csrf}) => {
    const response = await fetch('/login/webauthn/finish', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'x-csrf-token': csrf,
      },
      body,
    });

    return {status: response.status, text: await response.text()};
  }, {body: capturedBody, csrf: capturedCSRF});

  assert.equal(replay.status, 400, `replayed WebAuthn assertion must fail closed: ${replay.text}`);
  console.log('ok oidc-webauthn-replay-assertion');

  const updatedCredentials = await exportVirtualAuthenticatorCredentials(authenticator);
  await context.close();

  return updatedCredentials;
}

async function runWebAuthnSignCountRollback(browser, webAuthnCredentials) {
  const context = await newBrowserContext(browser, edgeA);
  const page = await context.newPage();
  const authenticator = await installVirtualAuthenticator(page);
  await importVirtualAuthenticatorCredentials(authenticator, webAuthnCredentials);

  await withPageState(page, 'WebAuthn sign-count rollback check', async () =>
    withCallbackServer('WebAuthn sign-count rollback check', async (redirectURI) => {
      await startMFAChallenge(page, redirectURI);
      if (!/\/login\/webauthn/.test(page.url())) {
        await page.goto(`${edgeA}/login/webauthn`);
      }

      const finishResponsePromise = page.waitForResponse((response) =>
        response.url().includes('/login/webauthn/finish') && response.request().method() === 'POST',
      {timeout: 15000});
      await page.click('#login-button');
      const finishResponse = await finishResponsePromise;

      assert.equal(finishResponse.status(), 400, 'stale WebAuthn sign count must fail closed');
      await page.waitForSelector('#webauthn-error:not(.hidden)', {timeout: 15000});
      await expectWebAuthnError(page, /sign count|rollback|invalid|error/i);
    }));

  console.log('ok oidc-webauthn-sign-count-rollback');
  await context.close();
}

async function runInvalidTOTPCode(browser) {
  const context = await newBrowserContext(browser, edgeA);
  const page = await context.newPage();

  await withPageState(page, 'invalid TOTP code check', async () =>
    withCallbackServer('invalid TOTP code check', async (redirectURI) => {
      await startMFAChallenge(page, redirectURI);
      if (!/\/login\/totp/.test(page.url())) {
        await page.goto(`${edgeA}/login/totp`);
      }

      const responsePromise = page.waitForResponse((response) =>
        response.url().includes('/login/totp') && response.request().method() === 'POST',
      {timeout: 15000});
      await page.fill('input[name="code"]', '0000000000000000');
      await page.click('button[type="submit"]');
      const response = await responsePromise;

      assert.equal(response.status(), 200, 'invalid TOTP must render the verification page again');
      await expectPageText(page, /Invalid OTP code/);
    }));

  console.log('ok oidc-totp-invalid-code');
  await context.close();
}

// runInvalidRecoveryCode verifies that a malformed recovery code never advances the active MFA flow.
async function runInvalidRecoveryCode(browser, options = {}) {
  const client = options.client || mfaClient;
  const user = options.user || mfaUsername;
  const okName = options.okName || 'oidc-recovery-invalid-code';
  const label = options.label || 'invalid recovery code check';
  const context = await newBrowserContext(browser, edgeA);
  const page = await context.newPage();

  await withPageState(page, label, async () =>
    withCallbackServer(label, async (redirectURI) => {
      await startMFAChallenge(page, redirectURI, {client, user});
      if (!/\/login\/recovery/.test(page.url())) {
        await page.goto(`${edgeA}/login/recovery`);
      }

      const responsePromise = page.waitForResponse((response) =>
        response.url().includes('/login/recovery') && response.request().method() === 'POST',
      {timeout: 15000});
      await page.fill('input[name="code"]', 'not-a-valid-recovery-code');
      await page.click('button[type="submit"]');
      const response = await responsePromise;

      assert.equal(response.status(), 200, 'invalid recovery code must render the verification page again');
      await expectPageText(page, /Invalid recovery code/);
    }));

  console.log(`ok ${okName}`);
  await context.close();
}

// runRecoveryCodeMatrix covers normal and delayed recovery-code logins for one principal.
async function runRecoveryCodeMatrix(browser, profile) {
  assertRecoveryCodes(profile.label, profile.codes, 3);
  await runInvalidRecoveryCode(browser, {
    user: profile.login,
    client: mfaClient,
    label: `${profile.label} invalid recovery code`,
    okName: profile.normalInvalidOK,
  });
  await runRecoveryCodeLogin(browser, {
    user: profile.login,
    client: mfaClient,
    code: profile.codes[0],
    label: `${profile.label} login`,
    okName: profile.normalLoginOK,
    expectedPreferredUsername: profile.expectedPreferredUsername,
    forbiddenPreferredUsername: profile.forbiddenPreferredUsername,
  });
  await runInvalidRecoveryCode(browser, {
    user: profile.login,
    client: delayedMFAClient,
    label: `delayed-response ${profile.label} invalid recovery code`,
    okName: profile.delayedInvalidOK,
  });
  await runRecoveryCodeLogin(browser, {
    user: profile.login,
    client: delayedMFAClient,
    code: profile.codes[1],
    label: `delayed-response ${profile.label} login`,
    okName: profile.delayedLoginOK,
    expectedPreferredUsername: profile.expectedPreferredUsername,
    forbiddenPreferredUsername: profile.forbiddenPreferredUsername,
  });
  await runDelayedResponseRecoveryFailure(browser, {
    user: profile.login,
    code: profile.codes[2],
    label: `delayed-response ${profile.label} wrong password`,
    okName: profile.delayedWrongPasswordOK,
  });
  await runRecoveryCodeReuseRejected(browser, {
    user: profile.login,
    code: profile.codes[0],
    label: `${profile.label} recovery-code reuse check`,
    okName: profile.reuseOK,
  });
}

// assertRecoveryCodes validates that a registration produced enough unique one-time codes for the matrix.
function assertRecoveryCodes(label, codes, minCount) {
  assert.ok(Array.isArray(codes), `${label} recovery codes must be an array`);
  assert.ok(codes.length >= minCount, `${label} needs at least ${minCount} recovery codes`);
  assert.equal(new Set(codes).size, codes.length, `${label} recovery codes must be unique`);
}

// runRecoveryCodeLogin completes an OIDC flow by submitting one valid recovery code.
async function runRecoveryCodeLogin(browser, options) {
  const context = await newBrowserContext(browser, edgeA);
  const page = await context.newPage();
  const label = options.label || 'recovery-code login';
  const client = options.client || mfaClient;

  const callback = await withPageState(page, label, async () =>
    withCallbackServer(label, async (redirectURI, callbackPromise) => {
      await page.goto(buildAuthorizeURL(edgeA, client.id, redirectURI, 'openid profile email'));
      await submitPasswordLogin(page, options.user, password);
      await completeRecoveryLogin(page, options.code);

      return callbackPromise;
    }));
  assert.ok(callback.code, `${label} completed the OIDC flow`);

  if (options.expectedPreferredUsername) {
    const token = await exchangeCode(edgeAAPI, client, callback.code, callback.redirectURI);
    assert.ok(token.id_token, `${label} returned an ID token`);

    const claims = decodeJWTClaims(token.id_token);
    assert.equal(claims.preferred_username, options.expectedPreferredUsername, `${label} must issue the target username`);
    assert.notEqual(claims.preferred_username, options.forbiddenPreferredUsername, `${label} must not leak the formatted login`);
  }

  console.log(`ok ${options.okName}`);
  await context.close();

  return callback;
}

// runDelayedResponseRecoveryFailure proves that delayed_response defers primary auth failure until after recovery MFA.
async function runDelayedResponseRecoveryFailure(browser, options) {
  const context = await newBrowserContext(browser, edgeA);
  const page = await context.newPage();

  await withPageState(page, options.label, async () =>
    withCallbackServer(options.label, async (redirectURI) => {
      await page.goto(buildAuthorizeURL(edgeA, delayedMFAClient.id, redirectURI, 'openid profile email'));
      await submitPasswordLogin(page, options.user, `${password}-wrong`);
      await completeRecoveryLogin(page, options.code, {expectCallback: false});
      assert.match(page.url(), /\/login/, `${options.label} must return to the login flow`);
      await expectPageText(page, /Invalid login or password/);
    }));

  console.log(`ok ${options.okName}`);
  await context.close();
}

// runRecoveryCodeReuseRejected verifies one-time recovery-code semantics for the selected principal.
async function runRecoveryCodeReuseRejected(browser, options) {
  const context = await newBrowserContext(browser, edgeA);
  const page = await context.newPage();
  const label = options.label || 'recovery-code reuse check';
  const okName = options.okName || 'oidc-recovery-code-reuse-rejected';

  await withPageState(page, label, async () =>
    withCallbackServer(label, async (redirectURI) => {
      await startMFAChallenge(page, redirectURI, {user: options.user});
      if (!/\/login\/recovery/.test(page.url())) {
        await page.goto(`${edgeA}/login/recovery`);
      }

      const responsePromise = page.waitForResponse((response) =>
        response.url().includes('/login/recovery') && response.request().method() === 'POST',
      {timeout: 15000});
      await page.fill('input[name="code"]', options.code);
      await page.click('button[type="submit"]');
      const response = await responsePromise;

      assert.equal(response.status(), 200, 'reused recovery code must render the verification page again');
      await expectPageText(page, /Invalid recovery code/);
    }));

  console.log(`ok ${okName}`);
  await context.close();
}

// startMFAChallenge opens an OIDC flow and stops once the selected principal reaches an MFA choice.
async function startMFAChallenge(page, redirectURI, options = {}) {
  const client = options.client || mfaClient;
  const user = options.user || mfaUsername;
  const secret = options.password || password;

  await page.goto(buildAuthorizeURL(edgeA, client.id, redirectURI, 'openid profile email'));
  await submitPasswordLogin(page, user, secret);
  await page.waitForURL(/\/login\/webauthn|\/login\/mfa|\/login\/totp|\/login\/recovery/, {timeout: 15000});
}

async function issueAuthorizationCode(browser, client, user, options = {}) {
  const context = await newBrowserContext(browser, edgeA);
  const page = await context.newPage();
  const scope = options.scope || 'openid profile email';
  const authOptions = options.authOptions || {};

  try {
    const callback = await withPageState(page, `authorization-code issue for ${user}`, async () =>
      withCallbackServer(`authorization-code issue for ${user}`, async (redirectURI, callbackPromise) => {
        await page.goto(buildAuthorizeURL(edgeA, client.id, redirectURI, scope, authOptions));
        await submitPasswordLogin(page, user, password);

        return callbackPromise;
      }));

    assert.ok(callback.code, `authorization-code issue for ${user} must return a code`);

    return callback;
  } finally {
    await context.close();
  }
}

async function issueRefreshToken(browser, user) {
  const code = await issueAuthorizationCode(browser, browserClient, user, {
    scope: 'openid profile email offline_access',
  });
  const token = await exchangeCode(edgeAAPI, browserClient, code.code, code.redirectURI);

  assert.ok(token.refresh_token, `refresh-token setup for ${user} must return a refresh token`);

  return token;
}

async function runMultiEdgeContinuity(browser) {
  const context = await newBrowserContext(browser, edgeA);
  const page = await context.newPage();
  await installVirtualAuthenticator(page);

  const callback = await withPageState(page, 'multi-edge OIDC continuity', async () =>
    withCallbackServer('multi-edge OIDC continuity', async (redirectURI, callbackPromise) => {
    await page.goto(buildAuthorizeURL(edgeA, browserClient.id, redirectURI, 'openid profile email'));
    await page.waitForSelector('input[name="username"]');

    const edgeBLoginURL = page.url().replace(edgeA, edgeB);
    await page.goto(edgeBLoginURL);
    await submitPasswordLogin(page, `${username}.continuity`, password);

    return callbackPromise;
  }));
  assert.ok(callback.code, 'flow that started on edge-a completed on edge-b');
  console.log('ok multi-edge-oidc-continuity');

  await context.close();
}

async function runMultiEdgeWebAuthnContinuity(browser, webAuthnCredentials) {
  const context = await newBrowserContext(browser, edgeA);
  const page = await context.newPage();
  const authenticator = await installVirtualAuthenticator(page);
  await importVirtualAuthenticatorCredentials(authenticator, webAuthnCredentials);

  const callback = await withPageState(page, 'multi-edge WebAuthn continuity', async () =>
    withCallbackServer('multi-edge WebAuthn continuity', async (redirectURI, callbackPromise) => {
    await page.goto(buildAuthorizeURL(edgeA, mfaClient.id, redirectURI, 'openid profile email'));
    await submitPasswordLogin(page, mfaUsername, password);
    await page.waitForURL(/\/login\/webauthn|\/login\/mfa/, {timeout: 15000});

    const edgeBMFALoginURL = page.url().replace(edgeA, edgeB);
    await page.goto(edgeBMFALoginURL);
    await completeWebAuthnLogin(page, edgeB);

    return callbackPromise;
  }));
  assert.ok(callback.code, 'WebAuthn flow that started on edge-a completed on edge-b');
  console.log('ok multi-edge-webauthn-continuity');

  await context.close();
}

function newBrowserContext(browser, baseURL) {
  return browser.newContext({baseURL, ignoreHTTPSErrors: true});
}

async function maybeRunSAMLFlow(browser) {
  if (samlLoginURL === '') {
    return;
  }

  const context = await browser.newContext({ignoreHTTPSErrors: true});
  const page = await context.newPage();
  try {
    await page.goto(samlLoginURL);
    await submitPasswordLogin(page, `${username}.saml`, password);
    await page.waitForLoadState('networkidle');
    assert.match(page.url(), /localhost:19095/i, 'SAML flow should return to the local SP');
    await expectPageText(page, /SAML2 Authentication Successful/i);
    console.log('ok saml-sso-login');

    await runSAMLSPInitiatedSLO(page);
  } finally {
    await context.close();
  }

  await runSAMLAttackFailures();
}

async function runSAMLSPInitiatedSLO(page) {
  await page.click('a.logout-btn');
  await page.waitForURL(/localhost:19095\/?$/, {timeout: callbackTimeoutMS});
  await page.waitForLoadState('networkidle').catch(() => undefined);
  await expectPageText(page, /Login via SAML2/);
  console.log('ok saml-sp-initiated-slo');
}

async function runSAMLAttackFailures() {
  await expectTextResponse(
    `${edgeAAPI}/saml/sso?SAMLRequest=not-base64`,
    400,
    /Failed to parse SAML request|Failed to validate SAML request|illegal base64/i,
    'saml-sso-malformed-request-rejected',
  );

  await expectTextResponse(
    `${edgeAAPI}/saml/slo`,
    400,
    /Invalid SAML SLO payload: .*missing SAMLRequest\/SAMLResponse payload/i,
    'saml-slo-missing-payload-rejected',
  );

  await expectTextResponse(
    `${edgeAAPI}/saml/slo?SAMLRequest=req&SAMLResponse=res`,
    400,
    /Invalid SAML SLO payload: .*must not be present together/i,
    'saml-slo-ambiguous-payload-rejected',
  );

  await expectTextResponse(
    `${edgeAAPI}/saml/slo?SAMLRequest=req&SAMLRequest=req2`,
    400,
    /Invalid SAML SLO payload: .*duplicated/i,
    'saml-slo-duplicate-request-rejected',
  );
}

async function installVirtualAuthenticator(page) {
  const cdp = await page.context().newCDPSession(page);
  await cdp.send('WebAuthn.enable');
  const result = await cdp.send('WebAuthn.addVirtualAuthenticator', {
    options: {
      protocol: 'ctap2',
      transport: 'usb',
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      automaticPresenceSimulation: true,
    },
  });

  return {cdp, authenticatorId: result.authenticatorId};
}

async function exportVirtualAuthenticatorCredentials(authenticator) {
  const result = await authenticator.cdp.send('WebAuthn.getCredentials', {
    authenticatorId: authenticator.authenticatorId,
  });
  const credentials = result.credentials || [];
  assert.ok(credentials.length > 0, 'WebAuthn registration produced a virtual credential');

  return credentials;
}

async function importVirtualAuthenticatorCredentials(authenticator, credentials) {
  assert.ok(credentials.length > 0, 'WebAuthn credential import needs at least one credential');

  for (const credential of credentials) {
    const credentialForImport = {
      ...credential,
      rpId: credential.rpId || new URL(edgeA).hostname,
    };

    await authenticator.cdp.send('WebAuthn.addCredential', {
      authenticatorId: authenticator.authenticatorId,
      credential: credentialForImport,
    });
  }
}

async function submitPasswordLogin(page, user, secret) {
  await page.waitForSelector('input[name="username"]');
  await page.fill('input[name="username"]', user);
  await page.fill('input[name="password"]', secret);
  await Promise.all([
    page.waitForLoadState('networkidle').catch(() => undefined),
    page.click('button[type="submit"]'),
  ]);
}

async function completeTOTPRegistration(page) {
  await page.waitForURL(/\/mfa\/totp\/register/);
  await traceCookieSizes(page, 'after TOTP registration page');
  const secret = (await page.locator('.font-mono').innerText()).trim();
  const counter = Math.floor(Date.now() / 30000);
  const codes = [counter, counter - 1, counter + 1].map((value) => totp(secret, value));

  for (const code of codes) {
    await page.fill('input[name="code"]', code);
    const responsePromise = page.waitForResponse((response) =>
      response.url().includes('/mfa/totp/register') && response.request().method() === 'POST');
    await page.click('button[type="submit"]');
    const response = await responsePromise;
    const hxRedirect = response.headers()['hx-redirect'];
    trace(`TOTP registration response status=${response.status()} hx-redirect=${hxRedirect || ''} url=${page.url()}`);
    if (response.ok() && hxRedirect) {
      await page.goto(new URL(hxRedirect, edgeA).toString());
      await page.waitForLoadState('networkidle').catch(() => undefined);
      await waitForMFARegistrationStep(page);

      return secret;
    }

    throw new Error(
      `TOTP registration failed with status=${response.status()} ` +
      `body=${await compactResponseText(response)} page=${await visiblePageText(page)}`,
    );
  }

  throw new Error(`TOTP registration did not advance from ${page.url()}: ${await visiblePageText(page)}`);
}

async function completeTOTPLogin(page, secret, options = {}) {
  const expectCallback = options.expectCallback !== false;

  await page.waitForURL(/\/login\/totp|\/login\/mfa|\/login\/webauthn|\/login\/recovery/, {timeout: 15000});
  if (!/\/login\/totp/.test(page.url())) {
    await page.goto(`${edgeA}/login/totp`);
  }

  const counter = Math.floor(Date.now() / 30000);
  const codes = [counter, counter - 1, counter + 1].map((value) => totp(secret, value));

  for (const code of codes) {
    const responsePromise = page.waitForResponse((response) =>
      response.url().includes('/login/totp') && response.request().method() === 'POST',
    {timeout: 15000});
    await page.fill('input[name="code"]', code);
    await page.click('button[type="submit"]');
    const response = await responsePromise;

    if (!response.ok() && response.status() !== 302) {
      throw new Error(
        `TOTP login failed with status=${response.status()} ` +
        `body=${await compactResponseText(response)} page=${await visiblePageText(page)}`,
      );
    }

    if (expectCallback) {
      const reachedCallback = await page.waitForURL(/callback/, {timeout: 3000})
        .then(() => true)
        .catch(() => false);
      if (reachedCallback) {
        return;
      }
      continue;
    }

    const returnedToLogin = await page.waitForURL(/\/login/, {timeout: 3000})
      .then(() => true)
      .catch(() => false);
    if (returnedToLogin) {
      return;
    }
  }

  throw new Error(`TOTP login did not advance from ${page.url()}: ${await visiblePageText(page)}`);
}

async function completeWebAuthnRegistration(page) {
  if (!/\/mfa\/webauthn\/register/.test(page.url())) {
    await page.goto(`${edgeA}/mfa/webauthn/register`);
  }

  await page.fill('#device-name', 'CDP virtual key');
  const beginResponsePromise = page.waitForResponse((response) =>
    response.url().includes('/mfa/webauthn/register/begin') &&
      response.request().method() === 'GET' &&
      response.status() !== 302,
  {timeout: 15000});
  const finishResponsePromise = page.waitForResponse((response) =>
    response.url().includes('/mfa/webauthn/register/finish') &&
      response.request().method() === 'POST',
  {timeout: 15000});

  await page.click('#register-button');
  const beginResponse = await beginResponsePromise;
  if (!beginResponse.ok()) {
    throw new Error(
      `WebAuthn registration begin failed with status=${beginResponse.status()} ` +
      `body=${await compactResponseText(beginResponse)} page=${await visiblePageText(page)}`,
    );
  }

  const finishResponse = await finishResponsePromise;
  if (!finishResponse.ok()) {
    throw new Error(
      `WebAuthn registration finish failed with status=${finishResponse.status()} ` +
      `body=${await compactResponseText(finishResponse)} page=${await visiblePageText(page)}`,
    );
  }

  await page.waitForURL(/callback|\/mfa\/register\/continue|\/mfa\/register\/home|\/mfa\/recovery\/register/, {timeout: 15000});
  if (/\/mfa\/register\/continue/.test(page.url())) {
    await page.goto(`${edgeA}/mfa/register/continue`);
    await page.waitForURL(/callback|\/mfa\/recovery\/register|\/mfa\/register\/home/, {timeout: 15000});
  }
}

async function completeRecoveryRegistration(page) {
  if (/callback/.test(page.url())) {
    return [];
  }

  if (!/\/mfa\/recovery\/register/.test(page.url())) {
    await page.goto(`${edgeA}/mfa/register/continue`);
    await page.waitForURL(/callback|\/mfa\/recovery\/register/, {timeout: 15000});
  }

  if (/callback/.test(page.url())) {
    return [];
  }

  const codes = (await page.locator('#recovery-codes-grid div').allInnerTexts())
    .map((value) => value.trim())
    .filter(Boolean);
  await Promise.all([
    page.waitForResponse((response) => response.url().includes('/mfa/recovery/register/save')).catch(() => undefined),
    page.click('#download-btn'),
  ]);
  await page.waitForSelector('#continue-btn:not([disabled])');
  await page.click('#continue-btn');
  await page.waitForURL(/callback|\/mfa\/register\/continue|\/mfa\/register\/home/, {timeout: 15000});

  return codes;
}

async function completeWebAuthnLogin(page, base) {
  await page.waitForURL(/\/login\/webauthn|\/login\/mfa|\/login\/totp|\/login\/recovery/, {timeout: 15000});
  if (!/\/login\/webauthn/.test(page.url())) {
    await page.goto(`${base}/login/webauthn`);
  }

  let finishResponseError;
  const beginResponsePromise = page.waitForResponse((response) =>
    response.url().includes('/login/webauthn/begin') &&
      response.request().method() === 'GET' &&
      response.status() !== 302,
  {timeout: 15000});
  const finishResponsePromise = page.waitForResponse((response) =>
    response.url().includes('/login/webauthn/finish') &&
      response.request().method() === 'POST',
  {timeout: 15000}).catch((error) => {
    finishResponseError = error;

    return undefined;
  });

  await page.click('#login-button');
  const beginResponse = await beginResponsePromise;
  if (!beginResponse.ok()) {
    await finishResponsePromise;

    throw new Error(
      `WebAuthn login begin failed with status=${beginResponse.status()} ` +
      `body=${await compactResponseText(beginResponse)} page=${await visiblePageText(page)}`,
    );
  }

  const finishResponse = await finishResponsePromise;
  if (finishResponseError) {
    throw finishResponseError;
  }

  if (!finishResponse.ok()) {
    throw new Error(
      `WebAuthn login finish failed with status=${finishResponse.status()} ` +
      `body=${await compactResponseText(finishResponse)} page=${await visiblePageText(page)}`,
    );
  }

  await page.waitForURL(/callback/, {timeout: 15000});
}

// completeRecoveryLogin submits a recovery code and waits for either callback or fail-back to login.
async function completeRecoveryLogin(page, code, options = {}) {
  const expectCallback = options.expectCallback !== false;

  await page.waitForURL(/\/login\/webauthn|\/login\/mfa|\/login\/recovery/, {timeout: 15000});
  if (!/\/login\/recovery/.test(page.url())) {
    await page.goto(`${edgeA}/login/recovery`);
  }

  const responsePromise = page.waitForResponse((response) =>
    response.url().includes('/login/recovery') && response.request().method() === 'POST',
  {timeout: 15000});
  await page.fill('input[name="code"]', code);
  await page.click('button[type="submit"]');
  const response = await responsePromise;

  if (expectCallback) {
    await page.waitForURL(/callback/, {timeout: 15000});

    return response;
  }

  await page.waitForURL(/\/login/, {timeout: 15000});

  return response;
}

function buildAuthorizeURL(base, clientID, redirectURI, scope, overrides = {}) {
  const url = new URL('/oidc/authorize', base);
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('client_id', clientID);
  url.searchParams.set('redirect_uri', redirectURI);
  url.searchParams.set('scope', scope);
  url.searchParams.set('state', base64URL(crypto.randomBytes(16)));
  url.searchParams.set('nonce', base64URL(crypto.randomBytes(16)));
  for (const [key, value] of Object.entries(overrides)) {
    if (value === null || value === undefined) {
      url.searchParams.delete(key);
      continue;
    }

    url.searchParams.set(key, value);
  }

  return url.toString();
}

function defaultRedirectURI() {
  return `https://${callbackPublicHost}:${callbackPort}/callback`;
}

async function withCallbackServer(label, run) {
  let resolveCallback;
  const callbackPromise = new Promise((resolve) => {
    resolveCallback = resolve;
  });
  const server = newCallbackServer(resolveCallback);

  await new Promise((resolve) => server.listen(callbackPort, callbackBindHost, resolve));
  const redirectURI = `https://${callbackPublicHost}:${callbackPort}/callback`;

  try {
    const result = await Promise.race([
      Promise.resolve(run(redirectURI, callbackPromise)),
      delay(callbackTimeoutMS).then(() => {
        throw new Error(`${label} OIDC callback timed out`);
      }),
    ]);

    return {...(result || {}), redirectURI};
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
}

// withPassiveCallbackServer accepts callback navigation without requiring the flow to finish there.
async function withPassiveCallbackServer(run) {
  const server = newCallbackServer(() => undefined);

  await new Promise((resolve) => server.listen(callbackPort, callbackBindHost, resolve));

  try {
    return await run(`https://${callbackPublicHost}:${callbackPort}/callback`);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
}

function newCallbackServer(resolveCallback) {
  return https.createServer({
    cert: fs.readFileSync(callbackCert),
    key: fs.readFileSync(callbackKey),
  }, (request, response) => {
    const url = new URL(request.url, `https://${callbackPublicHost}:${callbackPort}`);
    if (url.pathname !== '/callback') {
      response.writeHead(404);
      response.end();
      return;
    }

    resolveCallback({
      code: url.searchParams.get('code') || '',
      error: url.searchParams.get('error') || '',
      errorDescription: url.searchParams.get('error_description') || '',
      state: url.searchParams.get('state') || '',
    });
    response.writeHead(200, {'content-type': 'text/plain'});
    response.end('OK');
  });
}

async function exchangeCode(base, client, code, redirectURI, extraFields = {}) {
  return postForm(`${base}/oidc/token`, {
    grant_type: 'authorization_code',
    client_id: client.id,
    client_secret: client.secret,
    code,
    redirect_uri: redirectURI,
    ...extraFields,
  });
}

async function pollDeviceToken(base, client, deviceCode) {
  for (let attempt = 0; attempt < 30; attempt += 1) {
    const token = await postForm(`${base}/oidc/token`, {
      grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
      client_id: client.id,
      client_secret: client.secret,
      device_code: deviceCode,
    }, false);

    if (token.access_token) {
      return token;
    }

    await delay(1000);
  }

  throw new Error('device token polling timed out');
}

async function runInvalidDeviceUserCodeAttempt(browser, userCode, okName, logResult = true) {
  const context = await newBrowserContext(browser, edgeA);
  const page = await context.newPage();

  await page.goto(`${edgeA}/oidc/device/verify`);
  await page.fill('input[name="user_code"]', userCode);
  await page.fill('input[name="username"]', username);
  await page.fill('input[name="password"]', password);
  await Promise.all([
    page.waitForLoadState('networkidle').catch(() => undefined),
    page.click('button[type="submit"]'),
  ]);
  await expectPageText(page, /Invalid or expired user code/);
  if (logResult) {
    console.log(`ok ${okName}`);
  }

  await context.close();
}

async function submitSameOriginForm(page, pathName, fields) {
  return page.evaluate(async ({pathName: targetPath, fields: formFields}) => {
    const body = new URLSearchParams();
    for (const [key, value] of Object.entries(formFields)) {
      body.append(key, value);
    }

    const response = await fetch(targetPath, {
      method: 'POST',
      headers: {'content-type': 'application/x-www-form-urlencoded'},
      body,
    });

    return {
      status: response.status,
      text: await response.text(),
    };
  }, {pathName, fields});
}

// submitSelfServiceMutation sends an HTMX-style MFA self-service mutation.
async function submitSelfServiceMutation(page, method, pathName) {
  const csrfToken = await extractPageCSRFToken(page);

  return page.evaluate(async ({method: requestMethod, pathName: targetPath, csrf}) => {
    const response = await fetch(targetPath, {
      method: requestMethod,
      headers: {
        'content-type': 'application/x-www-form-urlencoded;charset=UTF-8',
        'hx-request': 'true',
        'x-csrf-token': csrf,
      },
      body: new URLSearchParams(),
    });

    return {
      status: response.status,
      text: await response.text(),
      hxRedirect: response.headers.get('HX-Redirect') || response.headers.get('hx-redirect') || '',
    };
  }, {method, pathName, csrf: csrfToken});
}

async function extractCSRFToken(page) {
  return page.locator('input[name="csrf_token"]').inputValue();
}

// extractPageCSRFToken supports normal forms, WebAuthn buttons, and HTMX buttons.
async function extractPageCSRFToken(page) {
  const formToken = await page.locator('input[name="csrf_token"]').first().inputValue().catch(() => '');
  if (formToken) {
    return formToken;
  }

  const webAuthnToken = await page.locator('[data-webauthn-csrf]').first().getAttribute('data-webauthn-csrf').catch(() => '');
  if (webAuthnToken) {
    return webAuthnToken;
  }

  const hxHeaders = await page.locator('[hx-headers]').first().getAttribute('hx-headers').catch(() => '');
  if (hxHeaders) {
    const parsed = JSON.parse(hxHeaders);

    return parsed['X-CSRF-Token'] || parsed['x-csrf-token'] || '';
  }

  throw new Error(`no CSRF token found on ${page.url()}`);
}

function duplicateTokenForm(duplicateKey) {
  const form = new URLSearchParams();
  form.append('grant_type', 'authorization_code');
  form.append('client_id', browserClient.id);
  form.append('client_secret', browserClient.secret);
  form.append('code', 'invalid-code');
  form.append('redirect_uri', defaultRedirectURI());
  form.append(duplicateKey, 'attacker-value');

  return form;
}

async function expectJSONBodyOAuthError(url, payload, status, error, okName) {
  const response = await fetch(url, {
    method: 'POST',
    headers: {'content-type': 'application/json'},
    body: JSON.stringify(payload),
  });
  const text = await response.text();
  const parsed = JSON.parse(text);

  assert.equal(response.status, status, `${okName} returned unexpected HTTP status: ${text}`);
  assert.equal(parsed.error, error, `${okName} returned unexpected OAuth error`);
  console.log(`ok ${okName}`);
}

async function expectIntrospectionInactive(token, okName) {
  const result = await postFormResponse(`${edgeAAPI}/oidc/introspect`, {
    token,
    client_id: browserClient.id,
    client_secret: browserClient.secret,
  });

  assert.equal(result.status, 200, `${okName} returned unexpected HTTP status: ${result.text}`);
  assert.equal(result.payload.active, false, `${okName} must be inactive`);
  console.log(`ok ${okName}`);
}

async function postForm(url, fields, failOnError = true) {
  const result = await postFormResponse(url, fields);
  if (failOnError && !result.ok) {
    throw new Error(`${url} returned ${result.status}: ${JSON.stringify(result.payload)}`);
  }

  return result.payload;
}

async function postFormResponse(url, fields, init = {}) {
  const body = fields instanceof URLSearchParams ? fields : new URLSearchParams(fields);
  const response = await fetch(url, {
    ...init,
    method: 'POST',
    headers: {
      ...init.headers,
      'content-type': 'application/x-www-form-urlencoded',
    },
    body,
  });
  const text = await response.text();
  let payload = {};
  if (text !== '') {
    payload = JSON.parse(text);
  }

  return {
    ok: response.ok,
    status: response.status,
    payload,
    text,
  };
}

async function expectFormError(url, fields, status, error, okName, init = {}) {
  const result = await postFormResponse(url, fields, init);

  assert.equal(result.status, status, `${okName} returned unexpected HTTP status: ${result.text}`);
  assert.equal(result.payload.error, error, `${okName} returned unexpected OAuth error`);
  console.log(`ok ${okName}`);
}

async function expectJSONError(url, init, status, error, okName) {
  const response = await fetch(url, init);
  const text = await response.text();
  const payload = JSON.parse(text);

  assert.equal(response.status, status, `${okName} returned unexpected HTTP status: ${text}`);
  assert.equal(payload.error, error, `${okName} returned unexpected JSON error`);
  console.log(`ok ${okName}`);
}

async function expectTextResponse(url, status, pattern, okName) {
  const response = await fetch(url);
  const text = await response.text();

  assert.equal(response.status, status, `${okName} returned unexpected HTTP status: ${text}`);
  assert.match(text, pattern, `${okName} returned unexpected response body`);
  console.log(`ok ${okName}`);
}

function totp(secret, counter) {
  const key = base32Decode(secret.replace(/\s+/g, ''));
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(counter), 0);
  const hmac = crypto.createHmac('sha1', key).update(msg).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  const binary = ((hmac[offset] & 0x7f) << 24)
    | ((hmac[offset + 1] & 0xff) << 16)
    | ((hmac[offset + 2] & 0xff) << 8)
    | (hmac[offset + 3] & 0xff);

  return String(binary % 1000000).padStart(6, '0');
}

function base32Decode(value) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = '';
  for (const char of value.toUpperCase().replace(/=+$/, '')) {
    const index = alphabet.indexOf(char);
    if (index < 0) {
      throw new Error(`invalid base32 character ${char}`);
    }

    bits += index.toString(2).padStart(5, '0');
  }

  const bytes = [];
  for (let offset = 0; offset + 8 <= bits.length; offset += 8) {
    bytes.push(Number.parseInt(bits.slice(offset, offset + 8), 2));
  }

  return Buffer.from(bytes);
}

function base64URL(value) {
  return Buffer.from(value).toString('base64url');
}

function base64URLJSON(value) {
  return base64URL(Buffer.from(JSON.stringify(value)));
}

function unsignedJWT(header, payload) {
  return `${base64URLJSON(header)}.${base64URLJSON(payload)}.`;
}

function decodeJWTClaims(token) {
  const parts = token.split('.');
  assert.equal(parts.length, 3, 'JWT must have three parts');

  return JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
}

function pkceVerifier() {
  return base64URL(crypto.randomBytes(48));
}

function pkceChallenge(verifier) {
  return base64URL(crypto.createHash('sha256').update(verifier).digest());
}

function mutateWebAuthnClientData(body, mutate) {
  body.response = body.response || {};
  const clientData = JSON.parse(Buffer.from(body.response.clientDataJSON, 'base64url').toString('utf8'));
  mutate(clientData);
  body.response.clientDataJSON = base64URL(Buffer.from(JSON.stringify(clientData)));
}

function trace(message) {
  if (process.env.NAUTHILUS_E2E_TRACE === '1') {
    console.log(`trace ${message}`);
  }
}

async function waitForMFARegistrationStep(page) {
  await page.waitForURL(
    /callback|\/mfa\/webauthn\/register|\/mfa\/recovery\/register|\/mfa\/register\/continue|\/mfa\/register\/home/,
    {timeout: 15000},
  );
}

async function visiblePageText(page) {
  const text = await page.locator('body').innerText().catch(() => '');

  return text.replace(/\s+/g, ' ').trim().slice(0, 500);
}

async function expectPageText(page, pattern) {
  assert.match(await visiblePageText(page), pattern);
}

async function expectWebAuthnError(page, pattern) {
  const text = await page.locator('#error-text').innerText();

  assert.match(text, pattern);
}

async function traceCookieSizes(page, label) {
  if (process.env.NAUTHILUS_E2E_TRACE !== '1') {
    return;
  }

  const cookies = await page.context().cookies(edgeA);
  for (const cookie of cookies) {
    console.log(`trace cookie ${label} ${cookie.name} length=${cookie.value.length}`);
  }
}

async function compactResponseText(response) {
  const text = await response.text().catch(() => '');

  return text.replace(/\s+/g, ' ').trim().slice(0, 500);
}

function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
