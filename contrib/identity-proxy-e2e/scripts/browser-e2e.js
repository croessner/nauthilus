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

async function main() {
  const browser = await chromium.launch({
    headless: process.env.NAUTHILUS_E2E_HEADED !== '1',
    args: ['--host-resolver-rules=MAP split.example.test 127.0.0.1,MAP authority.example.test 127.0.0.1'],
  });

  try {
    await runAuthorizationCodeFlow(browser);
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

async function runDeviceCodeFlow(browser) {
  const device = await postForm(`${edgeAAPI}/oidc/device`, {
    client_id: browserClient.id,
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

async function runRequiredMFAFlows(browser) {
  const context = await newBrowserContext(browser, edgeA);
  const page = await context.newPage();
  const registrationAuthenticator = await installVirtualAuthenticator(page);

  let recoveryCodes = [];
  const registration = await withPageState(page, 'required MFA registration', async () =>
    withCallbackServer('required MFA registration', async (redirectURI, callbackPromise) => {
    await page.goto(buildAuthorizeURL(edgeA, mfaClient.id, redirectURI, 'openid profile email'));
    await submitPasswordLogin(page, `${username}.mfa`, password);
    await completeTOTPRegistration(page);
    console.log('ok totp-registration');
    await completeWebAuthnRegistration(page);
    console.log('ok webauthn-registration');
    recoveryCodes = await completeRecoveryRegistration(page);

    return callbackPromise;
  }));
  assert.ok(registration.code, 'required MFA registration resumed the OIDC flow');
  assert.ok(recoveryCodes.length > 0, 'required MFA registration generated recovery codes');
  console.log('ok recovery-code-generation');
  const webAuthnCredentials = await exportVirtualAuthenticatorCredentials(registrationAuthenticator);
  await context.close();

  const webAuthnContext = await newBrowserContext(browser, edgeA);
  const webAuthnPage = await webAuthnContext.newPage();
  const webAuthnAuthenticator = await installVirtualAuthenticator(webAuthnPage);
  await importVirtualAuthenticatorCredentials(webAuthnAuthenticator, webAuthnCredentials);
  const webAuthnLogin = await withPageState(webAuthnPage, 'WebAuthn login', async () =>
    withCallbackServer('WebAuthn login', async (redirectURI, callbackPromise) => {
    await webAuthnPage.goto(buildAuthorizeURL(edgeA, mfaClient.id, redirectURI, 'openid profile email'));
    await submitPasswordLogin(webAuthnPage, `${username}.mfa`, password);
    await completeWebAuthnLogin(webAuthnPage, edgeA);

    return callbackPromise;
  }));
  assert.ok(webAuthnLogin.code, 'WebAuthn login completed the OIDC flow');
  console.log('ok webauthn-login');
  const updatedWebAuthnCredentials = await exportVirtualAuthenticatorCredentials(webAuthnAuthenticator);
  await webAuthnContext.close();

  const recoveryContext = await newBrowserContext(browser, edgeA);
  const recoveryPage = await recoveryContext.newPage();
  const recoveryLogin = await withPageState(recoveryPage, 'recovery-code login', async () =>
    withCallbackServer('recovery-code login', async (redirectURI, callbackPromise) => {
    await recoveryPage.goto(buildAuthorizeURL(edgeA, mfaClient.id, redirectURI, 'openid profile email'));
    await submitPasswordLogin(recoveryPage, `${username}.mfa`, password);
    await completeRecoveryLogin(recoveryPage, recoveryCodes[0]);

    return callbackPromise;
  }));
  assert.ok(recoveryLogin.code, 'recovery-code login completed the OIDC flow');
  console.log('ok recovery-code-login');
  await recoveryContext.close();

  return updatedWebAuthnCredentials;
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
    await submitPasswordLogin(page, `${username}.mfa`, password);
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
  if (process.env.NAUTHILUS_E2E_SAML_URL === '') {
    return;
  }

  const samlURL = process.env.NAUTHILUS_E2E_SAML_URL;
  if (!samlURL) {
    console.log('SAML smoke skipped; set NAUTHILUS_E2E_SAML_URL when a test SP is running.');
    return;
  }

  const context = await browser.newContext({ignoreHTTPSErrors: true});
  const page = await context.newPage();
  await page.goto(samlURL);
  await submitPasswordLogin(page, `${username}.saml`, password);
  await page.waitForLoadState('networkidle');
  assert.match(page.url(), /saml|localhost/i, 'SAML flow should return to the SP or SAML route');
  console.log('ok saml-sso-login');
  await context.close();
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

      return;
    }

    throw new Error(
      `TOTP registration failed with status=${response.status()} ` +
      `body=${await compactResponseText(response)} page=${await visiblePageText(page)}`,
    );
  }

  throw new Error(`TOTP registration did not advance from ${page.url()}: ${await visiblePageText(page)}`);
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
  await page.waitForURL(/\/login\/webauthn|\/login\/mfa/, {timeout: 15000});
  if (/\/login\/mfa/.test(page.url())) {
    await page.goto(`${base}/login/webauthn`);
  }

  const beginResponsePromise = page.waitForResponse((response) =>
    response.url().includes('/login/webauthn/begin') &&
      response.request().method() === 'GET' &&
      response.status() !== 302,
  {timeout: 15000});
  const finishResponsePromise = page.waitForResponse((response) =>
    response.url().includes('/login/webauthn/finish') &&
      response.request().method() === 'POST',
  {timeout: 15000});

  await page.click('#login-button');
  const beginResponse = await beginResponsePromise;
  if (!beginResponse.ok()) {
    throw new Error(
      `WebAuthn login begin failed with status=${beginResponse.status()} ` +
      `body=${await compactResponseText(beginResponse)} page=${await visiblePageText(page)}`,
    );
  }

  const finishResponse = await finishResponsePromise;
  if (!finishResponse.ok()) {
    throw new Error(
      `WebAuthn login finish failed with status=${finishResponse.status()} ` +
      `body=${await compactResponseText(finishResponse)} page=${await visiblePageText(page)}`,
    );
  }

  await page.waitForURL(/callback/, {timeout: 15000});
}

async function completeRecoveryLogin(page, code) {
  await page.waitForURL(/\/login\/webauthn|\/login\/mfa|\/login\/recovery/, {timeout: 15000});
  if (!/\/login\/recovery/.test(page.url())) {
    await page.goto(`${edgeA}/login/recovery`);
  }

  await page.fill('input[name="code"]', code);
  await page.click('button[type="submit"]');
  await page.waitForURL(/callback/, {timeout: 15000});
}

function buildAuthorizeURL(base, clientID, redirectURI, scope) {
  const url = new URL('/oidc/authorize', base);
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('client_id', clientID);
  url.searchParams.set('redirect_uri', redirectURI);
  url.searchParams.set('scope', scope);
  url.searchParams.set('state', base64URL(crypto.randomBytes(16)));
  url.searchParams.set('nonce', base64URL(crypto.randomBytes(16)));

  return url.toString();
}

async function withCallbackServer(label, run) {
  let resolveCallback;
  const callbackPromise = new Promise((resolve) => {
    resolveCallback = resolve;
  });
  const server = https.createServer({
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
      state: url.searchParams.get('state') || '',
    });
    response.writeHead(200, {'content-type': 'text/plain'});
    response.end('OK');
  });

  await new Promise((resolve) => server.listen(callbackPort, callbackBindHost, resolve));
  const redirectURI = `https://${callbackPublicHost}:${callbackPort}/callback`;

  try {
    const result = await Promise.race([
      Promise.resolve(run(redirectURI, callbackPromise)),
      delay(callbackTimeoutMS).then(() => {
        throw new Error(`${label} OIDC callback timed out`);
      }),
    ]);

    return {...result, redirectURI};
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
}

async function exchangeCode(base, client, code, redirectURI) {
  return postForm(`${base}/oidc/token`, {
    grant_type: 'authorization_code',
    client_id: client.id,
    client_secret: client.secret,
    code,
    redirect_uri: redirectURI,
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

async function postForm(url, fields, failOnError = true) {
  const body = new URLSearchParams(fields);
  const response = await fetch(url, {
    method: 'POST',
    headers: {'content-type': 'application/x-www-form-urlencoded'},
    body,
  });
  const payload = await response.json().catch(() => ({}));
  if (failOnError && !response.ok) {
    throw new Error(`${url} returned ${response.status}: ${JSON.stringify(payload)}`);
  }

  return payload;
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
