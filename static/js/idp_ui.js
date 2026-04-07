(() => {
    'use strict';

    // Shared state for the custom HTMX confirmation modal.
    let pendingConfirmRequest = null;
    const autoDisableDelayMs = 1000;
    const autoDisabledAttr = 'data-auto-disabled';
    const autoDisableSpinnerNodeSelector = '[data-auto-disable-spinner-node]';
    const submitControlSelector = 'button[type="submit"], button:not([type]), input[type="submit"], input[type="image"]';

    /**
     * @typedef {{pending: string, running: string, success: string, timeout: string, error: string, skipped: string, retrying: string, attempt: string, summaryDone: string, summaryPartial: string}} LogoutLabels
     * @typedef {{id?: string, display_name?: string, method: string, url?: string, payload_base64?: string, initial_status?: string, initial_detail?: string}} LogoutTask
     * @typedef {{state: string, detail: string}} LogoutTaskResult
     * @typedef {{statusDiv: HTMLElement | null, statusText: HTMLElement | null, errorDiv: HTMLElement | null, errorText: HTMLElement | null}} WebAuthnUI
     * @typedef {HTMLButtonElement | HTMLInputElement} SubmitControl
     * @typedef {{new (element: Element, options: {text: string, width: number, height: number, colorDark: string, colorLight: string, correctLevel: unknown}): unknown, CorrectLevel: {H: unknown}}} QRCodeGlobal
     * @typedef {{logAll: () => void}} HtmxGlobal
     * @typedef {{issueRequest: (skipConfirmation: boolean) => void, question: string}} HtmxConfirmDetail
     * @typedef {{elt: Element | null, triggeringEvent: Event | null}} HtmxRequestDetail
     */

    /**
     * Returns the active theme preference from local storage or system settings.
     *
     * @returns {string}
     */
    function getPreferredTheme() {
        const stored = localStorage.getItem('theme');
        if (stored) {
            return stored;
        }

        return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
    }

    /**
     * Applies the theme to the root document element.
     *
     * @param {string} theme
     * @returns {void}
     */
    function setTheme(theme) {
        document.documentElement.setAttribute('data-theme', theme);
    }

    /**
     * Switches between light and dark theme and persists the selection.
     *
     * @returns {void}
     */
    function toggleTheme() {
        const currentTheme = document.documentElement.getAttribute('data-theme');
        const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
        setTheme(newTheme);
        localStorage.setItem('theme', newTheme);
    }

    /**
     * Closes all open dropdowns except the one containing the provided target.
     *
     * @param {Element | null} target
     * @returns {void}
     */
    function closeOpenDropdownsExcept(target) {
        document.querySelectorAll('[data-dropdown-root].dropdown-open').forEach((dropdown) => {
            if (!target || !dropdown.contains(target)) {
                dropdown.classList.remove('dropdown-open');
            }
        });
    }

    /**
     * Converts binary data to Base64URL format.
     *
     * @param {ArrayBuffer} bin
     * @returns {string}
     */
    function arrayBufferToBase64URL(bin) {
        const uint8array = new Uint8Array(bin);
        const str = btoa(String.fromCharCode(...uint8array));

        return str.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
    }

    /**
     * Converts either a Base64URL string or a BufferSource to Uint8Array.
     *
     * @param {string | ArrayBuffer | ArrayBufferView} input
     * @returns {Uint8Array}
     */
    function base64URLToUint8Array(input) {
        if (input instanceof Uint8Array) {
            return input;
        }

        if (ArrayBuffer.isView(input)) {
            return new Uint8Array(input.buffer, input.byteOffset, input.byteLength);
        }

        if (input instanceof ArrayBuffer) {
            return new Uint8Array(input);
        }

        if (typeof input !== 'string') {
            throw new TypeError('Expected Base64URL string or BufferSource');
        }

        const len = input.length;
        const normalized = input
            .replace(/-/g, '+')
            .replace(/_/g, '/')
            .padEnd(len + ((4 - (len % 4)) % 4), '=');

        return new Uint8Array([...atob(normalized)].map((char) => char.charCodeAt(0)));
    }

    /**
     * Validates a relative redirect path and rejects protocol-relative values.
     *
     * @param {unknown} redirect
     * @returns {boolean}
     */
    function isSafeRelativeRedirect(redirect) {
        return typeof redirect === 'string' && redirect.startsWith('/') && !redirect.startsWith('//');
    }

    /**
     * Validates absolute redirect URLs for allowed protocols.
     *
     * @param {unknown} redirect
     * @returns {boolean}
     */
    function isSafeAbsoluteRedirect(redirect) {
        if (typeof redirect !== 'string' || redirect.startsWith('//')) {
            return false;
        }

        try {
            const parsed = new URL(redirect);
            return parsed.protocol === 'https:' || parsed.protocol === 'http:';
        } catch {
            return false;
        }
    }

    /**
     * Returns the global QRCode constructor when available.
     *
     * @returns {QRCodeGlobal | null}
     */
    function getQRCodeGlobal() {
        const candidate = /** @type {unknown} */ (window['QRCode']);
        if (typeof candidate !== 'function') {
            return null;
        }

        const qrCode = /** @type {{CorrectLevel?: {H?: unknown}}} */ (candidate);
        if (!qrCode.CorrectLevel || typeof qrCode.CorrectLevel !== 'object' || !('H' in qrCode.CorrectLevel)) {
            return null;
        }

        return /** @type {QRCodeGlobal} */ (candidate);
    }

    /**
     * Returns the global htmx object with logging capability.
     *
     * @returns {HtmxGlobal | null}
     */
    function getHtmxGlobal() {
        const candidate = /** @type {unknown} */ (window['htmx']);
        if (!candidate || (typeof candidate !== 'object' && typeof candidate !== 'function')) {
            return null;
        }

        const htmx = /** @type {{logAll?: unknown}} */ (candidate);
        if (typeof htmx.logAll !== 'function') {
            return null;
        }

        return /** @type {HtmxGlobal} */ (candidate);
    }

    /**
     * Extracts typed confirm detail from an HTMX confirm event.
     *
     * @param {Event} event
     * @returns {HtmxConfirmDetail | null}
     */
    function getHtmxConfirmDetail(event) {
        if (!(event instanceof CustomEvent) || !event.detail || typeof event.detail !== 'object') {
            return null;
        }

        const detail = /** @type {{issueRequest?: unknown, question?: unknown}} */ (event.detail);
        if (typeof detail.issueRequest !== 'function' || typeof detail.question !== 'string') {
            return null;
        }

        return {
            issueRequest: /** @type {(skipConfirmation: boolean) => void} */ (detail.issueRequest),
            question: detail.question,
        };
    }

    /**
     * Extracts typed request detail from HTMX request lifecycle events.
     *
     * @param {Event} event
     * @returns {HtmxRequestDetail}
     */
    function getHtmxRequestDetail(event) {
        if (!(event instanceof CustomEvent) || !event.detail || typeof event.detail !== 'object') {
            return {elt: null, triggeringEvent: null};
        }

        const detail = /** @type {{elt?: unknown, triggeringEvent?: unknown}} */ (event.detail);

        return {
            elt: detail.elt instanceof Element ? detail.elt : null,
            triggeringEvent: detail.triggeringEvent instanceof Event ? detail.triggeringEvent : null,
        };
    }

    // Front-channel logout helpers.
    /**
     * Resolves the final logout redirect target from config attributes.
     *
     * @param {Element} config
     * @returns {string}
     */
    function resolveLogoutTarget(config) {
        const rawTarget = (config.getAttribute('data-logout-target') || '').trim();
        if (isSafeRelativeRedirect(rawTarget) || isSafeAbsoluteRedirect(rawTarget)) {
            return rawTarget;
        }

        return '/logged_out';
    }

    /**
     * Parses a non-negative integer with fallback support.
     *
     * @param {string | null} value
     * @param {number} fallback
     * @returns {number}
     */
    function parsePositiveInteger(value, fallback) {
        const parsed = Number.parseInt(value || '', 10);
        if (Number.isNaN(parsed) || parsed < 0) {
            return fallback;
        }

        return parsed;
    }

    /**
     * Parses front-channel logout task definitions from a data attribute.
     *
     * @param {Element} config
     * @returns {LogoutTask[]}
     */
    function parseLogoutTasks(config) {
        const raw = config.getAttribute('data-logout-tasks');
        if (!raw) {
            return [];
        }

        try {
            const parsed = JSON.parse(raw);
            return Array.isArray(parsed) ? parsed : [];
        } catch {
            return [];
        }
    }

    /**
     * Collects localized status labels used by the logout progress view.
     *
     * @param {Element} config
     * @returns {LogoutLabels}
     */
    function logoutStateLabels(config) {
        return {
            pending: config.getAttribute('data-logout-status-pending') || 'Pending',
            running: config.getAttribute('data-logout-status-running') || 'Running',
            success: config.getAttribute('data-logout-status-success') || 'Success',
            timeout: config.getAttribute('data-logout-status-timeout') || 'Timeout',
            error: config.getAttribute('data-logout-status-error') || 'Error',
            skipped: config.getAttribute('data-logout-status-skipped') || 'Skipped',
            retrying: config.getAttribute('data-logout-retrying-text') || 'Retrying',
            attempt: config.getAttribute('data-logout-attempt-text') || 'Attempt',
            summaryDone: config.getAttribute('data-logout-summary-done') || 'Logout completed successfully.',
            summaryPartial: config.getAttribute('data-logout-summary-partial') || 'Logout completed with partial failures.',
        };
    }

    /**
     * Maps a logout state to a badge class.
     *
     * @param {string} state
     * @returns {string}
     */
    function statusClassForLogout(state) {
        switch (state) {
            case 'running':
                return 'badge-info';
            case 'success':
                return 'badge-success';
            case 'timeout':
                return 'badge-warning';
            case 'error':
                return 'badge-error';
            case 'skipped':
                return 'badge-ghost';
            default:
                return 'badge-neutral';
        }
    }

    /**
     * Resolves the localized label for a logout state.
     *
     * @param {string} state
     * @param {LogoutLabels} labels
     * @returns {string}
     */
    function stateLabelForLogout(state, labels) {
        switch (state) {
            case 'running':
                return labels.running;
            case 'success':
                return labels.success;
            case 'timeout':
                return labels.timeout;
            case 'error':
                return labels.error;
            case 'skipped':
                return labels.skipped;
            default:
                return labels.pending;
        }
    }

    /**
     * Updates one task row in the logout status list.
     *
     * @param {Element | null | undefined} node
     * @param {string} state
     * @param {string} detail
     * @param {LogoutLabels} labels
     * @returns {void}
     */
    function setLogoutStatus(node, state, detail, labels) {
        if (!node) {
            return;
        }

        const badge = node.querySelector('[data-logout-status-badge]');
        const detailNode = node.querySelector('[data-logout-status-detail]');

        if (badge) {
            badge.className = `badge ${statusClassForLogout(state)}`;
            badge.textContent = stateLabelForLogout(state, labels);
        }

        if (detailNode) {
            detailNode.textContent = detail || '';
            detailNode.classList.toggle('hidden', !detail);
        }
    }

    /**
     * Builds a status row element for one logout task.
     *
     * @param {LogoutTask} task
     * @param {LogoutLabels} labels
     * @returns {HTMLLIElement}
     */
    function makeLogoutStatusNode(task, labels) {
        const item = document.createElement('li');
        item.className = 'flex items-center justify-between gap-2 bg-base-100 rounded px-3 py-2';
        item.setAttribute('data-logout-task-id', task.id || '');

        const title = document.createElement('span');
        title.className = 'text-sm truncate';
        title.textContent = task.display_name || task.id || 'task';

        const badge = document.createElement('span');
        badge.setAttribute('data-logout-status-badge', '1');
        badge.className = `badge ${statusClassForLogout('pending')}`;
        badge.textContent = labels.pending;

        const detail = document.createElement('p');
        detail.setAttribute('data-logout-status-detail', '1');
        detail.className = 'text-xs opacity-70 mt-1 hidden';

        const left = document.createElement('div');
        left.className = 'min-w-0';
        left.appendChild(title);
        left.appendChild(detail);

        item.appendChild(left);
        item.appendChild(badge);

        return item;
    }

    /**
     * Adds a retry hint query parameter for repeated task attempts.
     *
     * @param {string} urlValue
     * @param {number} attempt
     * @returns {string}
     */
    function withRetryHint(urlValue, attempt) {
        if (attempt <= 1) {
            return urlValue;
        }

        try {
            const parsed = new URL(urlValue, window.location.origin);
            parsed.searchParams.set('_nauthilus_retry', String(attempt));
            return parsed.toString();
        } catch {
            return urlValue;
        }
    }

    /**
     * Executes one front-channel logout task in a hidden iframe.
     *
     * @param {LogoutTask} task
     * @param {number} timeoutMs
     * @param {number} attempt
     * @returns {Promise<LogoutTaskResult>}
     */
    function executeLogoutTaskAttempt(task, timeoutMs, attempt) {
        return new Promise((resolve) => {
            const iframe = document.createElement('iframe');
            iframe.style.display = 'none';
            iframe.style.width = '0';
            iframe.style.height = '0';
            iframe.style.border = '0';

            let settled = false;
            let loadEvents = 0;
            const expectsDoubleLoad = task.method === 'POST';

            const timer = window.setTimeout(() => {
                finalize('timeout', `request timed out after ${timeoutMs}ms`);
            }, timeoutMs);

            /**
             * Finalizes iframe task execution exactly once.
             *
             * @param {string} state
             * @param {string} detail
             * @returns {void}
             */
            function finalize(state, detail) {
                if (settled) {
                    return;
                }

                settled = true;
                window.clearTimeout(timer);
                iframe.remove();
                resolve({state, detail});
            }

            iframe.onload = () => {
                loadEvents += 1;
                if (expectsDoubleLoad && loadEvents < 2) {
                    return;
                }

                finalize('success', '');
            };

            iframe.onerror = () => finalize('error', 'iframe load failed');

            document.body.appendChild(iframe);

            if (task.method === 'GET' && task.url) {
                iframe.src = withRetryHint(task.url, attempt);
                return;
            }

            if (task.method === 'POST' && task.payload_base64) {
                try {
                    iframe.srcdoc = atob(task.payload_base64);
                } catch {
                    finalize('error', 'invalid POST payload');
                }

                return;
            }

            finalize('error', 'unsupported front-channel task');
        });
    }

    /**
     * Reads shared WebAuthn status/error nodes from the page.
     *
     * @returns {WebAuthnUI}
     */
    function getWebAuthnUIElements() {
        return {
            statusDiv: document.getElementById('webauthn-status'),
            statusText: document.getElementById('status-text'),
            errorDiv: document.getElementById('webauthn-error'),
            errorText: document.getElementById('error-text'),
        };
    }

    /**
     * Prepares the WebAuthn UI for an in-flight operation.
     *
     * @param {WebAuthnUI} ui
     * @param {HTMLButtonElement} trigger
     * @returns {void}
     */
    function setWebAuthnInitialUI(ui, trigger) {
        if (ui.statusDiv) {
            ui.statusDiv.classList.remove('hidden');
        }
        if (ui.errorDiv) {
            ui.errorDiv.classList.add('hidden');
        }
        trigger.disabled = true;
    }

    /**
     * Shows a WebAuthn error message and re-enables the trigger button.
     *
     * @param {WebAuthnUI} ui
     * @param {HTMLButtonElement} trigger
     * @param {string} message
     * @returns {void}
     */
    function showWebAuthnError(ui, trigger, message) {
        if (ui.errorDiv) {
            ui.errorDiv.classList.remove('hidden');
        }
        if (ui.errorText) {
            ui.errorText.innerText = message;
        }
        if (ui.statusDiv) {
            ui.statusDiv.classList.add('hidden');
        }
        trigger.disabled = false;
    }

    /**
     * Reads an error message body from a failed response.
     *
     * @param {Response} response
     * @param {string} fallback
     * @returns {Promise<string>}
     */
    async function readFailedResponseMessage(response, fallback) {
        try {
            const message = await response.text();
            if (message) {
                return message;
            }
        } catch {
            // Keep fallback message.
        }

        return fallback;
    }

    /**
     * Renders a caught runtime error in the shared WebAuthn error panel.
     *
     * @param {unknown} error
     * @param {string} fallback
     * @param {WebAuthnUI} ui
     * @param {HTMLButtonElement} trigger
     * @returns {void}
     */
    function showWebAuthnCaughtError(error, fallback, ui, trigger) {
        const message = error instanceof Error && error.message ? error.message : fallback;
        showWebAuthnError(ui, trigger, message);
    }

    /**
     * Shows a failed response message in the WebAuthn error panel.
     *
     * @param {Response} response
     * @param {string} fallback
     * @param {WebAuthnUI} ui
     * @param {HTMLButtonElement} trigger
     * @returns {Promise<boolean>}
     */
    async function ensureWebAuthnResponseOK(response, fallback, ui, trigger) {
        if (response.ok) {
            return true;
        }

        const message = await readFailedResponseMessage(response, fallback);
        showWebAuthnError(ui, trigger, message);

        return false;
    }

    /**
     * Fetches an endpoint and renders response errors in the WebAuthn error panel.
     *
     * @param {string} endpoint
     * @param {string} fallback
     * @param {WebAuthnUI} ui
     * @param {HTMLButtonElement} trigger
     * @returns {Promise<Response | null>}
     */
    async function fetchWebAuthnOrShowError(endpoint, fallback, ui, trigger) {
        const response = await fetch(endpoint);
        if (await ensureWebAuthnResponseOK(response, fallback, ui, trigger)) {
            return response;
        }

        return null;
    }

    /**
     * Runs WebAuthn login with begin/finish endpoints and updates UI state.
     *
     * @param {HTMLButtonElement} trigger
     * @returns {Promise<void>}
     */
    async function runWebAuthnLogin(trigger) {
        const beginEndpoint = trigger.getAttribute('data-webauthn-begin');
        const finishEndpoint = trigger.getAttribute('data-webauthn-finish');
        const csrfToken = trigger.getAttribute('data-webauthn-csrf') || '';
        const completingText = trigger.getAttribute('data-webauthn-completing') || 'Completing login...';
        const unknownErrorText = trigger.getAttribute('data-webauthn-unknown-error') || 'Unknown error';
        const nextURL = trigger.getAttribute('data-webauthn-next-url') || '/login';

        if (!beginEndpoint || !finishEndpoint) {
            return;
        }

        const ui = getWebAuthnUIElements();
        setWebAuthnInitialUI(ui, trigger);

        try {
            const beginResponse = await fetchWebAuthnOrShowError(beginEndpoint, unknownErrorText, ui, trigger);
            if (!beginResponse) {
                return;
            }

            const options = await beginResponse.json();
            options.publicKey.challenge = base64URLToUint8Array(options.publicKey.challenge);

            if (Array.isArray(options.publicKey.allowCredentials)) {
                options.publicKey.allowCredentials.forEach((credential) => {
                    credential.id = base64URLToUint8Array(credential.id);
                });
            }

            const assertion = await navigator.credentials.get({
                publicKey: options.publicKey,
            });

            if (ui.statusText) {
                ui.statusText.innerText = completingText;
            }

            const finishResponse = await fetch(finishEndpoint, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-Token': csrfToken,
                },
                body: JSON.stringify({
                    id: assertion.id,
                    rawId: arrayBufferToBase64URL(assertion.rawId),
                    type: assertion.type,
                    response: {
                        authenticatorData: arrayBufferToBase64URL(assertion.response.authenticatorData),
                        clientDataJSON: arrayBufferToBase64URL(assertion.response.clientDataJSON),
                        signature: arrayBufferToBase64URL(assertion.response.signature),
                        userHandle: assertion.response.userHandle
                            ? arrayBufferToBase64URL(assertion.response.userHandle)
                            : null,
                    },
                }),
            });

            if (!finishResponse.ok) {
                if (finishResponse.status === 401) {
                    try {
                        const errorData = await finishResponse.json();
                        if (isSafeRelativeRedirect(errorData.redirect)) {
                            window.location.href = errorData.redirect;
                            return;
                        }
                    } catch {
                        // Continue with generic error handling.
                    }
                }

                if (!await ensureWebAuthnResponseOK(finishResponse, unknownErrorText, ui, trigger)) {
                    return;
                }
            }

            window.location.href = nextURL;
        } catch (error) {
            showWebAuthnCaughtError(error, unknownErrorText, ui, trigger);
        }
    }

    /**
     * Runs WebAuthn registration with begin/finish endpoints and updates UI state.
     *
     * @param {HTMLButtonElement} trigger
     * @returns {Promise<void>}
     */
    async function runWebAuthnRegister(trigger) {
        const beginEndpoint = trigger.getAttribute('data-webauthn-begin');
        const finishEndpoint = trigger.getAttribute('data-webauthn-finish');
        const csrfToken = trigger.getAttribute('data-webauthn-csrf') || '';
        const completingText = trigger.getAttribute('data-webauthn-completing') || 'Completing registration...';
        const unknownErrorText = trigger.getAttribute('data-webauthn-unknown-error') || 'Unknown error';
        const deviceRequiredText = trigger.getAttribute('data-webauthn-device-required') || 'Device name is required';
        const nextURL = trigger.getAttribute('data-webauthn-next-url') || '/mfa/register/home';
        const deviceInputSelector = trigger.getAttribute('data-webauthn-device-input') || '#device-name';

        if (!beginEndpoint || !finishEndpoint) {
            return;
        }

        const ui = getWebAuthnUIElements();
        setWebAuthnInitialUI(ui, trigger);

        const deviceNameInput = document.querySelector(deviceInputSelector);
        const deviceName = deviceNameInput instanceof HTMLInputElement ? deviceNameInput.value.trim() : '';
        if (!deviceName) {
            showWebAuthnError(ui, trigger, deviceRequiredText);
            return;
        }

        try {
            const beginResponse = await fetchWebAuthnOrShowError(beginEndpoint, unknownErrorText, ui, trigger);
            if (!beginResponse) {
                return;
            }

            const options = await beginResponse.json();
            options.publicKey.challenge = base64URLToUint8Array(options.publicKey.challenge);
            options.publicKey.user.id = base64URLToUint8Array(options.publicKey.user.id);

            if (Array.isArray(options.publicKey.excludeCredentials)) {
                options.publicKey.excludeCredentials.forEach((credential) => {
                    credential.id = base64URLToUint8Array(credential.id);
                });
            }

            const credential = await navigator.credentials.create({
                publicKey: options.publicKey,
            });

            if (ui.statusText) {
                ui.statusText.innerText = completingText;
            }

            const finishResponse = await fetch(finishEndpoint, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-Token': csrfToken,
                },
                body: JSON.stringify({
                    name: deviceName,
                    credential: {
                        id: credential.id,
                        rawId: arrayBufferToBase64URL(credential.rawId),
                        type: credential.type,
                        response: {
                            attestationObject: arrayBufferToBase64URL(credential.response.attestationObject),
                            clientDataJSON: arrayBufferToBase64URL(credential.response.clientDataJSON),
                        },
                    },
                }),
            });

            if (!await ensureWebAuthnResponseOK(finishResponse, unknownErrorText, ui, trigger)) {
                return;
            }

            window.location.href = nextURL;
        } catch (error) {
            showWebAuthnCaughtError(error, unknownErrorText, ui, trigger);
        }
    }

    /**
     * Initializes the TOTP QR code widget once per page lifecycle.
     *
     * @returns {void}
     */
    function initTotpQRCode() {
        const qrcodeTarget = document.getElementById('qrcode');
        if (!qrcodeTarget || qrcodeTarget.getAttribute('data-qrcode-initialized') === '1') {
            return;
        }

        const qrcodeText = qrcodeTarget.getAttribute('data-qrcode-text');
        const qrCodeGlobal = getQRCodeGlobal();
        if (!qrcodeText || !qrCodeGlobal) {
            return;
        }

        new qrCodeGlobal(qrcodeTarget, {
            text: qrcodeText,
            width: 200,
            height: 200,
            colorDark: '#000000',
            colorLight: '#ffffff',
            correctLevel: qrCodeGlobal.CorrectLevel.H,
        });

        qrcodeTarget.setAttribute('data-qrcode-initialized', '1');
    }

    /**
     * Runs a single logout task with retries and updates its status node.
     *
     * @param {LogoutTask} task
     * @param {number} maxRetries
     * @param {number} timeoutMs
     * @param {LogoutLabels} labels
     * @param {Element | undefined} statusNode
     * @returns {Promise<string>}
     */
    async function runLogoutTask(task, maxRetries, timeoutMs, labels, statusNode) {
        if (task.initial_status === 'error') {
            setLogoutStatus(statusNode, 'error', task.initial_detail || 'task initialization failed', labels);
            return 'error';
        }

        if (task.method === 'NONE') {
            const state = task.initial_status === 'skipped' ? 'skipped' : 'error';
            setLogoutStatus(statusNode, state, task.initial_detail || 'task skipped', labels);
            return state;
        }

        setLogoutStatus(statusNode, 'running', '', labels);

        for (let attempt = 1; attempt <= maxRetries + 1; attempt += 1) {
            const result = await executeLogoutTaskAttempt(task, timeoutMs, attempt);
            if (result.state === 'success') {
                setLogoutStatus(statusNode, 'success', '', labels);
                return 'success';
            }

            if (attempt <= maxRetries) {
                setLogoutStatus(
                    statusNode,
                    'running',
                    `${labels.retrying} (${labels.attempt} ${attempt + 1}/${maxRetries + 1})`,
                    labels,
                );
                continue;
            }

            setLogoutStatus(statusNode, result.state, result.detail, labels);
            return result.state;
        }

        setLogoutStatus(statusNode, 'error', 'unexpected orchestration state', labels);
        return 'error';
    }

    /**
     * Initializes front-channel logout orchestration and redirect flow.
     *
     * @returns {void}
     */
    function initLogoutRedirect() {
        const config = document.getElementById('logout-config');
        if (!config || config.getAttribute('data-logout-initialized') === '1') {
            return;
        }

        config.setAttribute('data-logout-initialized', '1');

        const target = resolveLogoutTarget(config);
        const tasks = parseLogoutTasks(config);
        const labels = logoutStateLabels(config);
        const timeoutMs = parsePositiveInteger(config.getAttribute('data-logout-timeout-ms'), 4000);
        const maxRetries = parsePositiveInteger(config.getAttribute('data-logout-max-retries'), 1);
        const redirectDelayMs = parsePositiveInteger(config.getAttribute('data-logout-redirect-delay-ms'), 1500);
        const statusList = document.getElementById('logout-status-list');
        const progressBar = document.getElementById('logout-progress-bar');
        const progressCount = document.getElementById('logout-progress-count');
        const summary = document.getElementById('logout-summary');

        if (!Array.isArray(tasks) || tasks.length === 0) {
            window.setTimeout(() => {
                window.location.href = target;
            }, redirectDelayMs);

            return;
        }

        const statusNodes = new Map();
        let completed = 0;
        let failures = 0;

        if (statusList) {
            statusList.innerHTML = '';
            tasks.forEach((task) => {
                const node = makeLogoutStatusNode(task, labels);
                statusList.appendChild(node);
                statusNodes.set(task.id, node);
            });
        }

        /**
         * Updates the logout progress indicator widgets.
         *
         * @returns {void}
         */
        function updateProgress() {
            if (progressBar) {
                progressBar.max = tasks.length;
                progressBar.value = completed;
            }

            if (progressCount) {
                progressCount.textContent = `${completed} / ${tasks.length}`;
            }
        }

        updateProgress();

        (async () => {
            for (const task of tasks) {
                const statusNode = statusNodes.get(task.id);
                const state = await runLogoutTask(task, maxRetries, timeoutMs, labels, statusNode);
                completed += 1;
                if (state === 'error' || state === 'timeout') {
                    failures += 1;
                }

                updateProgress();
            }

            if (summary) {
                summary.textContent = failures === 0 ? labels.summaryDone : labels.summaryPartial;
            }

            window.setTimeout(() => {
                window.location.href = target;
            }, redirectDelayMs);
        })();
    }

    /**
     * Initializes SAML POST auto-submit behavior when enabled.
     *
     * @returns {void}
     */
    function initSAMLPostBinding() {
        const form = document.getElementById('SAMLResponseForm');
        if (!form || form.getAttribute('data-saml-autosubmit-initialized') === '1') {
            return;
        }

        form.setAttribute('data-saml-autosubmit-initialized', '1');

        if (form.getAttribute('data-autosubmit') === '0') {
            return;
        }

        form.submit();
    }

    /**
     * Enables global HTMX debug logging in developer mode.
     *
     * @returns {void}
     */
    function initDevHtmxLogging() {
        const root = document.documentElement;
        if (!root || root.getAttribute('data-dev-mode') !== '1') {
            return;
        }

        if (root.getAttribute('data-htmx-log-initialized') === '1') {
            return;
        }

        const htmxGlobal = getHtmxGlobal();
        if (htmxGlobal) {
            htmxGlobal.logAll();
            root.setAttribute('data-htmx-log-initialized', '1');
        }
    }

    /**
     * Resolves the DOM root used for recovery code actions.
     *
     * @param {Element} trigger
     * @returns {ParentNode}
     */
    function getRecoveryRoot(trigger) {
        const selector = trigger.getAttribute('data-recovery-scope');
        if (selector) {
            const scoped = document.querySelector(selector);
            if (scoped) {
                return scoped;
            }
        }

        return document;
    }

    /**
     * Extracts recovery codes from the configured recovery grid.
     *
     * @param {Element} trigger
     * @returns {string[]}
     */
    function getRecoveryCodes(trigger) {
        const root = getRecoveryRoot(trigger);
        const cells = root.querySelectorAll('#recovery-codes-grid > div');
        const codes = [];

        cells.forEach((cell) => {
            codes.push((cell.textContent || '').trim());
        });

        return codes.filter(Boolean);
    }

    /**
     * Renders recovery codes into a PNG data URL.
     *
     * @param {string[]} codes
     * @returns {string}
     */
    function buildRecoveryCodesPngDataURL(codes) {
        const lineHeight = 32;
        const colWidth = 220;
        const cols = 2;
        const rows = Math.ceil(codes.length / cols);
        const padding = 40;
        const titleHeight = 50;
        const width = cols * colWidth + padding * 2;
        const height = titleHeight + rows * lineHeight + padding * 2;

        const canvas = document.createElement('canvas');
        canvas.width = width;
        canvas.height = height;

        const context = canvas.getContext('2d');
        if (!context) {
            return '';
        }

        context.fillStyle = '#ffffff';
        context.fillRect(0, 0, width, height);

        context.fillStyle = '#000000';
        context.font = 'bold 18px monospace';
        context.textAlign = 'center';
        context.fillText('Recovery Codes', width / 2, padding);

        context.font = '16px monospace';
        context.textAlign = 'left';

        for (let index = 0; index < codes.length; index++) {
            const col = index % cols;
            const row = Math.floor(index / cols);
            const x = padding + col * colWidth;
            const y = titleHeight + padding + row * lineHeight;

            context.fillText(codes[index], x, y);
        }

        return canvas.toDataURL('image/png');
    }

    /**
     * Copies recovery codes into the clipboard and flashes a copied label.
     *
     * @param {Element} trigger
     * @returns {Promise<void>}
     */
    async function copyRecoveryCodes(trigger) {
        const codes = getRecoveryCodes(trigger);
        if (codes.length === 0 || !navigator.clipboard) {
            return;
        }

        try {
            await navigator.clipboard.writeText(codes.join('\n'));
        } catch {
            return;
        }

        const root = getRecoveryRoot(trigger);
        const label = root.querySelector('#copy-label');
        if (!label) {
            return;
        }

        const copiedLabel = trigger.getAttribute('data-copied-label');
        if (!copiedLabel) {
            return;
        }

        const original = label.textContent;
        label.textContent = copiedLabel;

        setTimeout(() => {
            label.textContent = original;
        }, 2000);
    }

    /**
     * Downloads recovery codes as PNG and optionally persists them server-side.
     *
     * @param {HTMLButtonElement} trigger
     * @returns {Promise<void>}
     */
    async function downloadRecoveryCodes(trigger) {
        const codes = getRecoveryCodes(trigger);
        if (codes.length === 0) {
            return;
        }

        trigger.disabled = true;

        try {
            const dataURL = buildRecoveryCodesPngDataURL(codes);
            if (!dataURL) {
                trigger.disabled = false;
                return;
            }

            const link = document.createElement('a');
            link.href = dataURL;
            link.download = 'recovery-codes.png';
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);

            const saveURL = trigger.getAttribute('data-save-url');
            if (!saveURL) {
                trigger.disabled = false;
                return;
            }

            const headers = {'Content-Type': 'application/json'};
            const csrf = trigger.getAttribute('data-csrf-token');
            if (csrf) {
                headers['X-CSRF-Token'] = csrf;
            }

            const response = await fetch(saveURL, {
                method: 'POST',
                credentials: 'same-origin',
                headers: headers,
                body: JSON.stringify({codes: codes}),
            });

            if (response.ok) {
                const enableTarget = trigger.getAttribute('data-enable-target');
                if (enableTarget) {
                    const button = document.querySelector(enableTarget);
                    if (button) {
                        button.disabled = false;
                    }
                }
            } else {
                trigger.disabled = false;
            }
        } catch {
            trigger.disabled = false;
        }
    }

    /**
     * Removes a modal by selector or closest modal ancestor.
     *
     * @param {Element} trigger
     * @returns {void}
     */
    function removeModal(trigger) {
        const modalSelector = trigger.getAttribute('data-modal-target');
        if (modalSelector) {
            const target = document.querySelector(modalSelector);
            if (target) {
                target.remove();
                return;
            }
        }

        const modal = trigger.closest('.modal');
        if (modal) {
            modal.remove();
        }
    }

    // Submission guard: prevent duplicate POST/mutation actions on slow responses.
    /**
     * Checks whether an element triggers an HTMX mutating request.
     *
     * @param {unknown} element
     * @returns {boolean}
     */
    function isMutationHtmxElement(element) {
        if (!(element instanceof Element)) {
            return false;
        }

        return element.hasAttribute('hx-post')
            || element.hasAttribute('hx-put')
            || element.hasAttribute('hx-patch')
            || element.hasAttribute('hx-delete');
    }

    /**
     * Determines whether form submits should participate in auto-disable logic.
     *
     * @param {unknown} form
     * @returns {boolean}
     */
    function shouldHandleFormSubmit(form) {
        if (!(form instanceof HTMLFormElement)) {
            return false;
        }

        if (isMutationHtmxElement(form)) {
            return true;
        }

        return (form.getAttribute('method') || 'get').toLowerCase() === 'post';
    }

    /**
     * Marks a submit control as auto-disabled.
     *
     * @param {unknown} control
     * @returns {boolean}
     */
    function markControlAutoDisabled(control) {
        if (!(control instanceof HTMLButtonElement || control instanceof HTMLInputElement)) {
            return false;
        }

        if (control.disabled) {
            return false;
        }

        control.disabled = true;
        control.setAttribute(autoDisabledAttr, '1');

        return true;
    }

    /**
     * Appends a loading spinner to a button if not present already.
     *
     * @param {unknown} control
     * @returns {void}
     */
    function appendAutoDisableSpinner(control) {
        if (!(control instanceof HTMLButtonElement)) {
            return;
        }

        if (control.querySelector(autoDisableSpinnerNodeSelector)) {
            return;
        }

        const spinner = document.createElement('span');
        spinner.className = 'loading loading-spinner loading-xs ml-2';
        spinner.setAttribute('aria-hidden', 'true');
        spinner.setAttribute('data-auto-disable-spinner-node', '1');

        control.appendChild(spinner);
    }

    /**
     * Schedules spinner insertion while a control remains disabled.
     *
     * @param {unknown} control
     * @returns {void}
     */
    function scheduleAutoDisableSpinner(control) {
        if (!(control instanceof HTMLButtonElement)) {
            return;
        }

        window.setTimeout(() => {
            if (!control.isConnected || !control.disabled) {
                return;
            }

            appendAutoDisableSpinner(control);
        }, autoDisableDelayMs);
    }

    /**
     * Restores one auto-disabled submit control to its active state.
     *
     * @param {unknown} control
     * @returns {void}
     */
    function clearAutoDisabledControl(control) {
        if (!(control instanceof HTMLButtonElement || control instanceof HTMLInputElement)) {
            return;
        }

        if (control.getAttribute(autoDisabledAttr) !== '1') {
            return;
        }

        control.disabled = false;
        control.removeAttribute(autoDisabledAttr);

        if (control instanceof HTMLButtonElement) {
            const spinner = control.querySelector(autoDisableSpinnerNodeSelector);
            if (spinner) {
                spinner.remove();
            }
        }
    }

    /**
     * Restores controls previously disabled by auto-disable within the trigger scope.
     *
     * @param {Element | null | undefined} source
     * @returns {void}
     */
    function restoreAutoDisabledControls(source) {
        if (!(source instanceof Element)) {
            return;
        }

        const form = source.closest('form');
        const scope = form || source;

        if (scope instanceof HTMLButtonElement || scope instanceof HTMLInputElement) {
            clearAutoDisabledControl(scope);
        }

        scope.querySelectorAll(`button[${autoDisabledAttr}="1"], input[${autoDisabledAttr}="1"]`).forEach((control) => {
            clearAutoDisabledControl(control);
        });
    }

    /**
     * Extracts the submit control from a native submit event.
     *
     * @param {Event} event
     * @returns {SubmitControl | null}
     */
    function getSubmitterFromSubmitEvent(event) {
        if (typeof SubmitEvent === 'undefined' || !(event instanceof SubmitEvent)) {
            return null;
        }

        const submitter = event.submitter;
        if (submitter instanceof HTMLButtonElement || submitter instanceof HTMLInputElement) {
            return submitter;
        }

        return null;
    }

    /**
     * Resolves the submitter that triggered an HTMX request event.
     *
     * @param {Event | null | undefined} event
     * @returns {SubmitControl | null}
     */
    function resolveSubmitterFromTriggeringEvent(event) {
        if (!(event instanceof Event)) {
            return null;
        }

        if (typeof SubmitEvent !== 'undefined' && event instanceof SubmitEvent) {
            return getSubmitterFromSubmitEvent(event);
        }

        const target = event.target;
        if (!(target instanceof Element)) {
            return null;
        }

        const submitter = target.closest(submitControlSelector);
        if (submitter instanceof HTMLButtonElement || submitter instanceof HTMLInputElement) {
            return submitter;
        }

        return null;
    }

    /**
     * Disables all submit controls in a form and schedules spinner feedback.
     *
     * @param {HTMLFormElement} form
     * @param {HTMLButtonElement | HTMLInputElement | null} preferredSpinnerTarget
     * @returns {void}
     */
    function disableFormSubmitControls(form, preferredSpinnerTarget) {
        if (!(form instanceof HTMLFormElement)) {
            return;
        }

        let spinnerTarget = preferredSpinnerTarget instanceof HTMLButtonElement
            ? preferredSpinnerTarget
            : null;

        form.querySelectorAll(submitControlSelector).forEach((control) => {
            if (!(control instanceof HTMLButtonElement || control instanceof HTMLInputElement)) {
                return;
            }

            if (markControlAutoDisabled(control) && !spinnerTarget && control instanceof HTMLButtonElement) {
                spinnerTarget = control;
            }
        });

        if (spinnerTarget) {
            scheduleAutoDisableSpinner(spinnerTarget);
        }
    }

    /**
     * Applies auto-disable rules for HTMX mutation triggers.
     *
     * @param {Element | null | undefined} elt
     * @param {Event | null | undefined} triggeringEvent
     * @returns {void}
     */
    function disableHtmxRequestTrigger(elt, triggeringEvent) {
        if (!(elt instanceof Element)) {
            return;
        }

        if (elt instanceof HTMLFormElement) {
            if (!shouldHandleFormSubmit(elt)) {
                return;
            }

            const submitter = resolveSubmitterFromTriggeringEvent(triggeringEvent);
            disableFormSubmitControls(elt, submitter);

            return;
        }

        if (!(elt instanceof HTMLButtonElement || elt instanceof HTMLInputElement)) {
            return;
        }

        if (!isMutationHtmxElement(elt)) {
            return;
        }

        if (markControlAutoDisabled(elt)) {
            scheduleAutoDisableSpinner(elt);
        }
    }

    /**
     * Renders and appends the custom HTMX confirmation modal.
     *
     * @param {string} question
     * @param {{title: string, yes: string, no: string}} labels
     * @returns {void}
     */
    function renderConfirmModal(question, labels) {
        const container = document.getElementById('modal-container') || document.body;
        const modalHTML = `
            <div class="modal modal-open" id="confirm-modal">
                <div class="modal-box mx-4 sm:mx-auto max-w-sm sm:max-w-lg">
                    <h3 class="font-bold text-lg text-primary">${labels.title}</h3>
                    <p class="py-4">${question}</p>
                    <div class="modal-action">
                        <button class="btn btn-primary" data-action="confirm-yes">${labels.yes}</button>
                        <button class="btn" data-action="confirm-no">${labels.no}</button>
                    </div>
                </div>
            </div>
        `;

        container.insertAdjacentHTML('beforeend', modalHTML);
    }

    /**
     * Closes the custom confirmation modal if present.
     *
     * @returns {void}
     */
    function closeConfirmModal() {
        const modal = document.getElementById('confirm-modal');
        if (modal) {
            modal.remove();
        }
    }

    /**
     * Dispatches declarative UI actions triggered through `data-action`.
     *
     * @param {Element} trigger
     * @param {Event} event
     * @returns {boolean}
     */
    function handleAction(trigger, event) {
        const action = trigger.getAttribute('data-action');
        if (!action) {
            return false;
        }

        switch (action) {
            case 'toggle-theme':
                event.preventDefault();
                toggleTheme();
                return true;
            case 'toggle-dropdown': {
                event.preventDefault();
                event.stopPropagation();

                const targetID = trigger.getAttribute('data-dropdown-target');
                if (!targetID) {
                    return true;
                }

                const dropdown = document.getElementById(targetID);
                if (!dropdown) {
                    return true;
                }

                const shouldOpen = !dropdown.classList.contains('dropdown-open');
                closeOpenDropdownsExcept(null);
                if (shouldOpen) {
                    dropdown.classList.add('dropdown-open');
                }

                return true;
            }
            case 'modal-close':
                event.preventDefault();
                removeModal(trigger);
                return true;
            case 'confirm-yes':
                event.preventDefault();
                if (pendingConfirmRequest) {
                    pendingConfirmRequest();
                }
                pendingConfirmRequest = null;
                closeConfirmModal();
                return true;
            case 'confirm-no':
                event.preventDefault();
                pendingConfirmRequest = null;
                closeConfirmModal();
                return true;
            case 'recovery-copy':
                event.preventDefault();
                void copyRecoveryCodes(trigger);
                return true;
            case 'recovery-download':
                event.preventDefault();
                void downloadRecoveryCodes(trigger);
                return true;
            case 'webauthn-login':
                event.preventDefault();
                void runWebAuthnLogin(trigger);
                return true;
            case 'webauthn-register':
                event.preventDefault();
                void runWebAuthnRegister(trigger);
                return true;
            default:
                return false;
        }
    }

    // Set theme as early as possible to avoid flashing the wrong theme.
    setTheme(getPreferredTheme());
    initDevHtmxLogging();

    if (window.matchMedia) {
        const mq = window.matchMedia('(prefers-color-scheme: dark)');
        const onChange = (event) => {
            if (!localStorage.getItem('theme')) {
                setTheme(event.matches ? 'dark' : 'light');
            }
        };

        if (typeof mq.addEventListener === 'function') {
            mq.addEventListener('change', onChange);
        }
    }

    // Global event wiring.
    document.addEventListener('htmx:confirm', (evt) => {
        const target = evt.target;
        if (!target || !target.hasAttribute('hx-confirm')) {
            return;
        }

        const detail = getHtmxConfirmDetail(evt);
        if (!detail) {
            return;
        }

        evt.preventDefault();
        pendingConfirmRequest = () => detail.issueRequest(true);

        renderConfirmModal(detail.question, {
            title: document.documentElement.getAttribute('data-confirm-title') || 'Confirmation',
            yes: document.documentElement.getAttribute('data-confirm-yes') || 'Yes',
            no: document.documentElement.getAttribute('data-confirm-no') || 'Cancel',
        });
    });

    document.addEventListener('htmx:beforeRequest', (evt) => {
        const {elt, triggeringEvent} = getHtmxRequestDetail(evt);
        if (elt && elt.id === 'recovery-modal-close') {
            const modal = document.getElementById('recovery-modal');
            if (modal) {
                modal.remove();
            }
        }

        disableHtmxRequestTrigger(elt, triggeringEvent);
    });

    ['htmx:afterRequest', 'htmx:sendError', 'htmx:timeout'].forEach((eventName) => {
        document.addEventListener(eventName, (evt) => {
            const {elt} = getHtmxRequestDetail(evt);
            restoreAutoDisabledControls(elt);
        });
    });

    document.addEventListener('htmx:afterSwap', () => {
        initTotpQRCode();
        initLogoutRedirect();
        initSAMLPostBinding();
        initDevHtmxLogging();
    });

    document.addEventListener('DOMContentLoaded', () => {
        initTotpQRCode();
        initLogoutRedirect();
        initSAMLPostBinding();
        initDevHtmxLogging();
    });

    document.addEventListener('submit', (event) => {
        const form = event.target;
        if (!(form instanceof HTMLFormElement) || !shouldHandleFormSubmit(form)) {
            return;
        }

        const submitter = getSubmitterFromSubmitEvent(event);
        disableFormSubmitControls(form, submitter);
    }, true);

    document.addEventListener('click', (event) => {
        const target = event.target;
        if (!(target instanceof Element)) {
            return;
        }

        const actionTrigger = target.closest('[data-action]');
        const handled = actionTrigger ? handleAction(actionTrigger, event) : false;
        if (!handled) {
            closeOpenDropdownsExcept(target);
        }
    });

    document.addEventListener('keydown', (event) => {
        if (event.key !== 'Enter') {
            return;
        }

        const webAuthnButton = document.querySelector('[data-action="webauthn-login"], [data-action="webauthn-register"]');
        if (!(webAuthnButton instanceof HTMLButtonElement) || webAuthnButton.disabled) {
            return;
        }

        event.preventDefault();
        webAuthnButton.click();
    });
})();
