(() => {
    'use strict';

    let pendingConfirmRequest = null;

    function getPreferredTheme() {
        const stored = localStorage.getItem('theme');
        if (stored) {
            return stored;
        }

        return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
    }

    function setTheme(theme) {
        document.documentElement.setAttribute('data-theme', theme);
    }

    function toggleTheme() {
        const currentTheme = document.documentElement.getAttribute('data-theme');
        const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
        setTheme(newTheme);
        localStorage.setItem('theme', newTheme);
    }

    function closeOpenDropdownsExcept(target) {
        document.querySelectorAll('[data-dropdown-root].dropdown-open').forEach((dropdown) => {
            if (!target || !dropdown.contains(target)) {
                dropdown.classList.remove('dropdown-open');
            }
        });
    }

    function arrayBufferToBase64URL(bin) {
        const uint8array = new Uint8Array(bin);
        const str = btoa(String.fromCharCode(...uint8array));

        return str.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
    }

    function base64URLToUint8Array(b64str) {
        const len = b64str.length;
        const normalized = b64str
            .replace(/-/g, '+')
            .replace(/_/g, '/')
            .padEnd(len + ((4 - (len % 4)) % 4), '=');

        return new Uint8Array([...atob(normalized)].map((char) => char.charCodeAt(0)));
    }

    function isSafeRelativeRedirect(redirect) {
        return typeof redirect === 'string' && redirect.startsWith('/') && !redirect.startsWith('//');
    }

    function getWebAuthnUIElements() {
        return {
            statusDiv: document.getElementById('webauthn-status'),
            statusText: document.getElementById('status-text'),
            errorDiv: document.getElementById('webauthn-error'),
            errorText: document.getElementById('error-text'),
        };
    }

    function setWebAuthnInitialUI(ui, trigger) {
        if (ui.statusDiv) {
            ui.statusDiv.classList.remove('hidden');
        }
        if (ui.errorDiv) {
            ui.errorDiv.classList.add('hidden');
        }
        trigger.disabled = true;
    }

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
            const beginResponse = await fetch(beginEndpoint);
            if (!beginResponse.ok) {
                throw new Error(await beginResponse.text());
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

                throw new Error(await finishResponse.text());
            }

            window.location.href = nextURL;
        } catch (error) {
            const message = error instanceof Error && error.message ? error.message : unknownErrorText;
            showWebAuthnError(ui, trigger, message);
        }
    }

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
            const beginResponse = await fetch(beginEndpoint);
            if (!beginResponse.ok) {
                throw new Error(await beginResponse.text());
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

            if (!finishResponse.ok) {
                throw new Error(await finishResponse.text());
            }

            window.location.href = nextURL;
        } catch (error) {
            const message = error instanceof Error && error.message ? error.message : unknownErrorText;
            showWebAuthnError(ui, trigger, message);
        }
    }

    function initTotpQRCode() {
        const qrcodeTarget = document.getElementById('qrcode');
        if (!qrcodeTarget || qrcodeTarget.getAttribute('data-qrcode-initialized') === '1') {
            return;
        }

        const qrcodeText = qrcodeTarget.getAttribute('data-qrcode-text');
        if (!qrcodeText || typeof window.QRCode === 'undefined') {
            return;
        }

        // eslint-disable-next-line no-undef
        new QRCode(qrcodeTarget, {
            text: qrcodeText,
            width: 200,
            height: 200,
            colorDark: '#000000',
            colorLight: '#ffffff',
            // eslint-disable-next-line no-undef
            correctLevel: QRCode.CorrectLevel.H,
        });

        qrcodeTarget.setAttribute('data-qrcode-initialized', '1');
    }

    function initLogoutRedirect() {
        const config = document.getElementById('logout-config');
        if (!config || config.getAttribute('data-logout-initialized') === '1') {
            return;
        }

        config.setAttribute('data-logout-initialized', '1');

        setTimeout(() => {
            let target = config.getAttribute('data-logout-target') || '/logged_out';
            if (!isSafeRelativeRedirect(target)) {
                target = '/logged_out';
            }

            window.location.href = target;
        }, 2000);
    }

    function initDevHtmxLogging() {
        const root = document.documentElement;
        if (!root || root.getAttribute('data-dev-mode') !== '1') {
            return;
        }

        if (root.getAttribute('data-htmx-log-initialized') === '1') {
            return;
        }

        if (window.htmx && typeof window.htmx.logAll === 'function') {
            window.htmx.logAll();
            root.setAttribute('data-htmx-log-initialized', '1');
        }
    }

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

    function getRecoveryCodes(trigger) {
        const root = getRecoveryRoot(trigger);
        const cells = root.querySelectorAll('#recovery-codes-grid > div');
        const codes = [];

        cells.forEach((cell) => {
            codes.push((cell.textContent || '').trim());
        });

        return codes.filter(Boolean);
    }

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

    function closeConfirmModal() {
        const modal = document.getElementById('confirm-modal');
        if (modal) {
            modal.remove();
        }
    }

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

    document.addEventListener('htmx:confirm', (evt) => {
        const target = evt.target;
        if (!target || !target.hasAttribute('hx-confirm')) {
            return;
        }

        evt.preventDefault();
        pendingConfirmRequest = () => evt.detail.issueRequest(true);

        renderConfirmModal(evt.detail.question, {
            title: document.documentElement.getAttribute('data-confirm-title') || 'Confirmation',
            yes: document.documentElement.getAttribute('data-confirm-yes') || 'Yes',
            no: document.documentElement.getAttribute('data-confirm-no') || 'Cancel',
        });
    });

    document.addEventListener('htmx:beforeRequest', (evt) => {
        const elt = evt.detail && evt.detail.elt;
        if (elt && elt.id === 'recovery-modal-close') {
            const modal = document.getElementById('recovery-modal');
            if (modal) {
                modal.remove();
            }
        }
    });

    document.addEventListener('htmx:afterSwap', () => {
        initTotpQRCode();
        initLogoutRedirect();
        initDevHtmxLogging();
    });

    document.addEventListener('DOMContentLoaded', () => {
        initTotpQRCode();
        initLogoutRedirect();
        initDevHtmxLogging();
    });

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
