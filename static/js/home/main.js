/*
 * Home page
 */


/**
 * Register TOTP
 */

const totp = document.getElementById("register_totp");
if (totp === null) {
    throw new Error("Missing element 'totp'");
}

const have_totp = totp.getAttribute("data-havetotp");
if (have_totp === "true") {
    totp.classList.add("disable");
    totp.disabled = true;
}

const device = document.getElementById("register_device");
if (device === null) {
    throw new Error("Missing element 'device'");
}

const register_totp = (event) => {
    event.preventDefault();

    const totp_url = encodeURI(`${location.protocol}//`
        + `${location.host}`
        + `${totp.getAttribute("data-endpointtotp")}`);

    location.assign(totp_url);
}
totp.addEventListener("click", register_totp);

/**
 * Register a U2F/FIDO2 device
 */

const register_device = async event => {
    event.preventDefault();

    const ab_to_b64 = bin => {
        const uint8array = new Uint8Array(bin)
        const str = btoa(String.fromCharCode(...uint8array))

        return str
            .replace(/\+/g, "-")
            .replace(/\//g, "_")
            .replace(/=/g, "")
    }

    const b64_to_uint8array = b64str => {
        const len = b64str.length

        b64str = b64str
            .replace(/-/g, "+")
            .replace(/_/g, "/")
            .padEnd(len+((4-len%4)%4), "=")

        return new Uint8Array([...atob(b64str)].map((e) => e.charCodeAt(0)))
    }

    // Check whether current browser supports WebAuthn
    if (!window.PublicKeyCredential) {
        alert("Error: this browser does not support WebAuthn");

        return;
    }

    let status_code

    // The username is stored in a cookie. Start the registration process...
    await fetch("/2fa/v1/webauthn/register/begin")
        .then(async response => {
            const credentialCreationOptions = await response.json();

            credentialCreationOptions.publicKey.challenge = b64_to_uint8array(
                credentialCreationOptions.publicKey.challenge
            );

            credentialCreationOptions.publicKey.user.id = b64_to_uint8array(
                credentialCreationOptions.publicKey.user.id
            );

            return navigator.credentials.create({
                publicKey: credentialCreationOptions.publicKey
            });
        })
        .then(async credential => {
            let attestationObject = credential.response.attestationObject;
            let clientDataJSON = credential.response.clientDataJSON;
            let rawId = credential.rawId;

            return await fetch("/2fa/v1/webauthn/register/finish", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    id: credential.id,
                    rawId: ab_to_b64(rawId),
                    type: credential.type,
                    response: {
                        attestationObject: ab_to_b64(attestationObject),
                        clientDataJSON: ab_to_b64(clientDataJSON),
                    }
                })
            });
        })
        .then (async response => {
            status_code = response.status;

            return await response.json();
        })
        .then (result => {
            console.log(`Registration result: code=${status_code} message=${result}`);
        })
        .catch (error => {
            console.error(`An error occurred when registering the user: ${error}`);
        });
}
device.addEventListener("click", register_device);
