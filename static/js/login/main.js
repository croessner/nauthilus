"use strict";

/*
 * Login page
 */

const submit = document.getElementById("submit");
if (submit === null) {
    throw new Error("Missing element 'submit'");
}

const device = document.getElementById("device");
if (device === null) {
    throw new Error("Missing element 'device'");
}

/**
 * This function is a click event handler that submits the form data to a backend server
 */
const login_credentials = () => {
    const form = document.querySelector("form");
    if (form === null) {
        throw new Error("Missing element 'form'");
    }

    form.action = encodeURI(submit.getAttribute("data-loginurl"));
    form.method = "POST";
}
submit.addEventListener("click", login_credentials);

/**
 * Login with a U2F/FIDO2 device
 */
const login_device = (event) => {
    event.preventDefault();

    const device_url = encodeURI(`${location.protocol}//`
        + `${location.host}`
        + `${device.getAttribute("data-deviceurl")}/`
        + `${location.search}`);

    location.assign(device_url);
}
device.addEventListener("click", login_device);
