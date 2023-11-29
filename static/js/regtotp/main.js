import Totp from "/static/js/classes/Totp.js";

const totp_digits = 6;

const totp_code = new Totp(document.querySelector("#totp > div"), totp_digits);

totp_code.generate_qr_code();
onresize = totp_code.refresh_qr_code;

// Copy QR code to clipboard when clicking the image
document.querySelector("#totp > div > img").addEventListener("click", totp_code.copy_qr_code_to_clipboard);
