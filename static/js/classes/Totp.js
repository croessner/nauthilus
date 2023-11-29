/**
 * The module "Totp" manages TOTP QR codes and HTML input fields
 * @module classes/Totp
 */

/**
 * The "Totp" class is used to create a TOTP QR code image and it is responsible to display the code digits input fields
 * as well as managing the submit button
 * @property #totp_image_element - HTML container for the TOTP QR code image. Set to null if unused!
 * @property #totp_digits - Number of digits for the TOTP code
 * @property #totp_form_element - the HTML <form> tag element
 * @property #concatenated_totp_code - concatenation of the 6 digits from the input fields
 * @property #mobile_device_width - if the display width is smaller than 400 pixels, the QR code image is displayed smaller
 * @property #image_small - flag that indicates that the image is for a smaller display size
 * @property #image_large - flag that indicates that the image is for a larger display size
 */
class Totp {
    /**
     * @type {HTMLElement}
     * @private
     */
    #totp_image_element;

    /**
     * @type {number}
     * @private
     */
    #totp_digits;

    /**
     * @type {HTMLElement}
     * @private
     */
    #totp_form_element;

    /**
     * @type {string}
     * @private
     */
    #concatenated_totp_code;

    /**
     * @type {number}
     * @private
     */
    #mobile_device_width;

    /**
     * @type {boolean}
     * @private
     */
    #image_small;

    /**
     * @type {boolean}
     * @private
     */
    #image_large;

    /**
     *
     * @param {HTMLElement} element - this represents an optional HTML element, which can be used to add a QR code image
     * @param {number} digits - the number of digits the TOTP code expects. It defaults to six.
     * @param {number} mobile_device_width - this is the display width of a mobile device, which is used to calculate the QR code image size.
     */
    constructor(element, digits= 6, mobile_device_width= 400) {
        this.#image_small = false;
        this.#image_large = false;
        this.#totp_image_element = element;
        this.#totp_digits = digits;
        this.#mobile_device_width = mobile_device_width;

        this.#totp_form_element = document.getElementById("totp-form");
        if (this.#totp_form_element !== null) {
            this.#totp_form_element.addEventListener("submit", this.#send_code);
        } else {
            throw new Error(`Missing element '#totp-form'`);
        }

        this.#display_input_fields();

        addEventListener("paste", this.#paste_qr_code_from_clipboard);
        document.addEventListener("keyup", this.#toggle_button);
    }

    /*
     * Create and modify a TOTP image
     */

    /**
     * Generate a QR code from the data-qrcode attribute.
     * @returns {QRCode} - QRCode image with a height and width sufficient for different display sizes
     * @public
     */
    generate_qr_code = () => {
        // The QR code is a square and its size is always assigned from the infobox width.
        const qr_code_length = this.#totp_image_element.clientWidth;

        return new QRCode(this.#totp_image_element, {
            text: this.#totp_image_element.getAttribute("data-qrcode"),
            width: qr_code_length,
            height: qr_code_length,
            colorDark: "#000000",
            colorLight: "#ffffff",
            correctLevel: QRCode.CorrectLevel.H
        });
    }

    /**
     * Re-create a QR code, if the size of the window changed or a mobile device was rotated.
     * @public
     */
    refresh_qr_code = () => {
        const remove_qr_code = () => {
            const canvas = this.#totp_image_element.querySelector("canvas");
            if (canvas !== null) {
                canvas.remove();
            }

            const image = this.#totp_image_element.querySelector("img");
            if (image !== null) {
                image.remove();
            }
        }

        // This size must match with the mobile device setting in CSS!
        if (innerWidth < this.#mobile_device_width) {
            if (!this.#image_small) {
                remove_qr_code();
                this.generate_qr_code();

                this.#image_small = true;
                this.#image_large = false;
            }
        } else {
            if (!this.#image_large) {
                remove_qr_code();
                this.generate_qr_code();

                this.#image_small = false;
                this.#image_large = true;
            }
        }
    }

    /**
     * Copy QR code to clipboard when clicking the image
     * @returns {Promise<void>} - A Promise which is resolved once the clipboard`s contents have been updated.
     * @public
     */
    copy_qr_code_to_clipboard = async () => {
        const p = document.createElement("p");

        const totp_copied = document.getElementById("totp-copied");
        if (totp_copied === null) {
            throw new Error("Missing element '#totp-copied'");
        }

        try {
            await navigator.clipboard.writeText(this.#totp_image_element.getAttribute("data-qrcode"));
        } catch (err) {
            console.error(`Failed to copy to clipboard: ${err}`);

            return;
        }

        p.classList.add("text");
        p.style.textAlign = "center";
        p.textContent = totp_copied.getAttribute("data-totpcopied");

        document.querySelectorAll("#totp-copied p").forEach(element => element.remove());
        totp_copied.insertAdjacentElement("afterbegin", p);

        setTimeout(() => p.remove(), 10000);
    }

    /*
     * Create and manage TOTP digit input fields
     */

    /**
     *
     * @param {number} input_number - integer that is appended to a newly created <input>-field (id, name attributes)
     * @returns {{input: HTMLInputElement, label: HTMLLabelElement}} - this object holds an HTML label and input field
     * @private
     */
    #generate_totp_input_field(input_number) {
        const label = document.createElement("label");

        label.classList.add("visually-hidden");
        label.setAttribute("for", `code_${input_number}`);
        label.textContent = `${input_number}`;

        const input = document.createElement("input");

        input.classList.add("totp-digit");
        input.setAttribute("type", "text");
        input.setAttribute("id", `code_${input_number}`);
        input.setAttribute("name", `code_${input_number}`);
        input.setAttribute("placeholder", `${input_number}`);
        input.setAttribute("minlength", "1");
        input.setAttribute("maxlength", "1");
        input.setAttribute("pattern", "[0-9]*");

        return {
            label: label,
            input: input
        }
    }

    /**
     * Add TOTP <input>-fields to the HTML document
     * @private
     */
    #display_input_fields() {
        const totp_code = document.getElementById("totp-code");
        if (totp_code === null) {
            throw new Error(`Missing element '#totp_code'`);
        }

        for (let i = 0; i < this.#totp_digits; i++) {
            const input_field = this.#generate_totp_input_field(i + 1);

            totp_code.insertAdjacentElement("beforeend", input_field.label);
            totp_code.insertAdjacentElement("beforeend", input_field.input);
            input_field.input.addEventListener("input", this.#validate_input);

            if (i === 0) {
                input_field.input.focus();
            }
        }
    }

    /**
     * Check input fields for numbers and removed unwanted characters
     * @param {InputEvent} event - the "input" event
     * @private
     */
    #validate_input = event => {
        const key = parseInt(event.data);

        if (key >= 0 && key <= 9) {
            if (event.target.nextElementSibling !== null) {
                event.target.nextElementSibling.focus();
            }
        } else if (isNaN(key)) {
            event.target.value = event.target.value.replace(/.*/gi, "");
        } else {
            console.error(`Key ist not recognized: ${event.data}`)
        }
    }

    /**
     * Add final TOTP code to form data
     * @private
     */
    #send_code = () => {
        const code = document.createElement("input");

        code.setAttribute("type", "hidden");
        code.setAttribute("name", "code");
        code.setAttribute("value", this.#concatenated_totp_code);
        this.#totp_form_element.insertAdjacentElement("afterbegin", code);
    }


    /**
     * Check that we have 6 digits given and enable (or disable) the submit button
     * @private
     */
    #toggle_button = () => {
        const submit = document.getElementById("submit");
        if (submit === null) {
            throw new Error("Missing element '#submit'");
        }

        const code_fields = [];

        for (let i = 0; i < this.#totp_digits; i++) {
            const code_field = document.getElementById("code_" + (i + 1));
            code_fields.push(code_field !== null ? code_field.value : "");
        }

        if (code_fields.filter(code_field => code_field !== "").length === this.#totp_digits) {
            this.#concatenated_totp_code = code_fields.join("");
            submit.classList.forEach(class_name => {
                if (class_name === "disable") {
                    submit.classList.remove(class_name);
                }
            });
            submit.disabled = false;
        } else {
            this.#concatenated_totp_code ="";
            submit.classList.add("disable");
            submit.disabled = true;
        }
    }

    /**
     * Parse TOTP code from clipboard into the digit fields
     * @returns {Promise<void>} - nothing is returned
     * @private
     */
    #paste_qr_code_from_clipboard = async () => {
        let totp_code = "";

        try {
            totp_code = await navigator.clipboard.readText();
        } catch (err) {
            throw new Error(`Failed to paste from clipboard: ${err}`);
        }

        if (totp_code.length !== this.#totp_digits) {
            return;
        }

        for (let i = 0; i < totp_code.length; i++) {
            if (!isNaN(parseInt(totp_code[i]))) {
                const digit = document.getElementById(`code_${i + 1}`);
                if (digit === null) {
                    throw new Error(`Missing element 'code_${i + 1}'`);
                }

                digit.value = totp_code[i];
                digit.focus();
            } else {
                break;
            }

            if (i === 5) {
                this.#toggle_button();
            }
        }
    }
}

export default  Totp;