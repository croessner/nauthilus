'use strict';

// Execute the actual UI event wiring after HTMX has already scheduled its redirect.
// An extra navigation can cancel the first load of a single-use enrollment page.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const listeners = new Map();
const navigations = ['/mfa/recovery/register?flow=opaque'];
class Element {}
class Event {}
class CustomEvent extends Event {
  constructor(detail) { super(); this.detail = detail; }
}
class XMLHttpRequest {
  getResponseHeader(name) { return name === 'HX-Redirect' ? navigations[0] : null; }
}
const root = {setAttribute() {}, getAttribute() { return null; }};
const context = {
  URL, Element, Event, CustomEvent, XMLHttpRequest,
  document: {documentElement: root, addEventListener(name, fn) { listeners.set(name, fn); }},
  localStorage: {getItem() { return 'dark'; }},
  window: {location: {href: 'https://idp.example.test/mfa/totp/register', origin: 'https://idp.example.test', assign(url) { navigations.push(url); }}},
};
vm.runInNewContext(fs.readFileSync(path.join(__dirname, '../../../static/js/idp_ui.js'), 'utf8'), context);
listeners.get('htmx:afterRequest')(new CustomEvent({xhr: new XMLHttpRequest()}));
assert.equal(navigations.length, 1, 'the UI must not repeat the navigation already performed by HTMX');
console.log('ok idp-single-owner-htmx-redirect');
