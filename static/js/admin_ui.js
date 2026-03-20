(function () {
    "use strict";

    var boundFlag = "data-admin-bound";
    var clickhouseState = {
        page: 1,
        pageSize: 25,
        hasMore: false,
        loading: false
    };

    function bindOnce(element, key) {
        var attribute = boundFlag + "-" + key;
        if (!element || element.hasAttribute(attribute)) {
            return false;
        }

        element.setAttribute(attribute, "1");

        return true;
    }

    function setActiveModuleTab() {
        var tabs = document.querySelectorAll("[data-module-tab]");
        if (!tabs.length) {
            return;
        }

        tabs.forEach(function (tab, idx) {
            if (idx === 0) {
                tab.classList.add("tab-active");
            }

            if (!bindOnce(tab, "module-tab")) {
                return;
            }

            tab.addEventListener("click", function () {
                tabs.forEach(function (t) {
                    t.classList.remove("tab-active");
                });
                tab.classList.add("tab-active");
            });
        });
    }

    function bindBruteForceTabs() {
        var form = document.getElementById("admin-bf-form");
        var buttons = document.querySelectorAll("[data-bf-tab]");
        if (!form || !buttons.length) {
            return;
        }

        var tabInput = form.querySelector("input[name='tab']");
        var pageInput = form.querySelector("input[name='page']");
        if (!tabInput || !pageInput) {
            return;
        }

        buttons.forEach(function (btn, idx) {
            if (idx === 0) {
                btn.classList.add("btn-active");
            }

            if (!bindOnce(btn, "bf-tab")) {
                return;
            }

            btn.addEventListener("click", function () {
                buttons.forEach(function (other) {
                    other.classList.remove("btn-active");
                });

                btn.classList.add("btn-active");
                tabInput.value = btn.getAttribute("data-bf-tab-value") || "ips";
                pageInput.value = "1";
                triggerBruteForceLoad();
            });
        });

        var refreshButton = document.querySelector("[data-bf-refresh]");
        if (refreshButton && bindOnce(refreshButton, "bf-refresh")) {
            refreshButton.addEventListener("click", triggerBruteForceLoad);
        }

        var searchField = form.querySelector("[name='search']");
        if (searchField && bindOnce(searchField, "bf-search")) {
            searchField.addEventListener("input", function () {
                pageInput.value = "1";
                triggerBruteForceLoad();
            });
        }

        triggerBruteForceLoad();
    }

    function bindClickhouseFormSerialization() {
        var form = document.getElementById("admin-clickhouse-form");
        if (!form) {
            return;
        }

        var pageInput = form.querySelector("input[name='page']");
        var pageSizeInput = form.querySelector("input[name='page_size']");
        if (!pageInput || !pageSizeInput) {
            return;
        }

        ["action", "status", "filter", "search"].forEach(function (name) {
            var field = form.querySelector("[name='" + name + "']");
            if (!field) {
                return;
            }

            if (!bindOnce(field, "clickhouse-reset-" + name)) {
                return;
            }

            field.addEventListener("change", function () {
                pageInput.value = "1";
                syncClickhouseStateFromForm(form);
            });
        });

        var runButton = document.querySelector("[data-clickhouse-run]");
        if (runButton && bindOnce(runButton, "clickhouse-run")) {
            runButton.addEventListener("click", function () {
                pageInput.value = "1";
                syncClickhouseStateFromForm(form);
                triggerClickhouseLoad();
            });
        }

        var searchField = form.querySelector("[name='search']");
        if (searchField && bindOnce(searchField, "clickhouse-search")) {
            searchField.addEventListener("input", function () {
                pageInput.value = "1";
                syncClickhouseStateFromForm(form);
                triggerClickhouseLoad();
            });
        }

        bindClickhousePaginationControls(form);
        syncClickhouseStateFromForm(form);
        updateClickhousePaginationControls();
        triggerClickhouseLoad();
    }

    function syncClickhouseStateFromForm(form) {
        var pageInput = form.querySelector("[name='page']");
        var pageSizeInput = form.querySelector("[name='page_size']");

        var page = parseInt((pageInput || {}).value || "1", 10);
        var pageSize = parseInt((pageSizeInput || {}).value || "25", 10);

        if (!Number.isFinite(page) || page < 1) {
            page = 1;
        }

        if (!Number.isFinite(pageSize) || pageSize < 1) {
            pageSize = 25;
        }

        clickhouseState.page = page;
        clickhouseState.pageSize = pageSize;
    }

    function bindClickhousePaginationControls(form) {
        var pageInput = form.querySelector("[name='page']");
        var pageSizeInput = form.querySelector("[name='page_size']");
        var prevButton = document.querySelector("[data-clickhouse-prev]");
        var nextButton = document.querySelector("[data-clickhouse-next]");
        var pageSizeSelect = document.querySelector("[data-clickhouse-page-size]");

        if (pageSizeSelect) {
            pageSizeSelect.value = (pageSizeInput || {}).value || "25";
        }

        if (prevButton && bindOnce(prevButton, "clickhouse-prev")) {
            prevButton.addEventListener("click", function () {
                if (clickhouseState.loading || clickhouseState.page <= 1) {
                    return;
                }

                clickhouseState.page -= 1;
                if (pageInput) {
                    pageInput.value = String(clickhouseState.page);
                }

                triggerClickhouseLoad();
            });
        }

        if (nextButton && bindOnce(nextButton, "clickhouse-next")) {
            nextButton.addEventListener("click", function () {
                if (clickhouseState.loading || !clickhouseState.hasMore) {
                    return;
                }

                clickhouseState.page += 1;
                if (pageInput) {
                    pageInput.value = String(clickhouseState.page);
                }

                triggerClickhouseLoad();
            });
        }

        if (pageSizeSelect && bindOnce(pageSizeSelect, "clickhouse-page-size")) {
            pageSizeSelect.addEventListener("change", function () {
                var value = pageSizeSelect.value || "25";
                if (pageSizeInput) {
                    pageSizeInput.value = value;
                }

                if (pageInput) {
                    pageInput.value = "1";
                }

                syncClickhouseStateFromForm(form);
                triggerClickhouseLoad();
            });
        }
    }

    function updateClickhousePaginationControls() {
        var prevButton = document.querySelector("[data-clickhouse-prev]");
        var nextButton = document.querySelector("[data-clickhouse-next]");
        var pageIndicator = document.getElementById("admin-clickhouse-page-indicator");
        var pageSizeSelect = document.querySelector("[data-clickhouse-page-size]");

        if (prevButton) {
            prevButton.disabled = clickhouseState.loading || clickhouseState.page <= 1;
        }

        if (nextButton) {
            nextButton.disabled = clickhouseState.loading || !clickhouseState.hasMore;
        }

        if (pageSizeSelect) {
            pageSizeSelect.disabled = clickhouseState.loading;
            pageSizeSelect.value = String(clickhouseState.pageSize);
        }

        if (pageIndicator) {
            pageIndicator.textContent = String(clickhouseState.page);
        }
    }

    function bindMapToggle() {
        var toggle = document.querySelector("[data-map-toggle]");
        var wrapper = document.getElementById("clickhouse-map-wrapper");
        if (!toggle || !wrapper) {
            return;
        }

        if (!bindOnce(toggle, "map-toggle")) {
            return;
        }

        var expandedText = "Collapse";
        var collapsedText = "Expand";

        toggle.addEventListener("click", function () {
            var hidden = wrapper.classList.toggle("hidden");
            toggle.textContent = hidden ? collapsedText : expandedText;
        });
    }

    function getCookie(name) {
        var prefix = name + "=";
        var parts = document.cookie.split(";");

        for (var i = 0; i < parts.length; i += 1) {
            var part = parts[i].trim();
            if (part.indexOf(prefix) === 0) {
                return decodeURIComponent(part.slice(prefix.length));
            }
        }

        return "";
    }

    function parseJSONObject(raw, fallback) {
        var text = (raw || "").trim();
        if (!text) {
            return fallback;
        }

        var parsed = JSON.parse(text);
        if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
            return parsed;
        }

        throw new Error("Expected JSON object");
    }

    function formatJSON(value) {
        try {
            return JSON.stringify(value, null, 2);
        } catch (_err) {
            return String(value);
        }
    }

    function getNoDataLabel(node) {
        if (node && node.dataset && node.dataset.noData) {
            return node.dataset.noData;
        }

        return "No data yet.";
    }

    function coerceArray(value) {
        return Array.isArray(value) ? value : [];
    }

    function textCell(value) {
        var text = value;
        if (text === null || text === undefined || text === "") {
            text = "-";
        }

        return "<td>" + escapeHTML(String(text)) + "</td>";
    }

    function escapeHTML(value) {
        return value
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/\"/g, "&quot;")
            .replace(/'/g, "&#39;");
    }

    function toISODate(raw) {
        if (!raw) {
            return "-";
        }

        var parsed = new Date(raw);
        if (Number.isNaN(parsed.getTime())) {
            return String(raw);
        }

        return parsed.toISOString();
    }

    function getRequestHeaders() {
        var csrfToken = getCookie("csrf_token");
        var headers = {"Content-Type": "application/json"};

        if (csrfToken) {
            headers["X-CSRF-Token"] = csrfToken;
        }

        return headers;
    }

    function submitJSON(url, method, payload) {
        return fetch(url, {
            method: method,
            credentials: "same-origin",
            headers: getRequestHeaders(),
            body: JSON.stringify(payload || {})
        }).then(function (response) {
            return response.json().catch(function () {
                return {};
            }).then(function (body) {
                return {ok: response.ok, status: response.status, body: body};
            });
        });
    }

    function parseBruteForceResult(payload) {
        var resultArray = coerceArray(payload && payload.result);
        var blockedIPs = resultArray[0] || {};
        var blockedAccounts = resultArray[1] || {};

        return {
            ips: coerceArray(blockedIPs.entries),
            accounts: blockedAccounts.accounts || {}
        };
    }

    function matchesSearch(haystackParts, search) {
        if (!search) {
            return true;
        }

        var haystack = haystackParts.join(" ").toLowerCase();
        return haystack.indexOf(search) !== -1;
    }

    function renderNoDataRow(tbody, colspan) {
        var label = getNoDataLabel(tbody);
        tbody.innerHTML = "<tr><td colspan=\"" + colspan + "\" class=\"text-center opacity-70\">" + escapeHTML(label) + "</td></tr>";
    }

    function renderBruteForceRows(data) {
        var form = document.getElementById("admin-bf-form");
        var tbody = document.getElementById("admin-bf-table-body");
        var summary = document.getElementById("admin-bf-summary");
        if (!form || !tbody || !summary) {
            return;
        }

        var tab = (form.querySelector("[name='tab']") || {}).value || "ips";
        var search = (((form.querySelector("[name='search']") || {}).value) || "").trim().toLowerCase();
        var page = parseInt(((form.querySelector("[name='page']") || {}).value) || "1", 10);
        var pageSize = parseInt(((form.querySelector("[name='page_size']") || {}).value) || "25", 10);
        if (!Number.isFinite(page) || page < 1) {
            page = 1;
        }

        if (!Number.isFinite(pageSize) || pageSize < 1) {
            pageSize = 25;
        }

        var rows = [];

        if (tab === "accounts") {
            var accounts = data.accounts || {};
            Object.keys(accounts).forEach(function (account) {
                var ips = coerceArray(accounts[account]);
                if (!matchesSearch([account].concat(ips), search)) {
                    return;
                }

                rows.push({
                    ip: ips.join(", "),
                    account: account,
                    protocol: "-",
                    timestamp: "-",
                    action: "free-user",
                    value: account
                });
            });
        } else {
            coerceArray(data.ips).forEach(function (entry) {
                var network = entry.network || "";
                var bucket = entry.bucket || "-";
                var timestamp = toISODate(entry.banned_at || entry.bannedAt);
                if (!matchesSearch([network, bucket, timestamp], search)) {
                    return;
                }

                rows.push({
                    ip: network,
                    account: "-",
                    protocol: bucket,
                    timestamp: timestamp,
                    action: "free-ip",
                    value: network,
                    ruleName: bucket
                });
            });
        }

        var total = rows.length;
        var start = (page - 1) * pageSize;
        var pageRows = rows.slice(start, start + pageSize);
        var freeIPLabel = form.dataset.labelFreeIp || "Free IP";
        var freeUserLabel = form.dataset.labelFreeUser || "Free User";
        summary.textContent = total > 0 ? String(total) : getNoDataLabel(summary);

        if (!pageRows.length) {
            renderNoDataRow(tbody, 5);
            return;
        }

        tbody.innerHTML = pageRows.map(function (row) {
            var actionButton;
            if (row.action === "free-user") {
                actionButton = "<button class=\"btn btn-xs btn-outline\" data-bf-action=\"free-user\" data-bf-user=\"" + escapeHTML(row.value) + "\" type=\"button\">" + escapeHTML(freeUserLabel) + "</button>";
            } else {
                actionButton = "<button class=\"btn btn-xs btn-outline\" data-bf-action=\"free-ip\" data-bf-ip=\"" + escapeHTML(row.value) + "\" data-bf-rule=\"" + escapeHTML(row.ruleName || "*") + "\" type=\"button\">" + escapeHTML(freeIPLabel) + "</button>";
            }

            return "<tr>"
                + textCell(row.ip)
                + textCell(row.account)
                + textCell(row.protocol)
                + textCell(row.timestamp)
                + "<td>" + actionButton + "</td>"
                + "</tr>";
        }).join("");

        bindBruteForceRowActions();
    }

    function bindBruteForceRowActions() {
        var form = document.getElementById("admin-bf-form");
        if (!form) {
            return;
        }

        var freeIPURL = form.dataset.apiFreeIpUrl || "/admin/api/bruteforce/free-ip";
        var freeUserURL = form.dataset.apiFreeUserUrl || "/admin/api/bruteforce/free-user";
        var buttons = document.querySelectorAll("[data-bf-action]");
        buttons.forEach(function (button) {
            if (!bindOnce(button, "bf-row-action")) {
                return;
            }

            button.addEventListener("click", function () {
                var action = button.getAttribute("data-bf-action");
                if (action === "free-user") {
                    var user = button.getAttribute("data-bf-user") || "";
                    submitJSON(freeUserURL, "POST", {user: user}).then(triggerBruteForceLoad);
                    return;
                }

                var ip = button.getAttribute("data-bf-ip") || "";
                var rule = button.getAttribute("data-bf-rule") || "*";
                submitJSON(freeIPURL, "POST", {ip_address: ip, rule_name: rule}).then(triggerBruteForceLoad);
            });
        });
    }

    function triggerBruteForceLoad() {
        var form = document.getElementById("admin-bf-form");
        var summary = document.getElementById("admin-bf-summary");
        if (!form) {
            return;
        }

        var url = form.dataset.apiListUrl || "/admin/api/bruteforce/list";
        var query = new URLSearchParams();
        var tab = (form.querySelector("[name='tab']") || {}).value || "ips";
        var search = (form.querySelector("[name='search']") || {}).value || "";

        if (tab === "accounts" && search.trim() !== "") {
            query.set("accounts", search.trim());
        }

        if (tab === "ips" && search.trim() !== "") {
            query.set("ip_addresses", search.trim());
        }

        var requestURL = query.toString() ? url + "?" + query.toString() : url;
        if (summary) {
            summary.textContent = "...";
        }

        fetch(requestURL, {
            method: "GET",
            credentials: "same-origin",
            headers: {Accept: "application/json"}
        }).then(function (response) {
            return response.json().then(function (body) {
                return {ok: response.ok, status: response.status, body: body};
            });
        }).then(function (result) {
            if (!result.ok) {
                if (summary) {
                    summary.textContent = "Error " + result.status;
                }

                return;
            }

            renderBruteForceRows(parseBruteForceResult(result.body));
        }).catch(function (err) {
            if (summary) {
                summary.textContent = String(err);
            }
        });
    }

    function pickFirstValue(row, keys) {
        var index;
        for (index = 0; index < keys.length; index += 1) {
            var value = row[keys[index]];
            if (value !== null && value !== undefined && value !== "") {
                return value;
            }
        }

        return "-";
    }

    function detectCountry(row) {
        return pickFirstValue(row, ["country", "country_name", "geo_country", "countryCode", "country_code", "cc", "geoip_country"]);
    }

    function updateCountrySummary(rows) {
        var countriesNode = document.getElementById("admin-clickhouse-countries");
        if (!countriesNode) {
            return;
        }

        var counts = {};
        rows.forEach(function (row) {
            var country = detectCountry(row);
            if (country === "-") {
                return;
            }

            counts[country] = (counts[country] || 0) + 1;
        });

        var entries = Object.keys(counts).map(function (key) {
            return {country: key, count: counts[key]};
        }).sort(function (a, b) {
            return b.count - a.count;
        }).slice(0, 8);

        if (!entries.length) {
            countriesNode.innerHTML = "<li><span>" + escapeHTML(getNoDataLabel(countriesNode)) + "</span></li>";
            return;
        }

        countriesNode.innerHTML = entries.map(function (entry) {
            return "<li><span>" + escapeHTML(entry.country) + " (" + entry.count + ")</span></li>";
        }).join("");
    }

    function renderClickhouseRows(payload) {
        var tbody = document.getElementById("admin-clickhouse-table-body");
        var summary = document.getElementById("admin-clickhouse-summary");
        var form = document.getElementById("admin-clickhouse-form");
        if (!tbody || !summary || !form) {
            return;
        }

        var rows = coerceArray(payload && payload.rows);
        clickhouseState.page = parseInt(payload && payload.page, 10);
        if (!Number.isFinite(clickhouseState.page) || clickhouseState.page < 1) {
            clickhouseState.page = 1;
        }

        clickhouseState.pageSize = parseInt(payload && payload.page_size, 10);
        if (!Number.isFinite(clickhouseState.pageSize) || clickhouseState.pageSize < 1) {
            clickhouseState.pageSize = 25;
        }

        clickhouseState.hasMore = Boolean(payload && payload.has_more);

        var pageInput = form.querySelector("[name='page']");
        var pageSizeInput = form.querySelector("[name='page_size']");
        if (pageInput) {
            pageInput.value = String(clickhouseState.page);
        }

        if (pageSizeInput) {
            pageSizeInput.value = String(clickhouseState.pageSize);
        }

        updateClickhousePaginationControls();

        if (!rows.length) {
            summary.textContent = getNoDataLabel(summary);
            renderNoDataRow(tbody, 5);
            updateCountrySummary(rows);
            return;
        }

        summary.textContent = "page " + clickhouseState.page + ", rows " + rows.length + ", has_more " + String(clickhouseState.hasMore);

        tbody.innerHTML = rows.map(function (row) {
            return "<tr>"
                + textCell(toISODate(pickFirstValue(row, ["timestamp", "ts", "event_time", "time"])))
                + textCell(pickFirstValue(row, ["username", "user", "login", "principal"]))
                + textCell(pickFirstValue(row, ["account", "account_name", "subject"]))
                + textCell(pickFirstValue(row, ["ip", "ip_address", "remote_addr", "client_ip"]))
                + textCell(pickFirstValue(row, ["status", "result", "auth_result", "state"]))
                + "</tr>";
        }).join("");

        updateCountrySummary(rows);
    }

    function triggerClickhouseLoad() {
        var form = document.getElementById("admin-clickhouse-form");
        var summary = document.getElementById("admin-clickhouse-summary");
        if (!form) {
            return;
        }

        clickhouseState.loading = true;
        updateClickhousePaginationControls();

        var queryURL = form.dataset.apiQueryUrl || "/admin/api/clickhouse/query";
        var params = new URLSearchParams();
        var fields = form.querySelectorAll("[name]");
        fields.forEach(function (field) {
            if (!field.name) {
                return;
            }

            var value = (field.value || "").trim();
            if (value === "") {
                return;
            }

            params.set(field.name, value);
        });

        if (summary) {
            summary.textContent = "...";
        }

        fetch(queryURL + "?" + params.toString(), {
            method: "GET",
            credentials: "same-origin",
            headers: {Accept: "application/json"}
        }).then(function (response) {
            return response.json().then(function (body) {
                return {ok: response.ok, status: response.status, body: body};
            });
        }).then(function (result) {
            if (!result.ok) {
                if (summary) {
                    summary.textContent = "Error " + result.status;
                }

                return;
            }

            renderClickhouseRows(result.body);
        }).catch(function (err) {
            if (summary) {
                summary.textContent = String(err);
            }
        }).finally(function () {
            clickhouseState.loading = false;
            updateClickhousePaginationControls();
        });
    }

    function bindHookTesterSerialization() {
        var form = document.getElementById("admin-hooktester-form");
        var sendButton = document.querySelector("[data-hooktester-send]");
        if (!form || !sendButton) {
            return;
        }

        var statusNode = document.getElementById("admin-hooktester-status");
        var contentTypeNode = document.getElementById("admin-hooktester-content-type");
        var headersNode = document.getElementById("admin-hooktester-response-headers");
        var bodyNode = document.getElementById("admin-hooktester-response-body");
        var errorNode = document.getElementById("admin-hooktester-error");
        var resetButton = form.querySelector("button[type='reset']");

        if (!statusNode || !contentTypeNode || !headersNode || !bodyNode || !errorNode) {
            return;
        }

        if (!bindOnce(sendButton, "hooktester-send")) {
            return;
        }

        if (resetButton && bindOnce(resetButton, "hooktester-reset")) {
            resetButton.addEventListener("click", function () {
                window.setTimeout(function () {
                    clearHookTesterFieldErrors(form);
                    hideHookTesterError(errorNode);
                    statusNode.textContent = "-";
                    contentTypeNode.textContent = "-";
                    headersNode.value = "{}";
                    bodyNode.value = "{}";
                }, 0);
            });
        }

        sendButton.addEventListener("click", function () {
            var methodField = form.querySelector("[name='method']");
            var endpointField = form.querySelector("[name='endpoint_path']");
            var queryField = form.querySelector("[name='query_json']");
            var headersField = form.querySelector("[name='headers_json']");
            var contentTypeField = form.querySelector("[name='content_type']");
            var bodyField = form.querySelector("[name='body']");

            if (!methodField || !endpointField || !queryField || !headersField || !contentTypeField || !bodyField) {
                return;
            }

            clearHookTesterFieldErrors(form);
            hideHookTesterError(errorNode);

            var endpoint = normalizeHookTesterEndpoint(endpointField.value);
            if (!endpoint) {
                markHookTesterFieldError(endpointField);
                showHookTesterError(errorNode, "Endpoint path must start with / and must not include /api/v1/custom.");
                return;
            }

            var request = {
                method: methodField.value,
                endpoint_path: endpoint
            };

            try {
                request.query = parseJSONObject(queryField.value, {});
            } catch (err) {
                markHookTesterFieldError(queryField);
                statusNode.textContent = "-";
                contentTypeNode.textContent = "application/json";
                headersNode.value = "{}";
                bodyNode.value = formatJSON({error: "Invalid query JSON", detail: err.message});
                showHookTesterError(errorNode, "Query JSON is invalid: " + err.message);
                return;
            }

            try {
                request.headers = parseJSONObject(headersField.value, {});
            } catch (err) {
                markHookTesterFieldError(headersField);
                statusNode.textContent = "-";
                contentTypeNode.textContent = "application/json";
                headersNode.value = "{}";
                bodyNode.value = formatJSON({error: "Invalid headers JSON", detail: err.message});
                showHookTesterError(errorNode, "Headers JSON is invalid: " + err.message);
                return;
            }

            request.content_type = contentTypeField.value;
            request.body = bodyField.value;

            sendButton.disabled = true;
            sendButton.classList.add("loading");
            statusNode.textContent = "...";
            contentTypeNode.textContent = "...";
            headersNode.value = "{}";
            bodyNode.value = "{}";

            var sendURL = form.dataset.apiSendUrl || "/admin/api/hooktester/send";

            fetch(sendURL, {
                method: "POST",
                credentials: "same-origin",
                headers: getRequestHeaders(),
                body: JSON.stringify(request)
            }).then(function (response) {
                return response.text().then(function (text) {
                    var payload = {};
                    if (text.trim() !== "") {
                        try {
                            payload = JSON.parse(text);
                        } catch (_err) {
                            payload = {raw_response: text};
                        }
                    }

                    return {
                        ok: response.ok,
                        status: response.status,
                        payload: payload
                    };
                });
            }).then(function (result) {
                if (!result.ok) {
                    statusNode.textContent = String(result.status);
                    contentTypeNode.textContent = "application/json";
                    headersNode.value = "{}";
                    bodyNode.value = formatJSON(result.payload);
                    showHookTesterError(errorNode, "Request failed with status " + result.status + ".");
                    return;
                }

                statusNode.textContent = String(result.payload.status || "-");
                contentTypeNode.textContent = result.payload.response_content_type || "-";
                headersNode.value = formatJSON(result.payload.response_headers || {});
                bodyNode.value = result.payload.response_body || "";
                hideHookTesterError(errorNode);
            }).catch(function (err) {
                statusNode.textContent = "-";
                contentTypeNode.textContent = "application/json";
                headersNode.value = "{}";
                bodyNode.value = formatJSON({error: "Request failed", detail: String(err)});
                showHookTesterError(errorNode, "Transport error: " + String(err));
            }).finally(function () {
                sendButton.disabled = false;
                sendButton.classList.remove("loading");
            });
        });
    }

    function markHookTesterFieldError(field) {
        if (!field) {
            return;
        }

        field.classList.add("input-error");
        field.classList.add("textarea-error");
    }

    function clearHookTesterFieldErrors(form) {
        var fields = form.querySelectorAll("[name='endpoint_path'], [name='query_json'], [name='headers_json']");
        fields.forEach(function (field) {
            field.classList.remove("input-error");
            field.classList.remove("textarea-error");
        });
    }

    function showHookTesterError(node, message) {
        node.textContent = message;
        node.classList.remove("hidden");
    }

    function hideHookTesterError(node) {
        node.textContent = "";
        node.classList.add("hidden");
    }

    function normalizeHookTesterEndpoint(raw) {
        var value = (raw || "").trim();
        if (!value) {
            return "";
        }

        if (!value.startsWith("/")) {
            return "";
        }

        if (value.startsWith("/api/v1/custom")) {
            return "";
        }

        return value;
    }

    function bindAll() {
        setActiveModuleTab();
        bindBruteForceTabs();
        bindClickhouseFormSerialization();
        bindMapToggle();
        bindHookTesterSerialization();
    }

    document.addEventListener("DOMContentLoaded", bindAll);
    document.body.addEventListener("htmx:afterSwap", bindAll);
})();
