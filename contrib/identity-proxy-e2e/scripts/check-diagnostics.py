#!/usr/bin/env python3
"""Assert the shape of the operational diagnostics answer of the identity-proxy E2E stack.

The answer comes from edge-a, which reads its own metric registry (nauthilus_runtime) and asks the disposable
Prometheus, which scrapes the authority and both edges (prometheus). The check exits non-zero with the first
deviation, so the caller can retry until Prometheus has seen every instance twice.
"""

import json
import sys

# Components the Prometheus profile covers, and the instances Prometheus scrapes.
PROMETHEUS_COMPONENTS = ("ldap", "auth_backend", "redis", "auth_event_delivery", "clickhouse_export", "policy")
INSTANCES = ("authority", "edge-a", "edge-b")

# Prometheus findings state counts of the window, never an unknown or a current state.
PROMETHEUS_STATUSES = ("not_observed", "observed")


def fail(message):
    sys.exit(message)


def check_scope(answer):
    scope = answer.get("scope", {})
    if answer.get("schema_version") != "1" or scope.get("instance") != "edge-a" or scope.get("deployment") != "e2e":
        fail("unexpected scope: " + json.dumps(scope))


def check_sources(answer):
    sources = {source["name"]: source for source in answer.get("sources", [])}

    runtime = sources.get("nauthilus_runtime", {})
    if runtime.get("status") != "ok" or runtime.get("kind") != "local_current" or \
            runtime.get("coverage", {}).get("view") != "local_instance" or runtime.get("coverage", {}).get("instances") != ["edge-a"]:
        fail("runtime source report: " + json.dumps(runtime))

    prometheus = sources.get("prometheus", {})
    covered = prometheus.get("coverage", {}).get("instances", [])
    if prometheus.get("status") != "ok" or prometheus.get("kind") != "historical" or \
            prometheus.get("coverage", {}).get("view") != "metric_labels":
        fail("prometheus source report: " + json.dumps(prometheus))
    if sorted(covered) != sorted(INSTANCES):
        fail("prometheus covers " + json.dumps(covered) + ", want " + json.dumps(list(INSTANCES)))

    if sources.get("loki", {}).get("status") != "not_configured":
        fail("loki source report: " + json.dumps(sources.get("loki")))

    return covered


def check_findings(answer):
    findings = answer.get("findings", [])
    ids = [finding["id"] for finding in findings]
    if len(set(ids)) != len(ids):
        fail("duplicate finding ids")

    runtime_components = {finding["component"] for finding in findings if finding["source"] == "nauthilus_runtime"}
    if not set(PROMETHEUS_COMPONENTS) <= runtime_components:
        fail("runtime findings miss components: " + json.dumps(sorted(set(PROMETHEUS_COMPONENTS) - runtime_components)))

    for component in PROMETHEUS_COMPONENTS:
        for instance in INSTANCES:
            matching = [finding for finding in findings if finding["source"] == "prometheus" and
                        finding["component"] == component and finding["scope"].get("instance") == instance]
            if not matching:
                fail("no prometheus finding for " + component + " on " + instance)
            for finding in matching:
                if finding["status"] not in PROMETHEUS_STATUSES or finding["freshness"]["basis"] != "metric_window":
                    fail("prometheus finding " + finding["id"] + " is " + finding["status"] + "/" + finding["freshness"]["basis"])

    return len(findings)


def check_notes(answer):
    notes = answer.get("notes", [])
    if "LOCAL_VIEW_NOT_CLUSTER" not in notes:
        fail("the local runtime view must be marked as not cluster-wide: " + json.dumps(notes))
    for unwanted in ("NO_HISTORICAL_SOURCE", "HISTORICAL_SOURCE_INCOMPLETE"):
        if unwanted in notes:
            fail("unexpected note " + unwanted)


def main(path):
    with open(path, encoding="utf-8") as handle:
        answer = json.load(handle)

    check_scope(answer)
    covered = check_sources(answer)
    count = check_findings(answer)
    check_notes(answer)

    print("diagnostics instance=%s prometheus_instances=%s findings=%d hypotheses=%d" % (
        answer["scope"]["instance"], ",".join(sorted(covered)), count, len(answer.get("hypotheses", []))))


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: check-diagnostics.py <answer.json>")

    main(sys.argv[1])
