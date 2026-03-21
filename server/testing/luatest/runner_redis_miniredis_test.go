package luatest

import (
	"os"
	"path/filepath"
	"testing"
)

// writeTempLuaTestFile writes helper fixtures for isolated Lua test runs.
func writeTempLuaTestFile(t *testing.T, dir, name, content string) string {
	t.Helper()

	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("failed to write %s: %v", name, err)
	}

	return path
}

// TestRedisModuleUsesMiniredisSeedData verifies typed Redis fixture data is readable through real Redis Lua functions.
func TestRedisModuleUsesMiniredisSeedData(t *testing.T) {
	tmpDir := t.TempDir()

	scriptPath := writeTempLuaTestFile(t, tmpDir, "script.lua", `
local redis = require("nauthilus_redis")

function nauthilus_call_action(request)
    local s, err = redis.redis_get("default", "seed:string")
    if err ~= nil or s ~= "alice" then
        return false
    end

    local h, herr = redis.redis_hgetall("default", "seed:hash")
    if herr ~= nil or h.mail ~= "alice@example.com" then
        return false
    end

    local members, smErr = redis.redis_smembers("default", "seed:set")
    if smErr ~= nil or #members ~= 2 then
        return false
    end

    local list, lErr = redis.redis_lrange("default", "seed:list", 0, -1)
    if lErr ~= nil or #list ~= 2 or list[1] ~= "first" or list[2] ~= "second" then
        return false
    end

    local zrange, zErr = redis.redis_zrange("default", "seed:zset", 0, -1)
    if zErr ~= nil or #zrange ~= 2 then
        return false
    end

    local hllCount, hllErr = redis.redis_pfcount("default", "seed:hll")
    if hllErr ~= nil or hllCount < 2 then
        return false
    end

    local ttl, ttlErr = redis.redis_get("default", "seed:ttl")
    if ttlErr ~= nil or ttl ~= "present" then
        return false
    end

    return true
end
`)

	mockPath := writeTempLuaTestFile(t, tmpDir, "mock.json", `{
  "redis": {
    "initial_data": {
      "strings": {
        "seed:string": "alice",
        "seed:ttl": "present"
      },
      "hashes": {
        "seed:hash": {
          "mail": "alice@example.com"
        }
      },
      "sets": {
        "seed:set": ["a", "b"]
      },
      "lists": {
        "seed:list": ["first", "second"]
      },
      "zsets": {
        "seed:zset": [
          {"member": "one", "score": 1},
          {"member": "two", "score": 2}
        ]
      },
      "hyperloglogs": {
        "seed:hll": ["alice", "bob"]
      },
      "ttl_seconds": {
        "seed:ttl": 3600
      }
    }
  },
  "expected_output": {
    "action_result": true,
    "error_expected": false
  }
}`)

	runner, err := NewTestRunner(scriptPath, "action", mockPath)
	if err != nil {
		t.Fatalf("NewTestRunner failed: %v", err)
	}

	result, err := runner.Run()
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	if !result.Success {
		t.Fatalf("expected miniredis-seeded redis operations to pass, got errors: %v", result.Errors)
	}
}

// TestRedisExpectedCallsWorkWithRealRedisModule verifies expected_calls order checking on wrapped real Redis functions.
func TestRedisExpectedCallsWorkWithRealRedisModule(t *testing.T) {
	tmpDir := t.TempDir()

	scriptPath := writeTempLuaTestFile(t, tmpDir, "script.lua", `
local redis = require("nauthilus_redis")

function nauthilus_call_action(request)
    local ok, setErr = redis.redis_set("default", "call:key", "value", 0)
    if setErr ~= nil or ok ~= "OK" then
        return false
    end

    local val, getErr = redis.redis_get("default", "call:key")
    if getErr ~= nil or val ~= "value" then
        return false
    end

    return true
end
`)

	mockPath := writeTempLuaTestFile(t, tmpDir, "mock.json", `{
  "redis": {
    "expected_calls": [
      {"method": "redis_set", "arg_contains": "call:key"},
      {"method": "redis_get", "arg_contains": "call:key"}
    ]
  },
  "expected_output": {
    "action_result": true,
    "error_expected": false
  }
}`)

	runner, err := NewTestRunner(scriptPath, "action", mockPath)
	if err != nil {
		t.Fatalf("NewTestRunner failed: %v", err)
	}

	result, err := runner.Run()
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	if !result.Success {
		t.Fatalf("expected redis expected_calls validation to pass, got errors: %v", result.Errors)
	}
}
