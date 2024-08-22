package lualib

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	lua "github.com/yuin/gopher-lua"
)

type mockMonitor struct {
	fail bool
}

func (m *mockMonitor) CheckBackendConnection(_ string, _ int, _ bool, _ bool) error {
	if m.fail {
		return errors.New("connection failed")
	}

	return nil
}

func TestCheckBackendConnection(t *testing.T) {
	monitor := &mockMonitor{}
	checkBackendConnection := CheckBackendConnection(monitor)

	testCases := []struct {
		desc       string
		parameters []lua.LValue
		expected   lua.LValue
		fail       bool
	}{
		{
			desc: "successful connection",
			parameters: []lua.LValue{
				lua.LString("127.0.0.1"),
				lua.LNumber(143),
				lua.LTrue,
				lua.LFalse,
			},
			expected: lua.LNil,
			fail:     false,
		},
		{
			desc: "failed connection",
			parameters: []lua.LValue{
				lua.LString("127.0.0.1"),
				lua.LNumber(143),
				lua.LTrue,
				lua.LFalse,
			},
			expected: lua.LString("connection failed"),
			fail:     true,
		},
		{
			desc:       "missing parameters",
			parameters: []lua.LValue{lua.LString("127.0.0.1")},
			expected:   lua.LString("Invalid number of arguments. Expected 4, got 1"),
			fail:       true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					if tc.fail {
						recoveredMessage := strings.Split(fmt.Sprintf("%v", r), "\n")[0]
						expectedMessage := strings.Split(fmt.Sprintf("%v", tc.expected), "\n")[0]

						if strings.TrimSpace(recoveredMessage) == strings.TrimSpace(expectedMessage) {
							return
						}

						t.Errorf("Expected panic with message '%s', got '%s'", expectedMessage, recoveredMessage)
					} else {
						t.Errorf("Unexpected panic: %v", r)
					}
				}
			}()

			L := lua.NewState()

			defer L.Close()

			for _, p := range tc.parameters {
				L.Push(p)
			}

			monitor.fail = tc.fail

			if r := checkBackendConnection(L); r != 1 {
				t.Errorf("Expected return value to be 1, got %d", r)
			}

			if !tc.fail {
				gotResult := L.Get(-1)
				if gotResult.Type() != tc.expected.Type() && gotResult.String() != tc.expected.String() {
					t.Errorf("Expected lua return value of '%s', got '%s'", tc.expected.String(), L.Get(-1).String())
				}
			}
		})
	}
}
