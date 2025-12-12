package definitions

import "testing"

func TestLuaAction_String(t *testing.T) {
	tests := []struct {
		name string
		a    LuaAction
		want string
	}{
		{name: "none", a: LuaActionNone, want: ""},
		{name: "brute_force", a: LuaActionBruteForce, want: LuaActionBruteForceName},
		{name: "rbl", a: LuaActionRBL, want: LuaActionRBLName},
		{name: "tls_encryption", a: LuaActionTLS, want: LuaActionTLSName},
		{name: "relay_domains", a: LuaActionRelayDomains, want: LuaActionRelayDomainsName},
		{name: "lua", a: LuaActionLua, want: LuaActionLuaName},
		{name: "post", a: LuaActionPost, want: LuaActionPostName},
		{name: "unknown", a: LuaAction(255), want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.a.String(); got != tt.want {
				t.Fatalf("LuaAction(%d).String() = %q, want %q", tt.a, got, tt.want)
			}
		})
	}
}
