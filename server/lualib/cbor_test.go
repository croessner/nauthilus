// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

package lualib

import (
	"testing"

	"github.com/croessner/nauthilus/server/definitions"
	"github.com/fxamacker/cbor/v2"
	lua "github.com/yuin/gopher-lua"
)

func preloadTestCBOR(t *testing.T, L *lua.LState) {
	t.Helper()

	L.PreloadModule(definitions.LuaModCBOR, LoaderModCBOR())
}

func TestLuaCBORDecode(t *testing.T) {
	L := lua.NewState()
	defer L.Close()

	preloadTestCBOR(t, L)

	payload, err := cbor.Marshal(map[string]any{
		"username": "user1",
		"groups":   []any{"mail", "admin"},
		"enabled":  true,
	})
	if err != nil {
		t.Fatal(err)
	}

	L.SetGlobal("payload", lua.LString(payload))

	if err := L.DoString(`
		local cbor = require("nauthilus_cbor")
		decoded, decode_err = cbor.decode(payload)
	`); err != nil {
		t.Fatal(err)
	}

	if got := L.GetGlobal("decode_err"); got != lua.LNil {
		t.Fatalf("expected nil decode error, got %v", got)
	}

	decoded := L.GetGlobal("decoded").(*lua.LTable)
	if got := decoded.RawGetString("username").String(); got != "user1" {
		t.Fatalf("expected username user1, got %q", got)
	}

	groups := decoded.RawGetString("groups").(*lua.LTable)
	if got := groups.RawGetInt(2).String(); got != "admin" {
		t.Fatalf("expected second group admin, got %q", got)
	}

	if got := decoded.RawGetString("enabled"); got != lua.LTrue {
		t.Fatalf("expected enabled true, got %v", got)
	}
}

func TestLuaCBOREncode(t *testing.T) {
	L := lua.NewState()
	defer L.Close()

	preloadTestCBOR(t, L)

	if err := L.DoString(`
		local cbor = require("nauthilus_cbor")
		payload, encode_err = cbor.encode({
			ok = true,
			user = "user1",
			values = {1, 2, 3},
		})
	`); err != nil {
		t.Fatal(err)
	}

	if got := L.GetGlobal("encode_err"); got != lua.LNil {
		t.Fatalf("expected nil encode error, got %v", got)
	}

	var decoded map[string]any
	if err := cbor.Unmarshal([]byte(L.GetGlobal("payload").String()), &decoded); err != nil {
		t.Fatal(err)
	}

	if decoded["user"] != "user1" {
		t.Fatalf("expected user1, got %v", decoded["user"])
	}

	if decoded["ok"] != true {
		t.Fatalf("expected ok true, got %v", decoded["ok"])
	}
}

func TestLuaCBORNullAndByteString(t *testing.T) {
	L := lua.NewState()
	defer L.Close()

	preloadTestCBOR(t, L)

	payload, err := cbor.Marshal(map[string]any{
		"empty": nil,
		"raw":   []byte{0x00, 0x01, 0x02},
	})
	if err != nil {
		t.Fatal(err)
	}

	L.SetGlobal("payload", lua.LString(payload))

	if err := L.DoString(`
		local cbor = require("nauthilus_cbor")
		decoded, decode_err = cbor.decode(payload)
		roundtrip, encode_err = cbor.encode({
			empty = cbor.null,
			raw = cbor.bytes(decoded.raw),
		})
	`); err != nil {
		t.Fatal(err)
	}

	if got := L.GetGlobal("decode_err"); got != lua.LNil {
		t.Fatalf("expected nil decode error, got %v", got)
	}

	if got := L.GetGlobal("encode_err"); got != lua.LNil {
		t.Fatalf("expected nil encode error, got %v", got)
	}

	var decoded map[string]any
	if err := cbor.Unmarshal([]byte(L.GetGlobal("roundtrip").String()), &decoded); err != nil {
		t.Fatal(err)
	}

	if decoded["empty"] != nil {
		t.Fatalf("expected empty nil, got %v", decoded["empty"])
	}

	raw, ok := decoded["raw"].([]byte)
	if !ok {
		t.Fatalf("expected raw []byte, got %T", decoded["raw"])
	}

	if string(raw) != string([]byte{0x00, 0x01, 0x02}) {
		t.Fatalf("unexpected raw payload: %v", raw)
	}
}
