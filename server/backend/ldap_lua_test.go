package backend

import (
	"context"
	"errors"
	"testing"

	"github.com/croessner/nauthilus/v3/server/backend/bktype"
	"github.com/croessner/nauthilus/v3/server/backend/priorityqueue"
	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/go-ldap/ldap/v3"
	"github.com/stretchr/testify/assert"
	"github.com/yuin/gopher-lua"
)

func bindLDAPRuntimeContextForTest(ctx context.Context, L *lua.LState) {
	reqEnv := L.NewTable()
	L.SetGlobal("__NAUTH_REQ_ENV", reqEnv)

	userData := L.NewUserData()
	userData.Value = ctx

	L.SetField(reqEnv, "__NAUTH_REQ_RUNTIME_CONTEXT", userData)
}

type testLDAPEnqueuer struct {
	t        *testing.T
	reply    *bktype.LDAPReply
	request  *bktype.LDAPRequest
	priority int
}

func (e *testLDAPEnqueuer) Push(request *bktype.LDAPRequest, priority int) {
	e.request = request
	e.priority = priority

	if e.reply == nil {
		return
	}

	go func() {
		request.LDAPReplyChan <- e.reply
	}()
}

func newSearchTable(L *lua.LState, rawResult bool) *lua.LTable {
	table := L.NewTable()
	table.RawSetString("pool_name", lua.LString("default"))
	table.RawSetString("session", lua.LString("session-1"))
	table.RawSetString("basedn", lua.LString("dc=example,dc=org"))
	table.RawSetString("filter", lua.LString("(uid=jdoe)"))
	table.RawSetString("scope", lua.LString("sub"))

	attrs := L.NewTable()
	attrs.Append(lua.LString("uid"))
	table.RawSetString("attributes", attrs)

	if rawResult {
		table.RawSetString("raw_result", lua.LTrue)
	}

	return table
}

func newSafeSearchTable(L *lua.LState, rawResult bool) *lua.LTable {
	table := L.NewTable()
	table.RawSetString("pool_name", lua.LString("default"))
	table.RawSetString("session", lua.LString("session-1"))
	table.RawSetString("basedn", lua.LString("ou=people,dc=example,dc=org"))
	table.RawSetString("allowed_base_dn", lua.LString("ou=people,dc=example,dc=org"))
	table.RawSetString("filter_attr", lua.LString("uid"))
	table.RawSetString("filter_value", lua.LString("jdoe"))
	table.RawSetString("scope", lua.LString("sub"))

	attrs := L.NewTable()
	attrs.Append(lua.LString("uid"))
	table.RawSetString("attributes", attrs)

	if rawResult {
		table.RawSetString("raw_result", lua.LTrue)
	}

	return table
}

func newModifyTable(L *lua.LState) *lua.LTable {
	table := L.NewTable()
	table.RawSetString("pool_name", lua.LString("default"))
	table.RawSetString("session", lua.LString("session-1"))
	table.RawSetString("operation", lua.LString("replace"))
	table.RawSetString("dn", lua.LString("uid=jdoe,dc=example,dc=org"))
	table.RawSetString("allowed_base_dn", lua.LString("dc=example,dc=org"))

	attrs := L.NewTable()
	attrs.RawSetString("description", lua.LString("new description"))
	table.RawSetString("attributes", attrs)

	return table
}

func TestLuaLDAPSearch_RawResult(t *testing.T) {
	L := lua.NewState()
	defer L.Close()

	bindLDAPRuntimeContextForTest(context.Background(), L)

	entry := &ldap.Entry{
		DN: "uid=jdoe,dc=example,dc=org",
		Attributes: []*ldap.EntryAttribute{
			{
				Name:   "uid",
				Values: []string{"jdoe"},
			},
		},
	}

	enqueuer := &testLDAPEnqueuer{t: t, reply: &bktype.LDAPReply{RawResult: []*ldap.Entry{entry}}}

	SetLuaLDAPQueue(enqueuer)
	defer SetLuaLDAPQueue(nil)

	table := newSafeSearchTable(L, true)
	L.Push(table)

	fn := LuaLDAPSearch(context.Background())
	ret := fn(L)

	assert.Equal(t, 1, ret)
	assert.NotNil(t, enqueuer.request)
	assert.Equal(t, definitions.DefaultBackendName, enqueuer.request.PoolName)
	assert.Equal(t, definitions.LDAPSearch, enqueuer.request.Command)
	assert.Equal(t, priorityqueue.PriorityLow, enqueuer.priority)

	result := L.Get(-1)
	resultTable, ok := result.(*lua.LTable)
	assert.True(t, ok)

	if !ok {
		return
	}

	assertRawLDAPEntry(t, L, resultTable)
}

// assertRawLDAPEntry verifies the raw LDAP entry returned to Lua.
func assertRawLDAPEntry(t *testing.T, L *lua.LState, resultTable *lua.LTable) {
	t.Helper()

	entryTable, ok := resultTable.RawGetInt(1).(*lua.LTable)
	assert.True(t, ok)

	if !ok {
		return
	}

	assert.Equal(t, "uid=jdoe,dc=example,dc=org", L.GetField(entryTable, "dn").String())
	assertRawLDAPEntryAttribute(t, L.GetField(entryTable, "attributes"))
}

// assertRawLDAPEntryAttribute verifies the raw LDAP uid attribute table.
func assertRawLDAPEntryAttribute(t *testing.T, attributes lua.LValue) {
	t.Helper()

	attrsTable, ok := attributes.(*lua.LTable)
	assert.True(t, ok)

	if !ok {
		return
	}

	uidTable, ok := attrsTable.RawGetString("uid").(*lua.LTable)
	assert.True(t, ok)

	if ok {
		assert.Equal(t, lua.LString("jdoe"), uidTable.RawGetInt(1))
	}
}

func TestLuaLDAPSearch_ErrorReply(t *testing.T) {
	L := lua.NewState()
	defer L.Close()

	bindLDAPRuntimeContextForTest(context.Background(), L)

	enqueuer := &testLDAPEnqueuer{t: t, reply: &bktype.LDAPReply{Err: errors.New("boom")}}

	SetLuaLDAPQueue(enqueuer)
	defer SetLuaLDAPQueue(nil)

	table := newSafeSearchTable(L, false)
	L.Push(table)

	fn := LuaLDAPSearch(context.Background())
	ret := fn(L)

	assert.Equal(t, 2, ret)
	assert.Equal(t, lua.LNil, L.Get(-2))
	assert.Equal(t, "boom", L.Get(-1).String())
}

func TestLuaLDAPModify_OK(t *testing.T) {
	L := lua.NewState()
	defer L.Close()

	bindLDAPRuntimeContextForTest(context.Background(), L)

	enqueuer := &testLDAPEnqueuer{t: t, reply: &bktype.LDAPReply{}}

	SetLuaLDAPQueue(enqueuer)
	defer SetLuaLDAPQueue(nil)

	table := newModifyTable(L)
	L.Push(table)

	fn := LuaLDAPModify(context.Background())
	ret := fn(L)

	assert.Equal(t, 1, ret)
	assert.NotNil(t, enqueuer.request)
	assert.Equal(t, definitions.DefaultBackendName, enqueuer.request.PoolName)
	assert.Equal(t, definitions.LDAPModify, enqueuer.request.Command)
	assert.Equal(t, definitions.LDAPModifyReplace, enqueuer.request.SubCommand)
	assert.Equal(t, "uid=jdoe,dc=example,dc=org", enqueuer.request.ModifyDN)
	assert.Equal(t, []string{"new description"}, enqueuer.request.ModifyAttributes["description"])
	assert.Equal(t, priorityqueue.PriorityLow, enqueuer.priority)
	assert.Equal(t, lua.LString("OK"), L.Get(-1))
}

func TestLuaLDAPSearchEscapesSafeEqualityFilterValue(t *testing.T) {
	L := lua.NewState()
	defer L.Close()

	bindLDAPRuntimeContextForTest(context.Background(), L)

	enqueuer := &testLDAPEnqueuer{t: t, reply: &bktype.LDAPReply{}}

	SetLuaLDAPQueue(enqueuer)
	defer SetLuaLDAPQueue(nil)

	table := newSafeSearchTable(L, false)
	table.RawSetString("filter_value", lua.LString("jdoe)(|(uid=*))"))
	L.Push(table)

	fn := LuaLDAPSearch(context.Background())
	ret := fn(L)

	assert.Equal(t, 1, ret)
	assert.NotNil(t, enqueuer.request)
	assert.Equal(t, "(uid="+ldap.EscapeFilter("jdoe)(|(uid=*))")+")", enqueuer.request.Filter)
	assert.Equal(t, "ou=people,dc=example,dc=org", enqueuer.request.BaseDN)
}

func TestLuaLDAPSearchRejectsUntrustedRawFilter(t *testing.T) {
	L := lua.NewState()
	defer L.Close()

	bindLDAPRuntimeContextForTest(context.Background(), L)

	enqueuer := &testLDAPEnqueuer{t: t, reply: &bktype.LDAPReply{}}

	SetLuaLDAPQueue(enqueuer)
	defer SetLuaLDAPQueue(nil)

	table := newSearchTable(L, false)
	table.RawSetString("filter", lua.LString("(uid=jdoe)(|(uid=*))"))
	L.Push(table)

	fn := LuaLDAPSearch(context.Background())

	assert.Panics(t, func() {
		fn(L)
	})
	assert.Nil(t, enqueuer.request)
}

func TestLuaLDAPModifyRejectsDNOutsideAllowedSubtree(t *testing.T) {
	L := lua.NewState()
	defer L.Close()

	bindLDAPRuntimeContextForTest(context.Background(), L)

	enqueuer := &testLDAPEnqueuer{t: t, reply: &bktype.LDAPReply{}}

	SetLuaLDAPQueue(enqueuer)
	defer SetLuaLDAPQueue(nil)

	table := newModifyTable(L)
	table.RawSetString("dn", lua.LString("uid=jdoe,ou=admins,dc=example,dc=org"))
	table.RawSetString("allowed_base_dn", lua.LString("ou=people,dc=example,dc=org"))
	L.Push(table)

	fn := LuaLDAPModify(context.Background())

	assert.Panics(t, func() {
		fn(L)
	})
	assert.Nil(t, enqueuer.request)
}

func TestLuaLDAPEndpoint_DefaultAndLDAPI(t *testing.T) {
	cfg := &config.FileSettings{
		LDAP: &config.LDAPSection{
			Config: &config.LDAPConf{ServerURIs: []string{"ldaps://ldap.example.org:636"}},
			OptionalLDAPPools: map[string]*config.LDAPConf{
				"mail": {ServerURIs: []string{"ldapi:///var/run/slapd.sock"}},
			},
		},
	}

	t.Run("default", func(t *testing.T) {
		L := lua.NewState()
		defer L.Close()

		fn := LuaLDAPEndpoint(cfg)
		ret := fn(L)

		assert.Equal(t, 3, ret)
		assert.Equal(t, "ldap.example.org", L.Get(-3).String())
		assert.Equal(t, lua.LNumber(636), L.Get(-2))
		assert.Equal(t, lua.LNil, L.Get(-1))
	})

	t.Run("ldapi", func(t *testing.T) {
		L := lua.NewState()
		defer L.Close()

		fn := LuaLDAPEndpoint(cfg)

		L.Push(lua.LString("mail"))
		ret := fn(L)

		assert.Equal(t, 3, ret)
		assert.Equal(t, "/var/run/slapd.sock", L.Get(-3).String())
		assert.Equal(t, lua.LNumber(0), L.Get(-2))
		assert.Equal(t, lua.LNil, L.Get(-1))
	})
}
