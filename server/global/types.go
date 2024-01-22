package global

// Backend is a numeric identifier for a database backend.
type Backend uint8

// AuthResult is the numeric result of a password check done by HandlePassword()
type AuthResult uint8

// LDAPCommand represents the LDAP operation like search, add or modify.
type LDAPCommand uint8

// LDAPState is the tri-state flag for the LDAPPool
type LDAPState uint8

// Algorithm is a password algorithm type.
type Algorithm uint8

// PasswordOption is a password encoding type.
type PasswordOption uint8

func (b Backend) String() string {
	switch b {
	case BackendCache:
		return BackendCacheName
	case BackendLDAP:
		return BackendLDAPName
	case BackendMySQL:
		return BackendMySQLName
	case BackendPostgres:
		return BackendPostgresName
	case BackendSQL:
		return BackendSQLName
	case BackendLua:
		return BackendLuaName
	default:
		return BackendUnknownName
	}
}

type DbgModule uint8

type LuaAction uint8

type LuaCommand uint8

type CacheNameBackend uint8
