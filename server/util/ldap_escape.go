package util

// EscapeLDAPFilter escapes a string for safe embedding into an LDAP filter per RFC 4515.
// It replaces the following characters:
//
//	\  -> \\5c
//	*  -> \\2a
//	(  -> \\28
//	)  -> \\29
//	NUL-> \\00
func EscapeLDAPFilter(s string) string {
	if s == "" {
		return s
	}

	// Order matters: backslash first to avoid double-escaping
	replaced := ""
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\\':
			replaced += "\\5c"
		case '*':
			replaced += "\\2a"
		case '(':
			replaced += "\\28"
		case ')':
			replaced += "\\29"
		case '\x00':
			replaced += "\\00"
		default:
			replaced += string(s[i])
		}
	}

	return replaced
}
