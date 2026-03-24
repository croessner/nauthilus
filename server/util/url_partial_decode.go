package util

// URLPartialDecode decodes valid percent-escaped byte sequences in a string and
// leaves invalid escape sequences untouched.
//
// Behavior:
// - Decodes only "%XX" where X are hexadecimal digits.
// - Does not treat '+' as space.
// - Leaves malformed escapes unchanged (e.g. "%2G", trailing "%").
func URLPartialDecode(value string) string {
	if value == "" {
		return ""
	}

	needsDecode := false
	for i := 0; i < len(value); i++ {
		if value[i] == '%' {
			needsDecode = true
			break
		}
	}

	if !needsDecode {
		return value
	}

	buf := make([]byte, 0, len(value))

	for i := 0; i < len(value); i++ {
		if value[i] == '%' && i+2 < len(value) {
			hi, okHi := fromHex(value[i+1])
			lo, okLo := fromHex(value[i+2])

			if okHi && okLo {
				buf = append(buf, hi<<4|lo)
				i += 2

				continue
			}
		}

		buf = append(buf, value[i])
	}

	return string(buf)
}

func fromHex(ch byte) (byte, bool) {
	switch {
	case ch >= '0' && ch <= '9':
		return ch - '0', true
	case ch >= 'a' && ch <= 'f':
		return ch - 'a' + 10, true
	case ch >= 'A' && ch <= 'F':
		return ch - 'A' + 10, true
	default:
		return 0, false
	}
}
