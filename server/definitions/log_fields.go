package definitions

// IsRequiredNoticeLogKey identifies fields that must survive NOTICE filtering.
func IsRequiredNoticeLogKey(key string) bool {
	switch key {
	case "time", "level", LogKeyInstance, LogKeyGUID, LogKeyMsg:
		return true
	default:
		return false
	}
}
