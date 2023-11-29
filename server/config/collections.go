package config

var void struct{}

// StringSet is a storage container that ensures unique keys.
type StringSet map[string]any

// GetStringSlice returns all values for a StringSet as a slice of strings.
func (s *StringSet) GetStringSlice() (result []string) {
	for key := range *s {
		result = append(result, key)
	}

	return
}

// Set adds an element to the StringSet
func (s *StringSet) Set(value string) {
	(*s)[value] = void
}

// NewStringSet constructs a new StringSet
func NewStringSet() StringSet {
	return make(StringSet, 1)
}
