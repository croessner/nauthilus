package testsupport

// MergeExample implements the documented test-fixture merge by map key and exact module/fact/field identity.
func MergeExample(base, addition any) any {
	if incoming, ok := addition.(map[string]any); ok {
		target, compatible := base.(map[string]any)
		if !compatible {
			target = make(map[string]any)
		}

		for key, value := range incoming {
			target[key] = MergeExample(target[key], value)
		}

		return target
	}

	incoming, list := addition.([]any)

	target, compatible := base.([]any)
	if !list || !compatible {
		return addition
	}

	for _, item := range incoming {
		identity := exampleIdentity(item)
		if identity == "" {
			return addition
		}

		found := false

		for index, old := range target {
			if exampleIdentity(old) == identity {
				target[index] = MergeExample(old, item)
				found = true

				break
			}
		}

		if !found {
			target = append(target, item)
		}
	}

	return target
}

// exampleIdentity recognizes only documented keyed collections and leaves scalar arrays as replacements.
func exampleIdentity(value any) string {
	record, ok := value.(map[string]any)
	if !ok {
		return ""
	}

	for _, field := range []string{"name", "attribute"} {
		if text, ok := record[field].(string); ok {
			return field + ":" + text
		}
	}

	return ""
}
