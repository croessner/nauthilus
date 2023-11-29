package backend

// DatabaseResult is a store for any database retrieved results. The keys are either SQL field names or LDAP attributes,
// while the values are the results.
type DatabaseResult map[string][]any

// Done is the value for channels to finish workers
type Done struct{}
