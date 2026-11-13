package agent

// DefaultsForTest exposes Bundle.defaults to the external test package.
func DefaultsForTest(b *Bundle, console string) { b.defaults(console) }
