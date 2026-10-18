// Package servicename holds the one rule for a tunnel service name, shared by
// the client and the server so the two can never accept different names.
package servicename

// Valid reports whether name is a dotted sequence of identifiers, the shape of
// a protobuf full service name such as pkg.v1.Service. Each identifier starts
// with an ASCII letter or underscore and continues with ASCII letters, digits
// or underscores. An empty name, an empty segment, a slash or any other
// character is refused.
func Valid(name string) bool {
	start := true
	for i := 0; i < len(name); i++ {
		b := name[i]
		switch {
		case b == '.':
			if start {
				return false
			}
			start = true
		case b == '_' || (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z'):
			start = false
		case b >= '0' && b <= '9':
			if start {
				return false
			}
		default:
			return false
		}
	}
	return !start
}
