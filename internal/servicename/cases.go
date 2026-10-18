package servicename

// InvalidExamples returns names both the client and the server must refuse.
// Tests in either package read it, so the two refusal sets are pinned to one
// list. It returns a fresh slice on every call.
func InvalidExamples() []string {
	return []string{
		"", ".", "a.", ".a", "a..b", "1a.b", "a.1b", "a/b", "/a.b", "a.b/Open",
		"a b", "a-b", "a.b ", "pkg.v1.Service\n", "été.v1.S",
	}
}
