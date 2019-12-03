package main

// BoolToPythonString - convert bool to Python string ("True", "False"); required for backward compatibility with python-pkidb
func BoolToPythonString(b bool) string {
	if b {
		return "True"
	}
	return "False"
}
