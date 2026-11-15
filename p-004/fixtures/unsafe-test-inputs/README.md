Inert hostile test cases are constructed in tests: recursive YAML aliases, unsafe
tags, malicious labels, credential strings, ambiguous URLs and path traversal.
They are never interpreted as shell commands, executed source, browser content
or authorization. Keeping them in Python test strings prevents accidental use as
an operator configuration.
