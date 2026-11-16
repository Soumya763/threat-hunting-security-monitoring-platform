"""
File and URL analysis building blocks (offline, dependency-light).

- hashing:   streaming MD5/SHA-1/SHA-256 with a size cap
- filetype:  magic-byte identification and extension policy
- static:    bounded PDF byte scan and ZIP/OOXML metadata inspection
- scoring:   explainable, factor-based risk score
- ssrf:      URL syntax checks and public-address enforcement

None of these modules performs network I/O except ssrf.resolve_public_addresses
(DNS only, and only when called). Nothing executes or writes uploaded files.
"""
