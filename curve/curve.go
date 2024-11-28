package curve

import "crypto/ecdh"

// P256 returns a [Curve] which implements NIST P-256 (FIPS 186-3, section D.2.3),
// also known as secp256r1 or prime256v1.
// Multiple invocations of this function will return the same value, which can
// be used for equality checks and switch statements.
func P256() ecdh.Curve { return ecdh.P256() }

// P521 returns a [Curve] which implements NIST P-521 (FIPS 186-3, section D.2.5),
// also known as secp521r1.
// Multiple invocations of this function will return the same value, which can
// be used for equality checks and switch statements.
func P521() ecdh.Curve { return ecdh.P521() }

// P384 returns a [Curve] which implements NIST P-384 (FIPS 186-3, section D.2.4),
// also known as secp384r1.
// Multiple invocations of this function will return the same value, which can
// be used for equality checks and switch statements.
func P384() ecdh.Curve { return ecdh.P384() }
