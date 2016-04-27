# supersphincs.js

## Overview

A wrapper around [sphincs.js](https://github.com/cyph/sphincs.js) that pairs
[SPHINCS](https://sphincs.cr.yp.to) with the more conventional (non-post-quantum)
[RSASSA-PKCS1-v1_5](https://tools.ietf.org/html/rfc3447#section-8.2) signing scheme.

To work around extremely poor performance of BLAKE-512 in the emitted SPHINCS asm.js code,
hashing is first performed in JavaScript using a remarkably efficient [pure JS implementation
of SHA-512](https://github.com/emn178/js-sha512) which outperforms native SubtleCrypto
SHA-512 in both Chrome and Firefox.

RSA signing is performed by the current platform's native implementation (SubtleCrypto API
in the browser, or Crypto API in Node.js). In clients without a native implementation,
generating keys and signing messages will fail. However, verifying signatures will continue
to work; in such cases, the client will simply ignore the RSA signature and verify only the
SPHINCS signature.

Whenever an exception occurs within a SuperSPHINCS function, the first argument sent to
the callback will be null, and the second will be a string containing an error message.

## Example Usage

	const message	= "hello";

	superSphincs.keyPair(keyPair => {
		superSphincs.sign(message, keyPair.privateKey, signed =>
			superSphincs.open(signed, keyPair.publicKey, verified =>
				console.log(verified) // same as message
			)
		);

		superSphincs.signDetached(message, keyPair.privateKey, signature =>
			superSphincs.verifyDetached(signature, message, keyPair.publicKey, isValid =>
				console.log(isValid) // true
			)
		);
	});
