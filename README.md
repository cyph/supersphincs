# supersphincs.js

## Overview

A wrapper around [sphincs.js](https://github.com/cyph/sphincs.js) that pairs
[SPHINCS](https://superSphincs.cr.yp.to) with the more conventional non-post-quantum
[RSASSA-PKCS1-v1_5](https://tools.ietf.org/html/rfc3447#section-8.2) signing scheme
(2048-bit, SHA-256).

The RSA implementation in use is provided by the browser's native SubtleCrypto interface.
In clients without this native implementation, generating keys and signing messages will
fail. However, verifying signatures will continue to work; in such cases, the client will
simply ignore the RSA signature and verify only the SPHINCS one.

In cases where SuperSPHINCS fails, the first argument sent to the callback function will be
null and the second will be a string containing an error message.

## Example Usage

	const message	= new Uint8Array([104, 101, 108, 108, 111, 0]); // "hello"

	superSphincs.keyPair(keyPair => {
		superSphincs.sign(message, keyPair.privateKey, signed =>
			superSphincs.open(signed, keyPair.publicKey, verified =>
				console.log(verified) // same as message
			)
		);

		superSphincs.signDetached(message, keyPair.privateKey, signature =>
			superSphincs.verifyDetached(signature, message, keyPair.publicKey, isValid =>
				console.log(isValid) // same as true
			)
		);
	});
