# supersphincs

## Overview

A wrapper around [sphincs.js](https://github.com/cyph/sphincs.js) that pairs
[SPHINCS](https://sphincs.cr.yp.to) with the more conventional (non-post-quantum)
[RSASSA-PKCS1-v1_5](https://tools.ietf.org/html/rfc3447#section-8.2) signing scheme.

To work around extremely poor performance of BLAKE-512 in the emitted SPHINCS asm.js code,
hashing is first performed in JavaScript using a remarkably efficient [pure JS implementation
of SHA-512](https://github.com/emn178/js-sha512) which seems to consistently outperform
native SubtleCrypto SHA-512 across devices in both Chrome and Firefox.

RSA signing is performed by the current platform's native implementation (SubtleCrypto API
in the browser, or Crypto API in Node.js). In clients without a native implementation,
generating keys and signing messages will fail. However, verifying signatures will continue
to work; in such cases, the client will simply ignore the RSA signature and verify only the
SPHINCS signature.

## Example Usage

	(async () => {
		const keyPair /*: {privateKey: Uint8Array; publicKey: Uint8Array} */ =
			await superSphincs.keyPair()
		;

		const message /*: string */ = 'hello';

		/* Combined signatures */

		const signed /*: string */ =
			await superSphincs.sign(message, keyPair.privateKey)
		;

		const verified /*: string */ =
			await superSphincs.open(signed, keyPair.publicKey) // same as message
		;

		/* Detached signatures */
		
		const signature /*: Uint8Array */ =
			await superSphincs.signDetached(message, keyPair.privateKey)
		;

		const isValid /*: boolean */ =
			await superSphincs.verifyDetached(signature, message, keyPair.publicKey) // true
		;

		/* Export and optionally encrypt keys */

		const keyData /*: {
			private: {
				rsa: string;
				sphincs: string;
				superSphincs: string;
			};
			public: {
				rsa: string;
				sphincs: string;
				superSphincs: string;
			};
		} */ =
			await superSphincs.exportKeys(keyPair, 'secret passphrase')
		;

		// May now save exported keys to disk (or whatever)
		localStorage.superSphincsPrivateKey	= keyData.private.superSphincs;
		localStorage.sphincsPrivateKey		= keyData.private.sphincs;
		localStorage.rsaPrivateKey			= keyData.private.rsa;
		localStorage.superSphincsPublicKey	= keyData.public.superSphincs;
		localStorage.sphincsPublicKey		= keyData.public.sphincs;
		localStorage.rsaPublicKey			= keyData.public.rsa;


		/* Reconstruct an exported key using either the superSphincs
			value or any pair of valid sphincs and rsa values */

		const keyPair1 = await superSphincs.importKeys({
			public: {
				rsa: localStorage.rsaPublicKey,
				sphincs: localStorage.sphincsPublicKey
			}
		});

		// May now use keyPair1.publicKey as in the above examples
		console.log('Import #1:');
		console.log(keyPair1);

		const keyPair2 = await superSphincs.importKeys(
			{
				private: {
					superSphincs: localStorage.superSphincsPrivateKey
				}
			},
			'secret passphrase'
		);

		// May now use keyPair2 as in the above examples
		console.log('Import #2:');
		console.log(keyPair2);

		// Constructing an entirely new SuperSPHINCS key pair from
		// the original SPHINCS key pair and a new RSA key pair
		const keyPair3 = await superSphincs.importKeys(
			{
				private: {
					rsa: (
						await superSphincs.exportKeys(
							await superSphincs.keyPair(),
							'hunter2'
						)
					).private.rsa,
					sphincs: localStorage.sphincsPrivateKey
				}
			},
			{
				rsa: 'hunter2',
				sphincs: 'secret passphrase'
			}
		);

		// May now use keyPair3 as in the above examples
		console.log('Import #3:');
		console.log(keyPair3);
	})();
