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

	const message	= 'hello';

	superSphincs.keyPair().then((keyPair /* : {publicKey: Uint8Array; privateKey: Uint8Array;} */) => {

		superSphincs.sign(
			message,
			keyPair.privateKey
		).then((signed /* : string */) => superSphincs.open(
			signed,
			keyPair.publicKey
		)).then((verified /* : string */) =>
			console.log(verified) /* Same as message */
		);

		superSphincs.signDetached(
			message,
			keyPair.privateKey
		).then((signature /* : string */) => superSphincs.verifyDetached(
			signature,
			message,
			keyPair.publicKey
		)).then((isValid /* : boolean */) =>
			console.log(isValid) /* true */
		);


		superSphincs.exportKeys(keyPair, 'secret passphrase').then((keyData /* : {
			public: {
				rsa: string;
				sphincs: string;
				superSphincs: string;
			};
			private: {
				rsa: string;
				sphincs: string;
				superSphincs: string;
			};
		} */) => {
			/* Can save exported keys to disk or whatever */

			if (typeof localStorage === 'undefined') {
				localStorage	= {};
			}

			localStorage.superSphincsPublicKey	= keyData.public.superSphincs;
			localStorage.sphincsPublicKey		= keyData.public.sphincs;
			localStorage.rsaPublicKey			= keyData.public.rsa;

			localStorage.superSphincsPrivateKey	= keyData.private.superSphincs;
			localStorage.sphincsPrivateKey		= keyData.private.sphincs;
			localStorage.rsaPrivateKey			= keyData.private.rsa;


			/* Reconstruct an exported key using either the superSphincs
				value or any pair of valid sphincs and rsa values */

			superSphincs.importKeys({
				public: {
					sphincs: localStorage.sphincsPublicKey,
					rsa: localStorage.rsaPublicKey
				}
			}).then(keyPair => {
				/* May now use keyPair.publicKey as in the above examples */
				console.log('Import #1:');
				console.log(keyPair);
			});

			superSphincs.importKeys(
				{
					private: {
						superSphincs: localStorage.superSphincsPrivateKey
					}
				},
				'secret passphrase'
			).then(keyPair => {
				/* May now use keyPair as in the above examples */
				console.log('Import #2:');
				console.log(keyPair);
			});

			superSphincs.keyPair().then(newKeyPair => superSphincs.exportKeys(
				newKeyPair,
				'hunter2'
			)).then(newKeyData =>
				newKeyData.private.rsa
			).then(newRsaPrivateKey => superSphincs.importKeys(
				{
					private: {
						sphincs: localStorage.sphincsPrivateKey,
						rsa: newRsaPrivateKey
					}
				},
				{
					sphincs: 'secret passphrase',
					rsa: 'hunter2'
				}
			)).then(keyPair => {
				/* May now use keyPair as in the above examples */
				console.log('Import #3:');
				console.log(keyPair);
			});
		});

	});
