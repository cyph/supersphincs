# supersphincs

## Overview

SuperSPHINCS combines the post-quantum [SPHINCS](https://sphincs.cr.yp.to) with the more conventional [RSASSA-PKCS1-v1_5](https://tools.ietf.org/html/rfc3447#section-8.2) as a single signing scheme.
SPHINCS is provided by [sphincs.js](https://github.com/cyph/sphincs.js) and RSA signing is performed
using [rsasign.js](https://github.com/cyph/rsasign.js).

Before signing, a SHA-512 hash is performed, using the current platform's native implementation
where available or [an efficient JavaScript implementation](https://github.com/emn178/js-sha512)
otherwise.

## Example Usage

	(async () => {
		const keyPair /*: {privateKey: Uint8Array; publicKey: Uint8Array} */ =
			await superSphincs.keyPair()
		;

		const message /*: Uint8Array */ =
			new Uint8Array([104, 101, 108, 108, 111, 0]) // "hello"
		;

		/* Combined signatures */

		const signed /*: Uint8Array */ =
			await superSphincs.sign(message, keyPair.privateKey)
		;

		const verified /*: Uint8Array */ =
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

		if (typeof localStorage === 'undefined') {
			localStorage	= {};
		}

		// May now save exported keys to disk (or whatever)
		localStorage.superSphincsPrivateKey = keyData.private.superSphincs;
		localStorage.sphincsPrivateKey      = keyData.private.sphincs;
		localStorage.rsaPrivateKey          = keyData.private.rsa;
		localStorage.superSphincsPublicKey  = keyData.public.superSphincs;
		localStorage.sphincsPublicKey       = keyData.public.sphincs;
		localStorage.rsaPublicKey           = keyData.public.rsa;


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
