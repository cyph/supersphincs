var isNode	=
	typeof process === 'object' &&
	typeof require === 'function' &&
	typeof window !== 'object' &&
	typeof importScripts !== 'function'
;


var sha512		= require('js-sha512');
var rsaSign		= require('rsasign');
var sodiumUtil	= require('sodiumutil');
var sphincs		= require('sphincs');


var nodeCrypto;
if (isNode) {
	nodeCrypto	= eval('require')('crypto');
}


function deriveEncryptionKey (password, salt) {
	if (isNode) {
		return new Promise(function (resolve, reject) {
			nodeCrypto.pbkdf2(
				new Buffer(password),
				new Buffer(salt),
				aes.keyDerivation.iterations,
				aes.keyBytes,
				aes.keyDerivation.hashFunction,
				function (err, key) {
					if (err) {
						reject(err);
					}
					else {
						resolve(key);
					}
				}
			);
		});
	}
	else {
		return Promise.resolve().then(function () {	
			return crypto.subtle.importKey(
				'raw',
				sodiumUtil.from_string(password),
				{
					name: aes.keyDerivation.algorithm,
				},
				false,
				['deriveKey']
			);
		}).then(function (keyOrigin) {
			return crypto.subtle.deriveKey(
				{
					name: aes.keyDerivation.algorithm,
					salt: salt,
					iterations: aes.keyDerivation.iterations,
					hash: {
						name: aes.keyDerivation.hashFunction
					},
				},
				keyOrigin,
				{
					name: aes.algorithm,
					length: aes.keyBits
				},
				false,
				['encrypt', 'decrypt']
			);
		});
	}
}

function encrypt (plaintext, password) {
	var setup	= Promise.resolve().then(function () {
		var iv		= isNode ?
			nodeCrypto.randomBytes(aes.ivBytes) :
			crypto.getRandomValues(new Uint8Array(aes.ivBytes))
		;

		var salt	= isNode ?
			nodeCrypto.randomBytes(aes.keyDerivation.saltBytes) :
			crypto.getRandomValues(new Uint8Array(aes.keyDerivation.saltBytes))
		;

		return Promise.all([iv, salt, deriveEncryptionKey(password, salt)]);
	}).then(function (results) {
		return {
			iv: results[0],
			salt: results[1],
			key: results[2]
		};
	});

	if (isNode) {
		return setup.then(function (o) {
			var cipher	= nodeCrypto.createCipheriv(aes.algorithm, o.key, o.iv);
			var buf1	= cipher.update(new Buffer(plaintext));
			var buf2	= cipher.final();
			var buf3	= cipher.getAuthTag();

			var cyphertext	= new Uint8Array(Buffer.concat([o.iv, o.salt, buf1, buf2, buf3]));

			sodiumUtil.memzero(o.iv);
			sodiumUtil.memzero(o.salt);
			sodiumUtil.memzero(o.key);
			sodiumUtil.memzero(buf1);
			sodiumUtil.memzero(buf2);
			sodiumUtil.memzero(buf3);

			return cyphertext;
		});
	}
	else {
		return setup.then(function (o) {
			return Promise.all([o, crypto.subtle.encrypt(
				{
					name: aes.algorithm,
					iv: o.iv,
					tagLength: aes.tagBits
				},
				o.key,
				plaintext
			)]);
		}).then(function (results) {
			var o			= results[0];
			var encrypted	= new Uint8Array(results[1]);

			var cyphertext	= new Uint8Array(
				aes.ivBytes + aes.keyDerivation.saltBytes + encrypted.length
			);

			cyphertext.set(o.iv);
			cyphertext.set(o.salt, aes.ivBytes);
			cyphertext.set(encrypted, aes.ivBytes + aes.keyDerivation.saltBytes);

			sodiumUtil.memzero(o.iv);
			sodiumUtil.memzero(o.salt);
			sodiumUtil.memzero(o.key);
			sodiumUtil.memzero(encrypted);

			return cyphertext;
		});
	}
}

function decrypt (cyphertext, password) {
	return Promise.resolve().then(function () {
		var iv		= new Uint8Array(cyphertext.buffer, cyphertext.byteOffset, aes.ivBytes);

		var salt	= new Uint8Array(
			cyphertext.buffer,
			cyphertext.byteOffset + aes.ivBytes,
			aes.keyDerivation.saltBytes
		);

		return Promise.all([iv, deriveEncryptionKey(password, salt)]);
	}).then(function (results) {
		var iv	= results[0];
		var key	= results[1];

		var decrypted;

		if (isNode) {
			var encrypted	= new Uint8Array(
				cyphertext.buffer,
				cyphertext.byteOffset + aes.ivBytes + aes.keyDerivation.saltBytes,
				cyphertext.length -
					aes.ivBytes -
					aes.keyDerivation.saltBytes -
					aes.tagBytes
			);

			var authTag		= new Uint8Array(
				cyphertext.buffer,
				cyphertext.byteOffset + cyphertext.length - aes.tagBytes
			);

			var decipher	= nodeCrypto.createDecipheriv(
				aes.algorithm,
				new Buffer(key),
				new Buffer(iv)
			);

			decipher.setAuthTag(new Buffer(authTag));

			var buf1	= decipher.update(new Buffer(encrypted));
			var buf2	= decipher.final();

			decrypted	= Buffer.concat([buf1, buf2]);;

			sodiumUtil.memzero(buf1);
			sodiumUtil.memzero(buf2);
		}
		else {
			var encrypted	= new Uint8Array(
				cyphertext.buffer,
				cyphertext.byteOffset + aes.ivBytes + aes.keyDerivation.saltBytes
			);

			decrypted	= crypto.subtle.decrypt(
				{
					name: aes.algorithm,
					iv: iv,
					tagLength: aes.tagBits
				},
				key,
				encrypted
			);
		}

		return Promise.all([key, decrypted]);
	}).then(function (results) {
		var key			= results[0];
		var decrypted	= results[1];

		sodiumUtil.memzero(key);

		return new Uint8Array(decrypted);
	});
}


var aes	= {
	algorithm: isNode ? 'aes-256-gcm' : 'AES-GCM',
	ivBytes: 12,
	keyBytes: 32,
	keyBits: 256,
	tagBytes: 16,
	tagBits: 128,

	keyDerivation: {
		algorithm: 'PBKDF2',
		hashFunction: isNode ? 'sha512' : 'SHA-512',
		iterations: 1000000,
		saltBytes: 32
	}
};


var superSphincs	= {
	publicKeyBytes: rsaSign.publicKeyBytes + sphincs.publicKeyBytes,
	privateKeyBytes: rsaSign.privateKeyBytes + sphincs.privateKeyBytes,
	bytes: rsaSign.bytes + sphincs.bytes,
	hashBytes: 64,

	hash: function (message, onlyBinary) {
		var messageBinary;
		var shouldClearMessageBinary	= typeof message === 'string';

		return Promise.resolve().then(function () {
			messageBinary	= sodiumUtil.from_string(message);

			if (isNode) {
				var hasher	= nodeCrypto.createHash('sha512');
				hasher.update(new Buffer(messageBinary));

				return hasher.digest();
			}
			else {
				return crypto.subtle.digest(
					{
						name: 'SHA-512'
					},
					messageBinary
				);
			}
		}).then(function (hash) {
			if (shouldClearMessageBinary) {
				sodiumUtil.memzero(messageBinary);
			}

			var binary	= new Uint8Array(hash);

			if (onlyBinary) {
				return binary;
			}

			return {binary: binary, hex: sodiumUtil.to_hex(binary)};
		}).catch(function () {
			if (shouldClearMessageBinary) {
				sodiumUtil.memzero(messageBinary);
			}

			var hex		= sha512(sodiumUtil.to_string(message));
			var binary	= sodiumUtil.from_hex(hex);

			if (onlyBinary) {
				return binary;
			}

			return {binary: binary, hex: hex};
		});
	},

	keyPair: function () {
		return rsaSign.keyPair().then(function (rsaKeyPair) {
			var sphincsKeyPair	= sphincs.keyPair();

			var keyPair	= {
				keyType: 'supersphincs',
				publicKey: new Uint8Array(superSphincs.publicKeyBytes),
				privateKey: new Uint8Array(superSphincs.privateKeyBytes)
			};

			keyPair.publicKey.set(rsaKeyPair.publicKey);
			keyPair.privateKey.set(rsaKeyPair.privateKey);
			keyPair.publicKey.set(sphincsKeyPair.publicKey, rsaSign.publicKeyBytes);
			keyPair.privateKey.set(sphincsKeyPair.privateKey, rsaSign.privateKeyBytes);

			sodiumUtil.memzero(sphincsKeyPair.privateKey);
			sodiumUtil.memzero(rsaKeyPair.privateKey);
			sodiumUtil.memzero(sphincsKeyPair.publicKey);
			sodiumUtil.memzero(rsaKeyPair.publicKey);

			return keyPair;
		});
	},

	sign: function (message, privateKey) {
		var shouldClearMessage	= typeof message === 'string';

		return superSphincs.signDetached(message, privateKey).then(function (signature) {
			message		= sodiumUtil.from_string(message);

			var signed	= new Uint8Array(
				superSphincs.bytes + message.length
			);

			signed.set(signature);
			signed.set(message, superSphincs.bytes);

			if (shouldClearMessage) {
				sodiumUtil.memzero(message);
			}

			sodiumUtil.memzero(signature);

			return signed;
		}).catch(function (err) {
			if (shouldClearMessage) {
				sodiumUtil.memzero(message);
			}

			throw err;
		});
	},

	signBase64: function (message, privateKey) {
		return superSphincs.sign(message, privateKey).then(function (signed) {
			var s	= sodiumUtil.to_base64(signed);
			sodiumUtil.memzero(signed);
			return s;
		});
	},

	signDetached: function (message, privateKey) {
		return superSphincs.hash(message).then(function (hash) {
			return Promise.all([hash, rsaSign.signDetached(
				hash.binary,
				new Uint8Array(privateKey.buffer, privateKey.byteOffset, rsaSign.privateKeyBytes)
			)]);
		}).then(function (results) {
			var hash			= results[0];
			var rsaSignature	= results[1];

			var sphincsSignature	= sphincs.signDetached(
				hash.binary,
				new Uint8Array(privateKey.buffer, privateKey.byteOffset + rsaSign.privateKeyBytes)
			);

			var signature	= new Uint8Array(superSphincs.bytes);

			signature.set(rsaSignature);
			signature.set(sphincsSignature, rsaSign.bytes);

			sodiumUtil.memzero(hash.binary);
			sodiumUtil.memzero(sphincsSignature);
			sodiumUtil.memzero(rsaSignature);

			return signature;
		});
	},

	signDetachedBase64: function (message, privateKey) {
		return superSphincs.signDetached(message, privateKey).then(function (signature) {
			var s	= sodiumUtil.to_base64(signature);
			sodiumUtil.memzero(signature);
			return s;
		});
	},

	open: function (signed, publicKey) {
		var shouldClearSigned	= typeof signed === 'string';

		return Promise.resolve().then(function () {
			signed	= sodiumUtil.from_base64(signed);

			var signature	= new Uint8Array(
				signed.buffer,
				signed.byteOffset,
				superSphincs.bytes
			);

			var message		= new Uint8Array(
				signed.buffer,
				signed.byteOffset + superSphincs.bytes
			);

			return Promise.all([message, superSphincs.verifyDetached(
				signature,
				message,
				publicKey
			)]);
		}).then(function (results) {
			var message	= results[0];
			var isValid	= results[1];

			if (shouldClearSigned) {
				sodiumUtil.memzero(signed);
			}

			if (isValid) {
				return message;
			}
			else {
				throw new Error('Failed to open SuperSPHINCS signed message.');
			}
		}).catch(function (err) {
			if (shouldClearSigned) {
				sodiumUtil.memzero(signed);
			}

			throw err;
		});
	},

	openString: function (signed, publicKey) {
		return superSphincs.open(signed, publicKey).then(function (message) {
			var s	= sodiumUtil.to_string(message);
			sodiumUtil.memzero(message);
			return s;
		});
	},

	verifyDetached: function (signature, message, publicKey) {
		var shouldClearSignature	= typeof signature === 'string';

		return superSphincs.hash(message).then(function (hash) {
			signature	= sodiumUtil.from_base64(signature);

			return Promise.all([
				hash,
				rsaSign.verifyDetached(
					new Uint8Array(signature.buffer, signature.byteOffset, rsaSign.bytes),
					hash.binary,
					new Uint8Array(publicKey.buffer, publicKey.byteOffset, rsaSign.publicKeyBytes)
				)
			]);
		}).then(function (results) {
			var hash		= results[0];
			var rsaIsValid	= results[1];

			var sphincsIsValid	= sphincs.verifyDetached(
				new Uint8Array(
					signature.buffer,
					signature.byteOffset + rsaSign.bytes,
					sphincs.bytes
				),
				hash.binary,
				new Uint8Array(publicKey.buffer, publicKey.byteOffset + rsaSign.publicKeyBytes)
			);

			if (shouldClearSignature) {
				sodiumUtil.memzero(signature);
			}

			sodiumUtil.memzero(hash.binary);

			return rsaIsValid && sphincsIsValid;
		}).catch(function (err) {
			if (shouldClearSignature) {
				sodiumUtil.memzero(signature);
			}

			throw err;
		});;
	},

	exportKeys: function (keyPair, password) {
		return Promise.resolve().then(function () {
			if (!keyPair.privateKey) {
				return null;
			}

			var rsaPrivateKey			= new Uint8Array(
				rsaSign.publicKeyBytes +
				rsaSign.privateKeyBytes
			);

			var sphincsPrivateKey		= new Uint8Array(
				sphincs.publicKeyBytes +
				sphincs.privateKeyBytes
			);

			var superSphincsPrivateKey	= new Uint8Array(
				superSphincs.publicKeyBytes +
				superSphincs.privateKeyBytes
			);

			rsaPrivateKey.set(new Uint8Array(
				keyPair.publicKey.buffer,
				keyPair.publicKey.byteOffset,
				rsaSign.publicKeyBytes
			));
			rsaPrivateKey.set(
				new Uint8Array(
					keyPair.privateKey.buffer,
					keyPair.privateKey.byteOffset,
					rsaSign.privateKeyBytes
				),
				rsaSign.publicKeyBytes
			);

			sphincsPrivateKey.set(new Uint8Array(
				keyPair.publicKey.buffer,
				keyPair.publicKey.byteOffset + rsaSign.publicKeyBytes
			));
			sphincsPrivateKey.set(
				new Uint8Array(
					keyPair.privateKey.buffer,
					keyPair.privateKey.byteOffset + rsaSign.privateKeyBytes
				),
				sphincs.publicKeyBytes
			);

			superSphincsPrivateKey.set(keyPair.publicKey);
			superSphincsPrivateKey.set(keyPair.privateKey, superSphincs.publicKeyBytes);

			if (password) {
				return Promise.all([
					encrypt(rsaPrivateKey, password),
					encrypt(sphincsPrivateKey, password),
					encrypt(superSphincsPrivateKey, password)
				]).then(function (results) {
					sodiumUtil.memzero(superSphincsPrivateKey);
					sodiumUtil.memzero(sphincsPrivateKey);
					sodiumUtil.memzero(rsaPrivateKey);

					return results;
				});
			}
			else {
				return [
					rsaPrivateKey,
					sphincsPrivateKey,
					superSphincsPrivateKey
				];
			}
		}).then(function (results) {
			if (!results) {
				return {
					rsa: null,
					sphincs: null,
					superSphincs: null
				};
			}

			var rsaPrivateKey			= results[0];
			var sphincsPrivateKey		= results[1];
			var superSphincsPrivateKey	= results[2];

			var privateKeyData	= {
				rsa: sodiumUtil.to_base64(rsaPrivateKey),
				sphincs: sodiumUtil.to_base64(sphincsPrivateKey),
				superSphincs: sodiumUtil.to_base64(superSphincsPrivateKey)
			};

			sodiumUtil.memzero(superSphincsPrivateKey);
			sodiumUtil.memzero(sphincsPrivateKey);
			sodiumUtil.memzero(rsaPrivateKey);

			return privateKeyData;
		}).then(function (privateKeyData) {
			return {
				private: privateKeyData,
				public: {
					rsa: sodiumUtil.to_base64(new Uint8Array(
						keyPair.publicKey.buffer,
						keyPair.publicKey.byteOffset,
						rsaSign.publicKeyBytes
					)),
					sphincs: sodiumUtil.to_base64(new Uint8Array(
						keyPair.publicKey.buffer,
						keyPair.publicKey.byteOffset + rsaSign.publicKeyBytes
					)),
					superSphincs: sodiumUtil.to_base64(keyPair.publicKey)
				}
			};
		});
	},

	importKeys: function (keyData, password) {
		return Promise.resolve().then(function () {
			if (!keyData.private) {
				return null;
			}

			if (keyData.private.superSphincs) {
				var superSphincsPrivateKey	= sodiumUtil.from_base64(keyData.private.superSphincs);

				if (password) {
					return Promise.all([decrypt(superSphincsPrivateKey, password)]);
				}
				else {
					return [superSphincsPrivateKey];
				}
			}
			else {
				var rsaPrivateKey		= sodiumUtil.from_base64(keyData.private.rsa);
				var sphincsPrivateKey	= sodiumUtil.from_base64(keyData.private.sphincs);

				if (password) {
					return Promise.all([
						decrypt(
							rsaPrivateKey,
							typeof password === 'string' ? password : password.rsa
						),
						decrypt(
							sphincsPrivateKey,
							typeof password === 'string' ? password : password.sphincs
						)
					]);
				}
				else {
					return [rsaPrivateKey, sphincsPrivateKey];
				}
			}
		}).then(function (results) {
			var keyPair	= {
				publicKey: new Uint8Array(superSphincs.publicKeyBytes),
				privateKey: null
			};

			if (!results) {
				return keyPair;
			}

			keyPair.privateKey	= new Uint8Array(superSphincs.privateKeyBytes);

			if (results.length === 1) {
				var superSphincsPrivateKey	= results[0];

				keyPair.publicKey.set(new Uint8Array(
					superSphincsPrivateKey.buffer,
					superSphincsPrivateKey.byteOffset,
					superSphincs.publicKeyBytes
				));

				keyPair.privateKey.set(new Uint8Array(
					superSphincsPrivateKey.buffer,
					superSphincsPrivateKey.byteOffset + superSphincs.publicKeyBytes
				));
			}
			else {
				var rsaPrivateKey		= results[0];
				var sphincsPrivateKey	= results[1];

				keyPair.publicKey.set(
					new Uint8Array(
						rsaPrivateKey.buffer,
						rsaPrivateKey.byteOffset,
						rsaSign.publicKeyBytes
					)
				);
				keyPair.publicKey.set(
					new Uint8Array(
						sphincsPrivateKey.buffer,
						sphincsPrivateKey.byteOffset,
						sphincs.publicKeyBytes
					),
					rsaSign.publicKeyBytes
				);

				keyPair.privateKey.set(
					new Uint8Array(
						rsaPrivateKey.buffer,
						rsaPrivateKey.byteOffset + rsaSign.publicKeyBytes
					)
				);
				keyPair.privateKey.set(
					new Uint8Array(
						sphincsPrivateKey.buffer,
						sphincsPrivateKey.byteOffset + sphincs.publicKeyBytes
					),
					rsaSign.privateKeyBytes
				);
			}

			return keyPair;
		}).then(function (keyPair) {
			if (!keyPair.privateKey) {
				if (keyData.public.superSphincs) {
					keyPair.publicKey.set(sodiumUtil.from_base64(keyData.public.superSphincs));
				}
				else if (keyData.public.rsa && keyData.public.sphincs) {
					keyPair.publicKey.set(sodiumUtil.from_base64(keyData.public.rsa));
					keyPair.publicKey.set(
						sodiumUtil.from_base64(keyData.public.sphincs),
						rsaSign.publicKeyBytes
					);
				}
			}

			return keyPair;
		});
	}
};



superSphincs.superSphincs	= superSphincs;
module.exports				= superSphincs;
