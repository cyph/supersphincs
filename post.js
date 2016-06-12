;

var rsaKeygen, pemJwk;
if (isNode) {
	rsaKeygen	= require('rsa-keygen');
	pemJwk		= require('pem-jwk');
}


function importJWK (key, purpose) {
	return Promise.resolve().then(function () {
		var jwk	= JSON.parse(to_string(new Uint8Array(key.buffer, 0, key.indexOf(0))));

		if (isNode) {
			return pemJwk.jwk2pem(jwk);
		}
		else {
			return crypto.subtle.importKey(
				'jwk',
				jwk,
				rsa.algorithm,
				false,
				[purpose]
			);
		}
	});
}
	
function exportJWK (key) {
	return Promise.resolve().then(function () {
		if (isNode) {
			return pemJwk.pem2jwk(key);
		}
		else {
			return crypto.subtle.exportKey(
				'jwk',
				key,
				rsa.algorithm.name
			);
		}
	}).then(function (jwk) {
		return from_string(JSON.stringify(jwk));
	});
}

function decodeBase64 (data) {
	return typeof data === 'string' ?
		from_base64(data) :
		data
	;
}

function encodeBase64 (data) {
	return typeof data === 'string' ?
		data :
		to_base64(data).replace(/\n/g, '')
	;
}

function decodeString (message) {
	return typeof message === 'string' ?
		from_string(message) :
		message
	;
}

function encodeString (message) {
	return typeof message === 'string' ?
		message :
		to_string(message)
	;
}

function deriveEncryptionKey (password, salt) {
	if (isNode) {
		return new Promise(function (resolve, reject) {
			crypto.pbkdf2(
				new Buffer(password),
				new Buffer(salt),
				aes.keyDerivation.iterations,
				aes.keyLength,
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
				decodeString(password),
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
					length: aes.bitLength
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
			crypto.randomBytes(aes.ivLength) :
			crypto.getRandomValues(new Uint8Array(aes.ivLength))
		;

		var salt	= isNode ?
			crypto.randomBytes(aes.keyDerivation.saltLength) :
			crypto.getRandomValues(new Uint8Array(aes.keyDerivation.saltLength))
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
			var cipher	= crypto.createCipheriv(aes.algorithm, o.key, o.iv);
			var buf1	= cipher.update(new Buffer(plaintext));
			var buf2	= cipher.final();
			var buf3	= cipher.getAuthTag();

			return new Uint8Array(Buffer.concat([o.iv, o.salt, buf1, buf2, buf3]));
		});
	}
	else {
		return setup.then(function (o) {
			return Promise.all([o, crypto.subtle.encrypt(
				{
					name: aes.algorithm,
					iv: o.iv,
					tagLength: aes.tagLengthBytes
				},
				o.key,
				plaintext
			)]);
		}).then(function (results) {
			var o			= results[0];
			var encrypted	= new Uint8Array(results[1]);

			var cyphertext	= new Uint8Array(
				aes.ivLength + aes.keyDerivation.saltLength + encrypted.length
			);

			cyphertext.set(o.iv);
			cyphertext.set(o.salt, aes.ivLength);
			cyphertext.set(encrypted, aes.ivLength + aes.keyDerivation.saltLength);

			return cyphertext;
		});
	}
}

function decrypt (cyphertext, password) {
	return Promise.resolve().then(function () {
		var iv		= new Uint8Array(cyphertext.buffer, 0, aes.ivLength);

		var salt	= new Uint8Array(
			cyphertext.buffer,
			aes.ivLength,
			aes.keyDerivation.saltLength
		);

		return Promise.all([iv, deriveEncryptionKey(password, salt)]);
	}).then(function (results) {
		var iv	= results[0];
		var key	= results[1];

		if (isNode) {
			var encrypted	= new Uint8Array(
				cyphertext.buffer,
				aes.ivLength + aes.keyDerivation.saltLength,
				cyphertext.length -
					aes.ivLength -
					aes.keyDerivation.saltLength -
					aes.tagLength
			);

			var authTag		= new Uint8Array(
				cyphertext.buffer,
				cyphertext.length - aes.tagLength
			);

			var decipher	= crypto.createDecipheriv(
				aes.algorithm,
				new Buffer(key),
				new Buffer(iv)
			);

			decipher.setAuthTag(new Buffer(authTag));

			var buf1	= decipher.update(new Buffer(encrypted));
			var buf2	= decipher.final();

			return Buffer.concat([buf1, buf2]);
		}
		else {
			var encrypted	= new Uint8Array(
				cyphertext.buffer,
				aes.ivLength + aes.keyDerivation.saltLength
			);

			return crypto.subtle.decrypt(
				{
					name: aes.algorithm,
					iv: iv,
					tagLength: aes.tagLengthBytes
				},
				key,
				encrypted
			);
		}
	}).then(function (decrypted) {
		return new Uint8Array(decrypted);
	});
}


var aes	= {
	algorithm: isNode ? 'aes-256-gcm' : 'AES-GCM',
	ivLength: 12,
	keyLength: 32,
	bitLength: 256,
	tagLength: 16,
	tagLengthBytes: null,

	keyDerivation: {
		algorithm: 'PBKDF2',
		hashFunction: isNode ? 'sha512' : 'SHA-512',
		iterations: 1000000,
		saltLength: 32
	}
};

aes.tagLengthBytes	= aes.tagLength * 8;


var rsa	= {
	algorithm: isNode ?
		'RSA-SHA256' :
		{
			name: 'RSASSA-PKCS1-v1_5',
			hash: {
				name: 'SHA-256'
			},
			modulusLength: 2048,
			publicExponent: new Uint8Array([0x01, 0x00, 0x01])
		}
	,

	publicKeyLength: 450,
	privateKeyLength: 1700,
	signatureLength: 256,

	keyPair: function () {
		return Promise.resolve().then(function () {
			if (isNode) {
				var keyPair	= rsaKeygen.generate();

				return {
					publicKey: keyPair.public_key,
					privateKey: keyPair.private_key
				};
			}
			else {
				return crypto.subtle.generateKey(
					rsa.algorithm,
					true,
					['sign', 'verify']
				);
			}
		}).then(function (keyPair) {
			return Promise.all([
				exportJWK(keyPair.publicKey),
				exportJWK(keyPair.privateKey)
			]);
		}).then(function (results) {
			return {
				publicKey: results[0],
				privateKey: results[1]
			};
		});
	},

	signDetached: function (message, privateKey) {
		return importJWK(privateKey, 'sign').then(function (sk) {
			if (isNode) {
				var signer	= crypto.createSign(rsa.algorithm);
				signer.write(new Buffer(message));
				signer.end();

				return signer.sign(sk);
			}
			else {
				return crypto.subtle.sign(rsa.algorithm, sk, message);
			}
		}).then(function (signature) {
			return new Uint8Array(signature);
		});
	},

	verifyDetached: function (signature, message, publicKey) {
		return importJWK(publicKey, 'verify').then(function (pk) {
			if (isNode) {
				var verifier	= crypto.createVerify(rsa.algorithm);
				verifier.update(new Buffer(message));

				return verifier.verify(pk, signature);
			}
			else {
				return crypto.subtle.verify(rsa.algorithm, pk, signature, message);
			}
		});
	}
};


var superSphincs	= {
	publicKeyLength: rsa.publicKeyLength + sphincs.publicKeyLength,
	privateKeyLength: rsa.privateKeyLength + sphincs.privateKeyLength,
	signatureLength: rsa.signatureLength + sphincs.signatureLength,
	hashLength: 64,

	hash: function (message) {
		return Promise.resolve().then(function () {
			var messageBytes	= decodeString(message);

			if (isNode) {
				var hasher	= crypto.createHash('sha512');
				hasher.update(new Buffer(messageBytes));

				return hasher.digest();
			}
			else {
				return crypto.subtle.digest(
					{
						name: 'SHA-512'
					},
					messageBytes
				);
			}
		}).then(function (hash) {
			var bytes	= new Uint8Array(hash);
			return {bytes: bytes, hex: to_hex(bytes)};
		}).catch(function () {
			var hex	= sha512(encodeString(message));
			return {bytes: from_hex(hex), hex: hex};
		});
	},

	keyPair: function () {
		return rsa.keyPair().then(function (rsaKeyPair) {
			var sphincsKeyPair	= sphincs.keyPair();

			var keyPair	= {
				publicKey: new Uint8Array(superSphincs.publicKeyLength),
				privateKey: new Uint8Array(superSphincs.privateKeyLength)
			};

			keyPair.publicKey.set(rsaKeyPair.publicKey);
			keyPair.privateKey.set(rsaKeyPair.privateKey);
			keyPair.publicKey.set(sphincsKeyPair.publicKey, rsa.publicKeyLength);
			keyPair.privateKey.set(sphincsKeyPair.privateKey, rsa.privateKeyLength);

			return keyPair;
		});
	},

	sign: function (message, privateKey, getHash) {
		return superSphincs.signDetached(message, privateKey, true, true).then(function (o) {
			message		= decodeString(message);

			var signed	= new Uint8Array(
				superSphincs.signatureLength + message.length
			);

			signed.set(o.signature);
			signed.set(message, superSphincs.signatureLength);

			var result	= {
				signed: encodeBase64(signed),
				hash: o.hash.hex
			};

			if (getHash) {
				return result;
			}
			else {
				return result.signed;
			}
		});
	},

	signDetached: function (message, privateKey, getHash, noEncode) {
		return superSphincs.hash(message).then(function (hash) {
			return Promise.all([hash, rsa.signDetached(
				hash.bytes,
				new Uint8Array(privateKey.buffer, 0, rsa.privateKeyLength)
			)]);
		}).then(function (results) {
			var hash			= results[0];
			var rsaSignature	= results[1];

			var sphincsSignature	= sphincs.signDetached(
				hash.bytes,
				new Uint8Array(privateKey.buffer, rsa.privateKeyLength)
			);

			var signature	= new Uint8Array(superSphincs.signatureLength);

			signature.set(rsaSignature);
			signature.set(sphincsSignature, rsa.signatureLength);

			var result	= noEncode ?
				{signature: signature, hash: hash} :
				{signature: encodeBase64(signature), hash: hash.hex}
			;

			if (getHash) {
				return result;
			}
			else {
				return result.signature;
			}
		});
	},

	open: function (signed, publicKey, getHash) {
		return Promise.resolve().then(function () {
			signed	= decodeBase64(signed);

			var signature	= new Uint8Array(
				signed.buffer,
				0,
				superSphincs.signatureLength
			);

			var message		= encodeString(
				new Uint8Array(signed.buffer, superSphincs.signatureLength)
			);

			return Promise.all([message, superSphincs.verifyDetached(
				signature,
				message,
				publicKey,
				true
			)]);
		}).then(function (results) {
			var message	= results[0];
			var o		= results[1];

			if (o.isValid) {
				var result	= {verified: message, hash: o.hash};

				if (getHash) {
					return result;
				}
				else {
					return result.verified;
				}
			}
			else {
				throw 'Failed to open SuperSPHINCS signed message.';
			}
		});
	},

	verifyDetached: function (signature, message, publicKey, getHash) {
		return superSphincs.hash(message).then(function (hash) {
			signature	= decodeBase64(signature);

			return Promise.all([
				hash,
				rsa.verifyDetached(
					new Uint8Array(signature.buffer, 0, rsa.signatureLength),
					hash.bytes,
					new Uint8Array(publicKey.buffer, 0, rsa.publicKeyLength)
				).catch(function () {
					return true;
				})
			]);
		}).then(function (results) {
			var hash		= results[0];
			var rsaIsValid	= results[1];

			var sphincsIsValid	= sphincs.verifyDetached(
				new Uint8Array(
					signature.buffer,
					rsa.signatureLength,
					sphincs.signatureLength
				),
				hash.bytes,
				new Uint8Array(publicKey.buffer, rsa.publicKeyLength)
			);

			var result	= {
				isValid: rsaIsValid && sphincsIsValid,
				hash: hash.hex
			};

			if (getHash) {
				return result;
			}
			else {
				return result.isValid;
			}
		});
	},

	exportKeys: function (keyPair, password) {
		return Promise.resolve().then(function () {
			if (!keyPair.privateKey) {
				return null;
			}

			var rsaPrivateKey			= new Uint8Array(
				rsa.publicKeyLength +
				rsa.privateKeyLength
			);

			var sphincsPrivateKey		= new Uint8Array(
				sphincs.publicKeyLength +
				sphincs.privateKeyLength
			);

			var superSphincsPrivateKey	= new Uint8Array(
				superSphincs.publicKeyLength +
				superSphincs.privateKeyLength
			);

			rsaPrivateKey.set(new Uint8Array(
				keyPair.publicKey.buffer,
				0,
				rsa.publicKeyLength
			));
			rsaPrivateKey.set(
				new Uint8Array(
					keyPair.privateKey.buffer,
					0,
					rsa.privateKeyLength
				),
				rsa.publicKeyLength
			);

			sphincsPrivateKey.set(new Uint8Array(
				keyPair.publicKey.buffer,
				rsa.publicKeyLength
			));
			sphincsPrivateKey.set(
				new Uint8Array(
					keyPair.privateKey.buffer,
					rsa.privateKeyLength
				),
				sphincs.publicKeyLength
			);

			superSphincsPrivateKey.set(keyPair.publicKey);
			superSphincsPrivateKey.set(keyPair.privateKey, superSphincs.publicKeyLength);

			if (password) {
				return Promise.all([
					encrypt(rsaPrivateKey, password),
					encrypt(sphincsPrivateKey, password),
					encrypt(superSphincsPrivateKey, password)
				]);
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

			return {
				rsa: encodeBase64(results[0]),
				sphincs: encodeBase64(results[1]),
				superSphincs: encodeBase64(results[2])
			};
		}).then(function (privateKeyData) {
			return {
				private: privateKeyData,
				public: {
					rsa: encodeBase64(new Uint8Array(
						keyPair.publicKey.buffer,
						0,
						rsa.publicKeyLength
					)),
					sphincs: encodeBase64(new Uint8Array(
						keyPair.publicKey.buffer,
						rsa.publicKeyLength
					)),
					superSphincs: encodeBase64(keyPair.publicKey)
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
				var superSphincsPrivateKey	= decodeBase64(keyData.private.superSphincs);

				if (password) {
					return Promise.all([decrypt(superSphincsPrivateKey, password)]);
				}
				else {
					return [superSphincsPrivateKey];
				}
			}
			else {
				var rsaPrivateKey		= decodeBase64(keyData.private.rsa);
				var sphincsPrivateKey	= decodeBase64(keyData.private.sphincs);

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
				publicKey: new Uint8Array(superSphincs.publicKeyLength),
				privateKey: null
			};

			if (!results) {
				return keyPair;
			}

			keyPair.privateKey	= new Uint8Array(superSphincs.privateKeyLength);

			if (results.length === 1) {
				var superSphincsPrivateKey	= results[0];

				keyPair.publicKey.set(new Uint8Array(
					superSphincsPrivateKey.buffer,
					0,
					superSphincs.publicKeyLength
				));

				keyPair.privateKey.set(new Uint8Array(
					superSphincsPrivateKey.buffer,
					superSphincs.publicKeyLength
				));
			}
			else {
				var rsaPrivateKey		= results[0];
				var sphincsPrivateKey	= results[1];

				keyPair.publicKey.set(
					new Uint8Array(
						rsaPrivateKey.buffer,
						0,
						rsa.publicKeyLength
					)
				);
				keyPair.publicKey.set(
					new Uint8Array(
						sphincsPrivateKey.buffer,
						0,
						sphincs.publicKeyLength
					),
					rsa.publicKeyLength
				);

				keyPair.privateKey.set(
					new Uint8Array(
						rsaPrivateKey.buffer,
						rsa.publicKeyLength
					)
				);
				keyPair.privateKey.set(
					new Uint8Array(
						sphincsPrivateKey.buffer,
						sphincs.publicKeyLength
					),
					rsa.privateKeyLength
				);
			}

			return keyPair;
		}).then(function (keyPair) {
			if (!keyPair.privateKey) {
				if (keyData.public.superSphincs) {
					keyPair.publicKey.set(decodeBase64(keyData.public.superSphincs));
				}
				else if (keyData.public.rsa && keyData.public.sphincs) {
					keyPair.publicKey.set(decodeBase64(keyData.public.rsa));
					keyPair.publicKey.set(
						decodeBase64(keyData.public.sphincs),
						rsa.publicKeyLength
					);
				}
			}

			return keyPair;
		});
	}
};



return superSphincs;

}());


if (isNode) {
	module.exports		= superSphincs;
}
else {
	self.superSphincs	= superSphincs;
}
