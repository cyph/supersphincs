;

var rsaKeygen, pemJwk;
if (isNode) {
	crypto		= require('crypto');
	rsaKeygen	= require('rsa-keygen');
	pemJwk		= require('pem-jwk');
}


function importJWK (key, purpose) {
	return Promise.resolve().then(function () {
		var jwk	= JSON.parse(
			sodiumUtil.to_string(
				new Uint8Array(new Uint8Array(key).buffer, 0, key.indexOf(0))
			)
		);

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
		return sodiumUtil.from_string(JSON.stringify(jwk));
	});
}

function clearMemory (data) {
	if (data instanceof Uint8Array) {
		sodiumUtil.memzero(data);
	}
	else if (isNode && data instanceof Buffer) {
		data.fill(0);
	}
}

function decodeBase64 (data) {
	return typeof data === 'string' ?
		sodiumUtil.from_base64(data) :
		data
	;
}

function encodeBase64 (data) {
	return typeof data === 'string' ?
		data :
		sodiumUtil.to_base64(data).replace(/\s+/g, '')
	;
}

function decodeString (message) {
	return typeof message === 'string' ?
		sodiumUtil.from_string(message) :
		message
	;
}

function encodeString (message) {
	return typeof message === 'string' ?
		message :
		sodiumUtil.to_string(message)
	;
}

function deriveEncryptionKey (password, salt) {
	if (isNode) {
		return new Promise(function (resolve, reject) {
			crypto.pbkdf2(
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
			crypto.randomBytes(aes.ivBytes) :
			crypto.getRandomValues(new Uint8Array(aes.ivBytes))
		;

		var salt	= isNode ?
			crypto.randomBytes(aes.keyDerivation.saltBytes) :
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
			var cipher	= crypto.createCipheriv(aes.algorithm, o.key, o.iv);
			var buf1	= cipher.update(new Buffer(plaintext));
			var buf2	= cipher.final();
			var buf3	= cipher.getAuthTag();

			var cyphertext	= new Uint8Array(Buffer.concat([o.iv, o.salt, buf1, buf2, buf3]));

			clearMemory(o.iv);
			clearMemory(o.salt);
			clearMemory(o.key);
			clearMemory(buf1);
			clearMemory(buf2);
			clearMemory(buf3);

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

			clearMemory(o.iv);
			clearMemory(o.salt);
			clearMemory(o.key);
			clearMemory(encrypted);

			return cyphertext;
		});
	}
}

function decrypt (cyphertext, password) {
	return Promise.resolve().then(function () {
		var iv		= new Uint8Array(cyphertext.buffer, 0, aes.ivBytes);

		var salt	= new Uint8Array(
			cyphertext.buffer,
			aes.ivBytes,
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
				aes.ivBytes + aes.keyDerivation.saltBytes,
				cyphertext.length -
					aes.ivBytes -
					aes.keyDerivation.saltBytes -
					aes.tagBytes
			);

			var authTag		= new Uint8Array(
				cyphertext.buffer,
				cyphertext.length - aes.tagBytes
			);

			var decipher	= crypto.createDecipheriv(
				aes.algorithm,
				new Buffer(key),
				new Buffer(iv)
			);

			decipher.setAuthTag(new Buffer(authTag));

			var buf1	= decipher.update(new Buffer(encrypted));
			var buf2	= decipher.final();

			decrypted	= Buffer.concat([buf1, buf2]);;

			clearMemory(buf1);
			clearMemory(buf2);
		}
		else {
			var encrypted	= new Uint8Array(
				cyphertext.buffer,
				aes.ivBytes + aes.keyDerivation.saltBytes
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

		clearMemory(key);

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

	publicKeyBytes: 450,
	privateKeyBytes: 1700,
	bytes: 256,

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
			var signature;

			if (isNode) {
				var messageBuffer	= new Buffer(message);
				var signer			= crypto.createSign(rsa.algorithm);
				signer.write(messageBuffer);
				signer.end();

				signature	= signer.sign(sk);

				clearMemory(messageBuffer);
			}
			else {
				signature	= crypto.subtle.sign(rsa.algorithm, sk, message);
			}

			return Promise.all([sk, signature]);
		}).then(function (results) {
			var sk			= results[0];
			var signature	= results[1];

			clearMemory(sk);

			return new Uint8Array(signature);
		});
	},

	verifyDetached: function (signature, message, publicKey) {
		return importJWK(publicKey, 'verify').then(function (pk) {
			var isValid;

			if (isNode) {
				var verifier	= crypto.createVerify(rsa.algorithm);
				verifier.update(new Buffer(message));

				isValid	= verifier.verify(pk, signature);
			}
			else {
				isValid	= crypto.subtle.verify(rsa.algorithm, pk, signature, message);
			}

			return Promise.all([pk, isValid]);
		}).then(function (results) {
			var pk		= results[0];
			var isValid	= results[1];

			clearMemory(pk);

			return isValid;
		});
	}
};


var superSphincs	= {
	publicKeyBytes: rsa.publicKeyBytes + sphincs.publicKeyBytes,
	privateKeyBytes: rsa.privateKeyBytes + sphincs.privateKeyBytes,
	bytes: rsa.bytes + sphincs.bytes,
	hashBytes: 64,

	hash: function (message, onlyBinary) {
		var messageBinary;
		var shouldClearMessageBinary	= typeof message === 'string';

		return Promise.resolve().then(function () {
			messageBinary	= decodeString(message);

			if (isNode) {
				var hasher	= crypto.createHash('sha512');
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
				clearMemory(messageBinary);
			}

			var binary	= new Uint8Array(hash);

			if (onlyBinary) {
				return binary;
			}

			return {binary: binary, hex: sodiumUtil.to_hex(binary)};
		}).catch(function () {
			if (shouldClearMessageBinary) {
				clearMemory(messageBinary);
			}

			var hex		= sha512(encodeString(message));
			var binary	= sodiumUtil.from_hex(hex);

			if (onlyBinary) {
				return binary;
			}

			return {binary: binary, hex: hex};
		});
	},

	keyPair: function () {
		return rsa.keyPair().then(function (rsaKeyPair) {
			var sphincsKeyPair	= sphincs.keyPair();

			var keyPair	= {
				keyType: 'supersphincs',
				publicKey: new Uint8Array(superSphincs.publicKeyBytes),
				privateKey: new Uint8Array(superSphincs.privateKeyBytes)
			};

			keyPair.publicKey.set(rsaKeyPair.publicKey);
			keyPair.privateKey.set(rsaKeyPair.privateKey);
			keyPair.publicKey.set(sphincsKeyPair.publicKey, rsa.publicKeyBytes);
			keyPair.privateKey.set(sphincsKeyPair.privateKey, rsa.privateKeyBytes);

			clearMemory(sphincsKeyPair.privateKey);
			clearMemory(rsaKeyPair.privateKey);
			clearMemory(sphincsKeyPair.publicKey);
			clearMemory(rsaKeyPair.publicKey);

			return keyPair;
		});
	},

	sign: function (message, privateKey, getHash) {
		var shouldClearMessage	= typeof message === 'string';

		return superSphincs.signDetached(message, privateKey, true, true).then(function (o) {
			message		= decodeString(message);

			var signed	= new Uint8Array(
				superSphincs.bytes + message.length
			);

			signed.set(o.signature);
			signed.set(message, superSphincs.bytes);

			var result	= {
				signed: encodeBase64(signed),
				hash: o.hash.hex
			};

			if (shouldClearMessage) {
				clearMemory(message);
			}

			clearMemory(signed);
			clearMemory(o.signature);
			clearMemory(o.hash.binary);

			if (getHash) {
				return result;
			}
			else {
				return result.signed;
			}
		}).catch(function (err) {
			if (shouldClearMessage) {
				clearMemory(message);
			}

			throw err;
		});
	},

	signDetached: function (message, privateKey, getHash, noEncode) {
		return superSphincs.hash(message).then(function (hash) {
			return Promise.all([hash, rsa.signDetached(
				hash.binary,
				new Uint8Array(privateKey.buffer, 0, rsa.privateKeyBytes)
			)]);
		}).then(function (results) {
			var hash			= results[0];
			var rsaSignature	= results[1];

			var sphincsSignature	= sphincs.signDetached(
				hash.binary,
				new Uint8Array(privateKey.buffer, rsa.privateKeyBytes)
			);

			var signature	= new Uint8Array(superSphincs.bytes);

			signature.set(rsaSignature);
			signature.set(sphincsSignature, rsa.bytes);

			var result	= noEncode ?
				{signature: signature, hash: hash} :
				{signature: encodeBase64(signature), hash: hash.hex}
			;

			if (!noEncode) {
				clearMemory(signature);
				clearMemory(hash.binary);
			}

			clearMemory(sphincsSignature);
			clearMemory(rsaSignature);

			if (getHash) {
				return result;
			}
			else {
				return result.signature;
			}
		});
	},

	open: function (signed, publicKey, getHash) {
		var shouldClearSigned	= typeof signed === 'string';

		return Promise.resolve().then(function () {
			signed	= decodeBase64(signed);

			var signature	= new Uint8Array(
				signed.buffer,
				0,
				superSphincs.bytes
			);

			var message		= encodeString(
				new Uint8Array(signed.buffer, superSphincs.bytes)
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

			if (shouldClearSigned) {
				clearMemory(signed);
			}

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
		}).catch(function (err) {
			if (shouldClearSigned) {
				clearMemory(signed);
			}

			throw err;
		});
	},

	verifyDetached: function (signature, message, publicKey, getHash) {
		var shouldClearSignature	= typeof signature === 'string';

		return superSphincs.hash(message).then(function (hash) {
			signature	= decodeBase64(signature);

			return Promise.all([
				hash,
				rsa.verifyDetached(
					new Uint8Array(signature.buffer, 0, rsa.bytes),
					hash.binary,
					new Uint8Array(publicKey.buffer, 0, rsa.publicKeyBytes)
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
					rsa.bytes,
					sphincs.bytes
				),
				hash.binary,
				new Uint8Array(publicKey.buffer, rsa.publicKeyBytes)
			);

			var result	= {
				isValid: rsaIsValid && sphincsIsValid,
				hash: hash.hex
			};

			if (shouldClearSignature) {
				clearMemory(signature);
			}

			clearMemory(hash.binary);

			if (getHash) {
				return result;
			}
			else {
				return result.isValid;
			}
		}).catch(function (err) {
			if (shouldClearSignature) {
				clearMemory(signature);
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
				rsa.publicKeyBytes +
				rsa.privateKeyBytes
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
				0,
				rsa.publicKeyBytes
			));
			rsaPrivateKey.set(
				new Uint8Array(
					keyPair.privateKey.buffer,
					0,
					rsa.privateKeyBytes
				),
				rsa.publicKeyBytes
			);

			sphincsPrivateKey.set(new Uint8Array(
				keyPair.publicKey.buffer,
				rsa.publicKeyBytes
			));
			sphincsPrivateKey.set(
				new Uint8Array(
					keyPair.privateKey.buffer,
					rsa.privateKeyBytes
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
					clearMemory(superSphincsPrivateKey);
					clearMemory(sphincsPrivateKey);
					clearMemory(rsaPrivateKey);

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
				rsa: encodeBase64(rsaPrivateKey),
				sphincs: encodeBase64(sphincsPrivateKey),
				superSphincs: encodeBase64(superSphincsPrivateKey)
			};

			clearMemory(superSphincsPrivateKey);
			clearMemory(sphincsPrivateKey);
			clearMemory(rsaPrivateKey);

			return privateKeyData;
		}).then(function (privateKeyData) {
			return {
				private: privateKeyData,
				public: {
					rsa: encodeBase64(new Uint8Array(
						keyPair.publicKey.buffer,
						0,
						rsa.publicKeyBytes
					)),
					sphincs: encodeBase64(new Uint8Array(
						keyPair.publicKey.buffer,
						rsa.publicKeyBytes
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
					0,
					superSphincs.publicKeyBytes
				));

				keyPair.privateKey.set(new Uint8Array(
					superSphincsPrivateKey.buffer,
					superSphincs.publicKeyBytes
				));
			}
			else {
				var rsaPrivateKey		= results[0];
				var sphincsPrivateKey	= results[1];

				keyPair.publicKey.set(
					new Uint8Array(
						rsaPrivateKey.buffer,
						0,
						rsa.publicKeyBytes
					)
				);
				keyPair.publicKey.set(
					new Uint8Array(
						sphincsPrivateKey.buffer,
						0,
						sphincs.publicKeyBytes
					),
					rsa.publicKeyBytes
				);

				keyPair.privateKey.set(
					new Uint8Array(
						rsaPrivateKey.buffer,
						rsa.publicKeyBytes
					)
				);
				keyPair.privateKey.set(
					new Uint8Array(
						sphincsPrivateKey.buffer,
						sphincs.publicKeyBytes
					),
					rsa.privateKeyBytes
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
						rsa.publicKeyBytes
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
	superSphincs.superSphincs	= superSphincs
	module.exports				= superSphincs;
}
else {
	self.superSphincs			= superSphincs;
}


}());
