;

var rsaKeygen, pemJwk;
if (isNode) {
	rsaKeygen	= require('rsa-keygen');
	pemJwk		= require('pem-jwk');
}


function importJWK (key, purpose, callback) {
	var jwk	= JSON.parse(to_string(new Uint8Array(key.buffer, 0, key.indexOf(0))));

	if (isNode) {
		callback(pemJwk.jwk2pem(jwk));
	}
	else {
		crypto.subtle.importKey(
			'jwk',
			jwk,
			rsa.algorithm,
			false,
			[purpose]
		).then(function (key) {
			try {
				callback(key);
			}
			catch (_) {}
		}).catch(function () {
			callback(null, 'Failed to import key.');
		});
	}
}
	
function exportJWK (key, callback) {
	function returnJWK (jwk) {
		callback(from_string(JSON.stringify(jwk)));
	}

	if (isNode) {
		returnJWK(pemJwk.pem2jwk(key));
	}
	else {
		crypto.subtle.exportKey(
			'jwk',
			key,
			rsa.algorithm.name
		).then(function (jwk) {
			try {
				returnJWK(jwk);
			}
			catch (_) {}
		}).catch(function () {
			callback(null, 'Failed to export key.');
		});
	}
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

function hashMessage (message) {
	var hex	= sha512(encodeString(message));
	return {bytes: from_hex(hex), hex: hex};
}

function deriveEncryptionKey (password, salt, callback) {
	if (isNode) {
		crypto.pbkdf2(
			new Buffer(password),
			new Buffer(salt),
			aes.keyDerivation.iterations,
			aes.keyLength,
			aes.keyDerivation.hashFunction,
			function (err, key) {
				callback(key, err);
			}
		);
	}
	else {
		crypto.subtle.importKey(
			'raw',
			decodeString(password),
			{
				name: aes.keyDerivation.algorithm,
			},
			false,
			['deriveKey']
		).then(function (keyOrigin) {
			crypto.subtle.deriveKey(
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
			).then(function (key) {
				try {
					callback(key);
				}
				catch (_) {}
			}).catch(function (err) {
				callback(null, err);
			});
		})
		.catch(function (err) {
			callback(null, err);
		});
	}
}

function encrypt (plaintext, password, callback) {
	var iv		= isNode ?
		crypto.randomBytes(aes.ivLength) :
		crypto.getRandomValues(new Uint8Array(aes.ivLength))
	;

	var salt	= isNode ?
		crypto.randomBytes(aes.keyDerivation.saltLength) :
		crypto.getRandomValues(new Uint8Array(aes.keyDerivation.saltLength))
	;

	deriveEncryptionKey(password, salt, function (key, err) {
		if (err) {
			callback(null, err);
			return;
		}

		if (isNode) {
			try {
				var cipher	= crypto.createCipheriv(aes.algorithm, key, iv);
				var buf1	= cipher.update(new Buffer(plaintext));
				var buf2	= cipher.final();
				var buf3	= cipher.getAuthTag();

				callback(new Uint8Array(Buffer.concat([iv, salt, buf1, buf2, buf3])));
			}
			catch (err) {
				callback(null, err);
			}
		}
		else {
			crypto.subtle.encrypt(
				{
					name: aes.algorithm,
					iv: iv,
					tagLength: aes.tagLengthBytes
				},
				key,
				plaintext
			).then(function (encrypted) {
				try {
					encrypted		= new Uint8Array(encrypted);

					var cyphertext	= new Uint8Array(
						aes.ivLength + aes.keyDerivation.saltLength + encrypted.length
					);

					cyphertext.set(iv);
					cyphertext.set(salt, aes.ivLength);
					cyphertext.set(encrypted, aes.ivLength + aes.keyDerivation.saltLength);

					callback(cyphertext);
				}
				catch (_) {}
			}).catch(function (err) {
				callback(null, err);
			});
		}
	});
}

function decrypt (cyphertext, password, callback) {
	var iv			= new Uint8Array(cyphertext.buffer, 0, aes.ivLength);

	var salt		= new Uint8Array(
		cyphertext.buffer,
		aes.ivLength,
		aes.keyDerivation.saltLength
	);

	deriveEncryptionKey(password, salt, function (key, err) {
		if (err) {
			callback(null, err);
			return;
		}

		if (isNode) {
			try {
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

				callback(new Uint8Array(Buffer.concat([buf1, buf2])));
			}
			catch (err) {
				callback(null, err);
			}
		}
		else {
			var encrypted	= new Uint8Array(
				cyphertext.buffer,
				aes.ivLength + aes.keyDerivation.saltLength
			);

			crypto.subtle.decrypt(
				{
					name: aes.algorithm,
					iv: iv,
					tagLength: aes.tagLengthBytes
				},
				key,
				encrypted
			).then(function (decrypted) {
				try {
					callback(new Uint8Array(decrypted));
				}
				catch (_) {}
			}).catch(function (err) {
				callback(null, err);
			});
		}
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

	errorMessages: {
		keyPair: 'Failed to generate RSA key pair.',
		signDetached: 'Failed to generate RSA signature.',
		verifyDetached: 'Failed to attempt to verify RSA signature.'
	},

	keyPair: function (callback) {
		function returnKeyPair (kp) {
			var keyPair = {};

			exportJWK(kp.publicKey, function (publicKey) {
				keyPair.publicKey = publicKey;

				exportJWK(kp.privateKey, function (privateKey) {
					keyPair.privateKey = privateKey;

					callback(keyPair);
				});
			});
		}

		try {
			if (isNode) {
				var kp	= rsaKeygen.generate();

				returnKeyPair({
					publicKey: kp.public_key,
					privateKey: kp.private_key
				});
			}
			else {
				crypto.subtle.generateKey(
					rsa.algorithm,
					true,
					['sign', 'verify']
				).then(function (kp) {
					try {
						returnKeyPair(kp);
					}
					catch (_) {}
				}).catch(function () {
					callback(null, rsa.errorMessages.keyPair);
				});
			}
		}
		catch (_) {
			callback(null, rsa.errorMessages.keyPair);
		}
	},

	signDetached: function (message, privateKey, callback) {
		try {
			importJWK(privateKey, 'sign', function (sk) {
				if (isNode) {
					var signer	= crypto.createSign(rsa.algorithm);
					signer.write(new Buffer(message));
					signer.end();
					callback(new Uint8Array(signer.sign(sk)));
				}
				else {
					crypto.subtle.sign(rsa.algorithm, sk, message).
						then(function (signature) {
							try {
								callback(new Uint8Array(signature));
							}
							catch (_) {}
						}).catch(function () {
							callback(null, rsa.errorMessages.signDetached);
						})
					;
				}
			});
		}
		catch (_) {
			callback(null, rsa.errorMessages.signDetached);
		}
	},

	verifyDetached: function (signature, message, publicKey, callback) {
		try {
			importJWK(publicKey, 'verify', function (pk) {
				if (isNode) {
					var verifier	= crypto.createVerify(rsa.algorithm);
					verifier.update(new Buffer(message));
					callback(verifier.sign(pk, signature));
				}
				else {
					crypto.subtle.verify(rsa.algorithm, pk, signature, message).
						then(function (isValid) {
							try {
								callback(isValid);
							}
							catch (_) {}
						}).catch(function () {
							callback(null, rsa.errorMessages.verifyDetached);
						})
					;
				}
			});
		}
		catch (_) {
			callback(null, rsa.errorMessages.verifyDetached);
		}
	}
};


var superSphincs	= {
	publicKeyLength: rsa.publicKeyLength + sphincs.publicKeyLength,
	privateKeyLength: rsa.privateKeyLength + sphincs.privateKeyLength,
	signatureLength: rsa.signatureLength + sphincs.signatureLength,
	hashLength: 64,

	errorMessages: {
		keyPair: 'Failed to generate SuperSPHINCS key pair.',
		sign: 'Failed to generate SuperSPHINCS signature.',
		open: 'Failed to open SuperSPHINCS signed message.',
		verify: 'Failed to attempt to verify SuperSPHINCS signature.'
	},

	hash: hashMessage,

	keyPair: function (callback) {
		var sphincsKeyPair;

		try {
			sphincsKeyPair	= sphincs.keyPair();
		}
		catch (_) {
			callback(null, superSphincs.errorMessages.keyPair);
		}

		rsa.keyPair(function (rsaKeyPair, err) {
			if (err) {
				callback(null, superSphincs.errorMessages.keyPair);
				return;
			}

			var keyPair	= {
				publicKey: new Uint8Array(superSphincs.publicKeyLength),
				privateKey: new Uint8Array(superSphincs.privateKeyLength)
			};

			keyPair.publicKey.set(rsaKeyPair.publicKey);
			keyPair.privateKey.set(rsaKeyPair.privateKey);
			keyPair.publicKey.set(sphincsKeyPair.publicKey, rsa.publicKeyLength);
			keyPair.privateKey.set(sphincsKeyPair.privateKey, rsa.privateKeyLength);

			callback(keyPair);
		});
	},

	sign: function (message, privateKey, callback) {
		superSphincs.signDetached(
			message,
			privateKey,
			function (signature, hash, err) {
				if (signature) {
					message		= decodeString(message);

					var signed	= new Uint8Array(
						superSphincs.signatureLength + message.length
					);

					signed.set(signature);
					signed.set(message, superSphincs.signatureLength);

					callback(encodeBase64(signed), hash.hex);
				}
				else {
					callback(null, null, err);
				}
			},
			true
		);
	},

	signDetached: function (message, privateKey, callback, noEncode) {
		try {
			var hash	= hashMessage(message);

			var sphincsSignature	= sphincs.signDetached(
				hash.bytes,
				new Uint8Array(privateKey.buffer, rsa.privateKeyLength)
			);

			rsa.signDetached(
				hash.bytes,
				new Uint8Array(privateKey.buffer, 0, rsa.privateKeyLength),
				function (rsaSignature, err) {
					if (err) {
						callback(null, null, superSphincs.errorMessages.sign);
						return;
					}

					var signature	= new Uint8Array(superSphincs.signatureLength);

					signature.set(rsaSignature);
					signature.set(sphincsSignature, rsa.signatureLength);

					if (noEncode) {
						callback(signature, hash);
					}
					else {
						callback(encodeBase64(signature), hash.hex);
					}
				}
			);
		}
		catch (_) {
			callback(null, null, superSphincs.errorMessages.sign);
		}
	},

	open: function (signed, publicKey, callback) {
		try {
			signed	= decodeBase64(signed);

			var signature	= new Uint8Array(
				signed.buffer,
				0,
				superSphincs.signatureLength
			);

			var message		= encodeString(
				new Uint8Array(signed.buffer, superSphincs.signatureLength)
			);

			superSphincs.verifyDetached(
				signature,
				message,
				publicKey,
				function (isValid, messageHash) {
					if (isValid) {
						callback(message, messageHash);
					}
					else {
						callback(null, null, superSphincs.errorMessages.open);
					}
				}
			);
		}
		catch (_) {
			callback(null, null, superSphincs.errorMessages.open);
		}
	},

	verifyDetached: function (signature, message, publicKey, callback) {
		try {
			signature	= decodeBase64(signature);

			var hash	= hashMessage(message);

			var sphincsIsValid	= sphincs.verifyDetached(
				new Uint8Array(
					signature.buffer,
					rsa.signatureLength,
					sphincs.signatureLength
				),
				hash.bytes,
				new Uint8Array(publicKey.buffer, rsa.publicKeyLength)
			);

			rsa.verifyDetached(
				new Uint8Array(signature.buffer, 0, rsa.signatureLength),
				hash.bytes,
				new Uint8Array(publicKey.buffer, 0, rsa.publicKeyLength),
				function (rsaIsValid, err) {
					if (err) {
						rsaIsValid	= true;
					}

					callback(rsaIsValid && sphincsIsValid, hash.hex);
				}
			);
		}
		catch (_) {
			callback(null, null, superSphincs.errorMessages.verify);
		}
	},

	exportKeys: function (keyPair, password, callback) {
		if (typeof callback === 'undefined') {
			callback	= password;
			password	= null;
		}

		var keyData	= {
			public: {
				rsa: null,
				sphincs: null,
				superSphincs: null
			},
			private: {
				rsa: null,
				sphincs: null,
				superSphincs: null
			}
		};

		if (keyPair.publicKey) {
			keyData.public.rsa			= encodeBase64(new Uint8Array(
				keyPair.publicKey.buffer,
				0,
				rsa.publicKeyLength
			));

			keyData.public.sphincs		= encodeBase64(new Uint8Array(
				keyPair.publicKey.buffer,
				rsa.publicKeyLength
			));

			keyData.public.superSphincs	= encodeBase64(keyPair.publicKey);
		}

		if (keyPair.privateKey) {
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
				encrypt(rsaPrivateKey, password, function (encrypted, err) {
					if (err) {
						callback(null, err);
						return;
					}

					keyData.private.rsa	= encodeBase64(encrypted);

					encrypt(sphincsPrivateKey, password, function (encrypted, err) {
						if (err) {
							callback(null, err);
							return;
						}

						keyData.private.sphincs	= encodeBase64(encrypted);

						encrypt(superSphincsPrivateKey, password, function (encrypted, err) {
							if (err) {
								callback(null, err);
								return;
							}

							keyData.private.superSphincs	= encodeBase64(encrypted);

							callback(keyData);
						});
					});
				});

				return;
			}

			keyData.private.rsa				= encodeBase64(rsaPrivateKey);
			keyData.private.sphincs			= encodeBase64(sphincsPrivateKey);
			keyData.private.superSphincs	= encodeBase64(superSphincsPrivateKey);
		}

		callback(keyData);
	},

	importKeys: function (keyData, password, callback) {
		if (typeof callback === 'undefined') {
			callback	= password;
			password	= null;
		}

		var keyPair	= {
			publicKey: null,
			privateKey: null
		};

		if (keyData.private) {
			if (keyData.private.superSphincs) {
				var superSphincsPrivateKey	= decodeBase64(keyData.private.superSphincs);

				if (password) {
					decrypt(
						superSphincsPrivateKey,
						password,
						function (decrypted, err) {
							if (err) {
								callback(null, err);
								return;
							}

							keyPair.publicKey	= new Uint8Array(
								new Uint8Array(
									decrypted.buffer,
									0,
									superSphincs.publicKeyLength
								)
							);

							keyPair.privateKey	= new Uint8Array(
								new Uint8Array(
									decrypted.buffer,
									superSphincs.publicKeyLength
								)
							);

							callback(keyPair);
						}
					);

					return;
				}

				keyPair.publicKey	= new Uint8Array(
					new Uint8Array(
						superSphincsPrivateKey.buffer,
						0,
						superSphincs.publicKeyLength
					)
				);

				keyPair.privateKey	= new Uint8Array(
					new Uint8Array(
						superSphincsPrivateKey.buffer,
						superSphincs.publicKeyLength
					)
				);
			}
			else if (keyData.private.rsa && keyData.private.sphincs) {
				keyPair.publicKey	= new Uint8Array(superSphincs.publicKeyLength);
				keyPair.privateKey	= new Uint8Array(superSphincs.privateKeyLength);

				var rsaPrivateKey		= decodeBase64(keyData.private.rsa);
				var sphincsPrivateKey	= decodeBase64(keyData.private.sphincs);

				if (password) {
					decrypt(
						rsaPrivateKey,
						typeof password === 'string' ? password : password.rsa,
						function (decrypted, err) {
							if (err) {
								callback(null, err);
								return;
							}

							keyPair.publicKey.set(new Uint8Array(
								decrypted.buffer,
								0,
								rsa.publicKeyLength
							));

							keyPair.privateKey.set(new Uint8Array(
								decrypted.buffer,
								rsa.publicKeyLength
							));

							decrypt(
								sphincsPrivateKey,
								typeof password === 'string' ? password : password.sphincs,
								function (decrypted, err) {
									if (err) {
										callback(null, err);
										return;
									}

									keyPair.publicKey.set(
										new Uint8Array(
											decrypted.buffer,
											0,
											sphincs.publicKeyLength
										),
										rsa.publicKeyLength
									);

									keyPair.privateKey.set(
										new Uint8Array(
											decrypted.buffer,
											sphincs.publicKeyLength
										),
										rsa.privateKeyLength
									);

									callback(keyPair);
								}
							);
						}
					);

					return;
				}

				keyPair.publicKey.set(new Uint8Array(
					rsaPrivateKey.buffer,
					0,
					rsa.publicKeyLength
				));

				keyPair.privateKey.set(new Uint8Array(
					rsaPrivateKey.buffer,
					rsa.publicKeyLength
				));

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
						sphincsPrivateKey.buffer,
						sphincs.publicKeyLength
					),
					rsa.privateKeyLength
				);
			}
		}
		else if (keyData.public) {
			if (keyData.public.superSphincs) {
				keyPair.publicKey	= decodeBase64(keyData.public.superSphincs);
			}
			else if (keyData.public.rsa && keyData.public.sphincs) {
				keyPair.publicKey	= new Uint8Array(superSphincs.publicKeyLength);

				keyPair.publicKey.set(decodeBase64(keyData.public.rsa));
				keyPair.publicKey.set(
					decodeBase64(keyData.public.sphincs),
					rsa.publicKeyLength
				);
			}
		}

		callback(keyPair);
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
