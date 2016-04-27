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
		).then(callback).catch(function () {
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
			returnJWK(jwk);
		}).catch(function () {
			callback(null, 'Failed to export key.');
		});
	}
}

function hashMessage (message) {
	return from_hex(sha512(
		typeof message === 'string' ?
			message :
			to_string(message)
	));
}

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
		verifyDetached: 'Failed to verify RSA signature.'
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
				).then(returnKeyPair).catch(function () {
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
							callback(new Uint8Array(signature));
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
							callback(isValid);
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

	errorMessages: {
		keyPair: 'Failed to generate SuperSPHINCS key pair.',
		sign: 'Failed to generate SuperSPHINCS signature.',
		open: 'Failed to open SuperSPHINCS signed message.'
	},

	keyPair: function (callback) {
		var sphincsKeyPair	= sphincs.keyPair();

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
		superSphincs.signDetached(message, privateKey, function (signature, err) {
			if (signature) {
				var signed	= new Uint8Array(
					superSphincs.signatureLength + message.length
				);

				signed.set(signature);
				signed.set(message, superSphincs.signatureLength);

				callback(signed);
			}
			else {
				callback(null, err);
			}
		});
	},

	signDetached: function (message, privateKey, callback) {
		var hash	= hashMessage(message);

		var sphincsSignature	= sphincs.signDetached(
			hash,
			new Uint8Array(privateKey.buffer, rsa.privateKeyLength)
		);

		rsa.signDetached(
			hash,
			new Uint8Array(privateKey.buffer, 0, rsa.privateKeyLength),
			function (rsaSignature, err) {
				if (err) {
					callback(null, superSphincs.errorMessages.sign);
					return;
				}

				var signature	= new Uint8Array(superSphincs.signatureLength);

				signature.set(rsaSignature);
				signature.set(sphincsSignature, rsa.signatureLength);

				callback(signature);
			}
		);
	},

	open: function (signed, publicKey, callback) {
		var signature	= new Uint8Array(signed.buffer, 0, superSphincs.signatureLength);
		var message		= new Uint8Array(signed.buffer, superSphincs.signatureLength);

		superSphincs.verifyDetached(signature, message, publicKey, function (isValid) {
			if (isValid) {
				callback(message);
			}
			else {
				callback(null, superSphincs.errorMessages.open);
			}
		});
	},

	verifyDetached: function (signature, message, publicKey, callback) {
		var hash	= hashMessage(message);

		var sphincsIsValid	= sphincs.verifyDetached(
			new Uint8Array(signature.buffer, rsa.signatureLength),
			hash,
			new Uint8Array(publicKey.buffer, rsa.publicKeyLength)
		);

		rsa.verifyDetached(
			new Uint8Array(signature.buffer, 0, rsa.signatureLength),
			hash,
			new Uint8Array(publicKey.buffer, 0, rsa.publicKeyLength),
			function (rsaIsValid, err) {
				if (err) {
					rsaIsValid	= true;
				}

				callback(rsaIsValid && sphincsIsValid);
			}
		);
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
