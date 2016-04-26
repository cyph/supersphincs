;

function importJWK (key, algorithm, purpose, callback) {
	crypto.subtle.importKey(
		'jwk',
		JSON.parse(to_string(new Uint8Array(key.buffer, 0, key.indexOf(0)))),
		algorithm,
		false,
		[purpose]
	).then(callback).catch(function () {
		callback(null, 'Failed to import key.');
	});
}
	
function exportJWK (key, algorithm, callback) {
	crypto.subtle.exportKey('jwk', key, algorithm).then(function (data) {
		callback(from_string(JSON.stringify(data)));
	}).catch(function () {
		callback(null, 'Failed to export key.');
	});
}

var rsa	= {
	algorithm: {
		name: 'RSASSA-PKCS1-v1_5',
		hash: {
			name: 'SHA-256'
		},
		modulusLength: 2048,
		publicExponent: new Uint8Array([0x01, 0x00, 0x01])
	},

	publicKeyLength: 420,
	privateKeyLength: 1660,
	signatureLength: 256,

	errorMessages: {
		keyPair: 'Failed to generate RSA key pair.',
		signDetached: 'Failed to generate RSA signature.',
		verifyDetached: 'Failed to verify RSA signature.'
	},

	keyPair: function (callback) {
		try {
			crypto.subtle.generateKey(
				rsa.algorithm,
				true,
				['sign', 'verify']
			).then(function (kp) {
				var keyPair = {};

				exportJWK(
					kp.publicKey,
					rsa.algorithm.name,
					function (publicKey) {
						keyPair.publicKey = publicKey;

						exportJWK(
							kp.privateKey,
							rsa.algorithm.name,
							function (privateKey) {
								keyPair.privateKey = privateKey;

								callback(keyPair);
							}
						);
					}
				);
			}).catch(function () {
				callback(null, rsa.errorMessages.keyPair);
			});
		}
		catch (_) {
			callback(null, rsa.errorMessages.keyPair);
		}
	},

	signDetached: function (message, privateKey, callback) {
		try {
			importJWK(privateKey, rsa.algorithm, 'sign', function (sk) {
				crypto.subtle.sign(rsa.algorithm, sk, message).
					then(function (signature) {
						callback(new Uint8Array(signature));
					}).catch(function () {
						callback(null, rsa.errorMessages.signDetached);
					})
				;
			});
		}
		catch (_) {
			callback(null, rsa.errorMessages.signDetached);
		}
	},

	verifyDetached: function (signature, message, publicKey, callback) {
		try {
			importJWK(publicKey, rsa.algorithm, 'verify', function (pk) {
				crypto.subtle.verify(rsa.algorithm, pk, signature, message).
					then(function (isValid) {
						callback(isValid);
					}).catch(function () {
						callback(null, rsa.errorMessages.verifyDetached);
					})
				;
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
		var sphincsSigned	= sphincs.sign(
			message,
			new Uint8Array(privateKey.buffer, rsa.privateKeyLength)
		);

		rsa.signDetached(
			message,
			new Uint8Array(privateKey.buffer, 0, rsa.privateKeyLength),
			function (rsaSignature, err) {
				if (err) {
					callback(null, superSphincs.errorMessages.sign);
					return;
				}

				var signed	= new Uint8Array(
					rsa.signatureLength + sphincsSigned.length
				);

				signed.set(rsaSignature);
				signed.set(sphincsSigned, rsa.signatureLength);

				callback(signed);
			}
		);
	},

	signDetached: function (message, privateKey, callback) {
		var sphincsSignature	= sphincs.signDetached(
			message,
			new Uint8Array(privateKey.buffer, rsa.privateKeyLength)
		);

		rsa.signDetached(
			message,
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
		var sphincsIsValid	= sphincs.verifyDetached(
			new Uint8Array(signature.buffer, rsa.signatureLength),
			message,
			new Uint8Array(publicKey.buffer, rsa.publicKeyLength)
		);

		rsa.verifyDetached(
			new Uint8Array(signature.buffer, 0, rsa.signatureLength),
			message,
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

self.superSphincs	= superSphincs;
