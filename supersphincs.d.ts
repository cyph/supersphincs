declare module 'supersphincs' {
	interface ISuperSphincs {
		/** Signature length. */
		bytes: Promise<number>;

		/** Hash length. */
		hashBytes: Promise<number>;

		/** Private key length. */
		privateKeyBytes: Promise<number>;

		/** Public key length. */
		publicKeyBytes: Promise<number>;

		/** Serializes key pair. */
		exportKeys (keyPair: {publicKey: Uint8Array}) : Promise<{
			private: {
				rsa: null;
				sphincs: null;
				superSphincs: null;
			};
			public: {
				rsa: string;
				sphincs: string;
				superSphincs: string;
			};
		}>;

		/**
		 * Serializes key pair with optional encryption.
		 * Using encryption (a password) requires native crypto support.
		 */
		exportKeys (
			keyPair: {
				privateKey: Uint8Array;
				publicKey: Uint8Array;
			},
			password?: string
		) : Promise<{
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
		}>;

		/** SHA-512 hash. */
		hash (message: Uint8Array|string, onlyBinary: true) : Promise<Uint8Array>;

		/** SHA-512 hash. */
		hash (message: Uint8Array|string, onlyBinary?: false) : Promise<{
			binary: Uint8Array;
			hex: string;
		}>;

		/** Imports exported keys and creates key pair object. */
		importKeys (keyData: {
			public: {rsa: string; sphincs: string}|{superSphincs: string}
		}) : Promise<{
			privateKey: null;
			publicKey: Uint8Array;
		}>;

		/**
		 * Imports exported keys and creates key pair object.
		 * Using a password requires native crypto support.
		 */
		importKeys (
			keyData: {
				private: {rsa: string; sphincs: string}|{superSphincs: string};
				public?: any;
			},
			password?: string
		) : Promise<{
			privateKey: Uint8Array;
			publicKey: Uint8Array;
		}>;

		/** Generates key pair. */
		keyPair () : Promise<{privateKey: Uint8Array; publicKey: Uint8Array}>;

		/** Verifies signed message against publicKey and returns it. */
		open (
			signed: Uint8Array|string,
			publicKey: Uint8Array|{
				public: {rsa: string; sphincs: string}|{superSphincs: string}
			},
			additionalData?: Uint8Array|string,
			knownGoodHash?: Uint8Array|string
		) : Promise<Uint8Array>;

		/** Verifies signed message against publicKey and returns it. */
		open (
			signed: Uint8Array|string,
			publicKey: Uint8Array|{
				public: {rsa: string; sphincs: string}|{superSphincs: string}
			},
			includeHash: true,
			additionalData?: Uint8Array|string,
			knownGoodHash?: Uint8Array|string
		) : Promise<{
			hash: Uint8Array;
			message: Uint8Array;
		}>;

		/** Verifies signed message against publicKey and returns it decoded to a string. */
		openString (
			signed: Uint8Array|string,
			publicKey: Uint8Array|{
				public: {rsa: string; sphincs: string}|{superSphincs: string}
			},
			additionalData?: Uint8Array|string,
			knownGoodHash?: Uint8Array|string
		) : Promise<string>;

		/** Verifies signed message against publicKey and returns it decoded to a string. */
		openString (
			signed: Uint8Array|string,
			publicKey: Uint8Array|{
				public: {rsa: string; sphincs: string}|{superSphincs: string}
			},
			includeHash: true,
			additionalData?: Uint8Array|string,
			knownGoodHash?: Uint8Array|string
		) : Promise<{
			hash: string;
			message: Uint8Array;
		}>;

		/** Signs message with privateKey and returns combined message. */
		sign (
			message: Uint8Array|string,
			privateKey: Uint8Array,
			additionalData?: Uint8Array|string
		) : Promise<Uint8Array>;

		/** Signs message with privateKey and returns combined message encoded as base64. */
		signBase64 (
			message: Uint8Array|string,
			privateKey: Uint8Array,
			additionalData?: Uint8Array|string
		) : Promise<string>;

		/** Signs message with privateKey and returns signature. */
		signDetached (
			message: Uint8Array|string,
			privateKey: Uint8Array,
			additionalData?: Uint8Array|string,
			preHashed?: boolean
		) : Promise<Uint8Array>;

		/** Signs message with privateKey and returns signature encoded as base64. */
		signDetachedBase64 (
			message: Uint8Array|string,
			privateKey: Uint8Array,
			additionalData?: Uint8Array|string,
			preHashed?: boolean
		) : Promise<string>;

		/** Verifies detached signature against publicKey. */
		verifyDetached (
			signature: Uint8Array|string,
			message: Uint8Array|string,
			publicKey: Uint8Array|{
				public: {rsa: string; sphincs: string}|{superSphincs: string}
			},
			additionalData?: Uint8Array|string,
			knownGoodHash?: Uint8Array|string
		) : Promise<boolean>;

		/** Verifies detached signature against publicKey. */
		verifyDetached (
			signature: Uint8Array|string,
			message: Uint8Array|string,
			publicKey: Uint8Array|{
				public: {rsa: string; sphincs: string}|{superSphincs: string}
			},
			includeHash: true,
			additionalData?: Uint8Array|string,
			knownGoodHash?: Uint8Array|string
		) : Promise<{
			hash: Uint8Array;
			valid: boolean;
		}>;
	}

	const superSphincs: ISuperSphincs;
}
