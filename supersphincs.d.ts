export interface ISuperSphincs {
	/** Signature length. */
	bytes: number;

	/** Hash length. */
	hashBytes: number;

	/** Private key length. */
	privateKeyBytes: number;

	/** Public key length. */
	publicKeyBytes: number;

	/** Serializes key pair with optional encryption. */
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

	/** Serializes key pair with optional encryption. */
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
	hash (message: Uint8Array|string, onlyBinary: true) : Uint8Array;

	/** SHA-512 hash. */
	hash (message: Uint8Array|string, onlyBinary?: false) : {binary: Uint8Array; hex: string};

	/** Imports exported keys and creates key pair object. */
	importKeys (keyData: {public: {superSphincs: string}}) : Promise<{
		privateKey: null;
		publicKey: Uint8Array;
	}>;

	/** Imports exported keys and creates key pair object. */
	importKeys (keyData: {public: {rsa: string; sphincs: string}}) : Promise<{
		privateKey: null;
		publicKey: Uint8Array;
	}>;

	/** Imports exported keys and creates key pair object. */
	importKeys (
		keyData: {
			private: {
				superSphincs: string;
			};
			public?: any;
		},
		password?: string
	) : Promise<{
		privateKey: Uint8Array;
		publicKey: Uint8Array;
	}>;

	/** Imports exported keys and creates key pair object. */
	importKeys (
		keyData: {
			private: {
				rsa: string;
				sphincs: string;
			};
			public?: any;
		},
		password?: string|{
			rsa: string;
			sphincs: string;
		}
	) : Promise<{
		privateKey: Uint8Array;
		publicKey: Uint8Array;
	}>;

	/** Generates key pair. */
	keyPair () : Promise<{privateKey: Uint8Array; publicKey: Uint8Array}>;

	/** Verifies signed message against publicKey and returns it. */
	open (signed: Uint8Array|string, publicKey: Uint8Array) : Promise<string>;

	/** Signs message with privateKey and returns combined message. */
	sign (message: Uint8Array|string, privateKey: Uint8Array) : Promise<string>;

	/** Signs message with privateKey and returns signature. */
	signDetached (message: Uint8Array|string, privateKey: Uint8Array) : Promise<string>;

	/** Verifies detached signature against publicKey. */
	verifyDetached (
		signature: Uint8Array|string,
		message: Uint8Array|string,
		publicKey: Uint8Array
	) : Promise<boolean>;
};

export const superSphincs: ISuperSphincs;
