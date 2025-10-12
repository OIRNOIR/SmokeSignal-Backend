import crypto from "node:crypto";
import * as kyber from "crystals-kyber-js";

const window = {
	crypto: crypto.webcrypto
};

import atob from "atob";
import btoa from "btoa";

function exportCryptoArray(array: Uint8Array): string {
	return btoa(JSON.stringify(Array.from(array)));
}

function importCryptoString(str: string): Uint8Array {
	return new Uint8Array(JSON.parse(atob(str)));
}

interface KyberKeyPair {
	publicKey: Uint8Array;
	privateKey: Uint8Array;
}

interface ExportedKeyPair {
	publicKey: string;
	privateKey: string;
}

// biome-ignore lint/complexity/noStaticOnlyClass: I like this layout
export default class ChatCrypto {
	static async generateKyberKeyPair(): Promise<KyberKeyPair> {
		const kyberInstance = new kyber.Kyber1024();
		const keys = await kyberInstance.generateKeyPair();
		return { publicKey: keys[0], privateKey: keys[1] };
	}

	static async generateAESKey(): Promise<CryptoKey> {
		return window.crypto.subtle.generateKey(
			{
				name: "AES-GCM",
				length: 256
			},
			true,
			["encrypt", "decrypt"]
		);
	}

	static async exportKyberKeyPair(
		keyPair: KyberKeyPair,
		password: string | null = null
	): Promise<ExportedKeyPair> {
		async function exportKey(key: Uint8Array): Promise<string> {
			const str = exportCryptoArray(key);
			if (password == null) {
				return str;
			}
			return await ChatCrypto.encryptAESStringWithPassword(str, password);
		}
		return {
			publicKey: await exportKey(keyPair.publicKey),
			privateKey: await exportKey(keyPair.privateKey)
		};
	}

	static exportKyberPublicKeyFromPair(keyPair: KyberKeyPair): string {
		return exportCryptoArray(keyPair.publicKey);
	}

	static unprotectedKyberExport(key: Uint8Array): string {
		return exportCryptoArray(key);
	}

	static async exportAESKey(key: CryptoKey): Promise<string> {
		const jwk = await window.crypto.subtle.exportKey("jwk", key);
		return btoa(JSON.stringify(jwk));
	}

	static async wrapAESKeyWithPassword(
		key: CryptoKey,
		password: string
	): Promise<string> {
		const exportedKey = await ChatCrypto.exportAESKey(key);
		return ChatCrypto.encryptAESStringWithPassword(exportedKey, password);
	}

	static async wrapAESKey(
		wrapperKey: CryptoKey,
		wrappedKey: CryptoKey
	): Promise<string> {
		const exportedKey = await ChatCrypto.exportAESKey(wrappedKey);
		return ChatCrypto.encryptAESString(wrapperKey, exportedKey);
	}

	static async unwrapAESKeyWithPassword(
		cipherText: string,
		password: string
	): Promise<CryptoKey> {
		const decrypted = await ChatCrypto.decryptAESStringWithPassword(
			cipherText,
			password
		);
		return ChatCrypto.importAESKey(decrypted);
	}

	static async unwrapAESKey(
		key: CryptoKey,
		cipherText: string
	): Promise<CryptoKey> {
		const decrypted = await ChatCrypto.decryptAESString(key, cipherText);
		return ChatCrypto.importAESKey(decrypted);
	}

	static async importKyberKeyPair(
		keyPair: ExportedKeyPair,
		password: string | null = null
	): Promise<KyberKeyPair> {
		async function importKey(key: string): Promise<Uint8Array> {
			if (password == null) {
				return importCryptoString(key);
			}
			const decrypted = await ChatCrypto.decryptAESStringWithPassword(
				key,
				password
			);
			return importCryptoString(decrypted);
		}
		return {
			publicKey: await importKey(keyPair.publicKey),
			privateKey: await importKey(keyPair.privateKey)
		};
	}

	static importKyberPublicKey(key: string): Uint8Array {
		return importCryptoString(key);
	}

	static async importAESKey(key: string): Promise<CryptoKey> {
		const imported = await window.crypto.subtle.importKey(
			"jwk",
			JSON.parse(atob(key)),
			{
				name: "AES-GCM"
			},
			true,
			["encrypt", "decrypt"]
		);
		return imported;
	}

	static async importRawAESKey(key: Uint8Array): Promise<CryptoKey> {
		const imported = await window.crypto.subtle.importKey(
			"raw",
			key,
			{
				name: "AES-GCM"
			},
			true,
			["encrypt", "decrypt"]
		);
		return imported;
	}

	static async deriveCipherKyber(
		publicKey: Uint8Array
	): Promise<{ cipherText: string; symmetricKey: CryptoKey }> {
		const kyberInstance = new kyber.Kyber1024();
		/* cspell: disable-next-line */
		const c_ss = await kyberInstance.encap(publicKey);
		const exportedCipherText = exportCryptoArray(c_ss[0]);
		const importedKey = await ChatCrypto.importRawAESKey(c_ss[1]);
		return { cipherText: exportedCipherText, symmetricKey: importedKey };
	}

	static async deriveKeyKyber(
		cipherText: string,
		privateKey: Uint8Array
	): Promise<CryptoKey> {
		const kyberInstance = new kyber.Kyber1024();
		const cipherArr = importCryptoString(cipherText);
		/* cspell: disable-next-line */
		const ss = await kyberInstance.decap(cipherArr, privateKey);
		const importedKey = await ChatCrypto.importRawAESKey(ss);
		return importedKey;
	}

	static async encryptAES(key: CryptoKey, data: Uint8Array): Promise<string> {
		const iv = window.crypto.getRandomValues(new Uint8Array(16));

		const ivStr = Array.from(iv)
			.map((b) => String.fromCharCode(b))
			.join("");

		const encryptedData = await window.crypto.subtle.encrypt(
			{ name: "AES-GCM", iv: iv },
			key,
			data
		);

		const uintArray = Array.from(new Uint8Array(encryptedData));

		const ctStr = uintArray.map((byte) => String.fromCharCode(byte)).join("");
		return btoa(`${btoa(ivStr)}:${btoa(ctStr)}`);
	}

	static async encryptAESString(key: CryptoKey, data: string): Promise<string> {
		return ChatCrypto.encryptAES(key, new TextEncoder().encode(data));
	}

	/**
	 * Precondition: data is a valid output of encryptAES
	 */
	static async decryptAES(key: CryptoKey, data: string): Promise<ArrayBuffer> {
		const splitData = atob(data).split(":");
		const ivB64 = splitData[0];
		const strB64 = splitData[1];
		if (ivB64 == undefined || strB64 == undefined) {
			throw new Error("Precondition violated: Unprocessable entity in decryptAES");
		}

		const ivStr = atob(ivB64);
		const iv = new Uint8Array(Array.from(ivStr).map((ch) => ch.charCodeAt(0)));

		const string = atob(strB64);
		const uintArray = new Uint8Array(
			[...string].map((char) => char.charCodeAt(0))
		);

		const algorithm = {
			name: "AES-GCM",
			iv: iv
		};

		const decryptedData = await window.crypto.subtle.decrypt(
			algorithm,
			key,
			uintArray
		);

		return decryptedData;
	}

	static async decryptAESString(key: CryptoKey, data: string): Promise<string> {
		const decryptedData = await ChatCrypto.decryptAES(key, data);
		return new TextDecoder().decode(decryptedData);
	}

	static async deriveEncryptionKey(
		password: string,
		salt: Uint8Array
	): Promise<CryptoKey> {
		const imported = await window.crypto.subtle.importKey(
			"raw",
			new TextEncoder().encode(password),
			{
				name: "PBKDF2"
			},
			false,
			["deriveKey"]
		);
		return window.crypto.subtle.deriveKey(
			{
				name: "PBKDF2",
				salt: salt,
				iterations: 1000000,
				hash: {
					name: "SHA-512"
				}
			},
			imported,
			{
				name: "AES-GCM",
				length: 256
			},
			false,
			["encrypt", "decrypt", "wrapKey", "unwrapKey"]
		);
	}

	static async encryptAESStringWithPassword(
		string: string,
		password: string
	): Promise<string> {
		const salt = window.crypto.getRandomValues(new Uint8Array(32));
		const encryptionKey = await ChatCrypto.deriveEncryptionKey(password, salt);
		const encrypted = await ChatCrypto.encryptAESString(encryptionKey, string);
		const saltStr = Array.from(salt)
			.map((b) => String.fromCharCode(b))
			.join("");
		return btoa(`${btoa(saltStr)}:${encrypted}`);
	}

	static async decryptAESStringWithPassword(
		data: string,
		password: string
	): Promise<string> {
		const splitData = atob(data).split(":");
		const ivB64 = splitData[0];
		const strB64 = splitData[1];
		if (ivB64 == undefined || strB64 == undefined) {
			throw new Error("Precondition violated: Unprocessable entity in decryptAES");
		}
		const salt = new Uint8Array(
			Array.from(atob(ivB64)).map((ch) => ch.charCodeAt(0))
		);
		const encryptionKey = await ChatCrypto.deriveEncryptionKey(password, salt);
		return await ChatCrypto.decryptAESString(encryptionKey, strB64);
	}

	static async hashSHA256String(data: string): Promise<string> {
		const encoded = new TextEncoder().encode(data);
		const hashBuffer = await window.crypto.subtle.digest("SHA-256", encoded);
		const hashArray = Array.from(new Uint8Array(hashBuffer));
		const hashHex = hashArray
			.map((b) => b.toString(16).padStart(2, "0"))
			.join(""); // convert bytes to hex string
		return hashHex;
	}
}
