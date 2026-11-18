package org.majhrs16.vpn.shared;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.concurrent.atomic.AtomicLong;

/**
 * AES-256-GCM para el túnel. Formato en el cable (igual que el cliente Linux):
 * nonce(12) || ciphertext || tag(16).
 *
 * Las variantes con offsets escriben/leen sobre buffers reutilizados y reutilizan
 * la instancia de Cipher del hilo, para no reservar memoria ni crear un provider
 * por paquete. Las variantes antiguas (byte[], SecretKey) se mantienen por
 * compatibilidad de API.
 */
public class CryptoUtils {

	public static final int PBKDF2_ITERATIONS = 100000;
	public static final byte[] PBKDF2_SALT = "vpn-relay-psk-v1".getBytes(StandardCharsets.US_ASCII);

	public static final int IV_LENGTH = 12;
	public static final int TAG_LENGTH = 16;
	/** Bytes que añade el cifrado a un payload: nonce + tag. */
	public static final int OVERHEAD = IV_LENGTH + TAG_LENGTH;

	private static final String ALGORITHM = "AES/GCM/NoPadding";
	private static final int GCM_TAG_LENGTH = 128;
	private static final SecureRandom RANDOM = new SecureRandom();

	private static final ThreadLocal<Cipher> CIPHER = ThreadLocal.withInitial(() -> {
		try {
			return Cipher.getInstance(ALGORITHM);
		} catch (Exception e) {
			throw new IllegalStateException("AES/GCM/NoPadding no disponible", e);
		}
	});

	private static final ThreadLocal<byte[]> IV = ThreadLocal.withInitial(() -> new byte[IV_LENGTH]);

	/**
	 * Nonce por paquete sin SecureRandom: 6 bytes aleatorios fijos del proceso y
	 * un contador global de 48 bits. El contador es monótono, así que dentro del
	 * proceso no se repite nunca; entre procesos haría falta que coincidieran los
	 * 48 bits del prefijo (2^-48). Con 2^48 paquetes el contador no se agota en
	 * la práctica (siglos a 10.000 paq/s).
	 */
	private static final byte[] NONCE_PREFIX = new byte[6];
	private static final AtomicLong NONCE_SEQ = new AtomicLong();

	static {
		RANDOM.nextBytes(NONCE_PREFIX);
	}

	/** Rellena iv con prefijo || contador. Nunca devuelve null. */
	private static byte[] nextIv(byte[] iv) {
		System.arraycopy(NONCE_PREFIX, 0, iv, 0, 6);
		long v = NONCE_SEQ.getAndIncrement() & 0xFFFFFFFFFFFFL;
		iv[6] = (byte) (v >>> 40);
		iv[7] = (byte) (v >>> 32);
		iv[8] = (byte) (v >>> 24);
		iv[9] = (byte) (v >>> 16);
		iv[10] = (byte) (v >>> 8);
		iv[11] = (byte) v;
		return iv;
	}

	/** Deriva una clave AES-256 a partir del PSK (PBKDF2-HMAC-SHA256 + salt fijo). */
	public static SecretKey deriveKey(String psk) throws Exception {
		PBEKeySpec spec = new PBEKeySpec(psk.toCharArray(), PBKDF2_SALT, PBKDF2_ITERATIONS, 256);
		SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
		return new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");
	}

	/**
	 * Cifra in[inOff..inOff+inLen) y escribe nonce||ct||tag en out[outOff..).
	 * Devuelve los bytes escritos o -1 si falla.
	 */
	public static int encrypt(byte[] in, int inOff, int inLen, byte[] out, int outOff, SecretKey key) {
		return encrypt(in, inOff, inLen, out, outOff, key, null);
	}

	/**
	 * Igual que la variante anterior pero con la clave ya codificada: permite
	 * usar la ruta nativa sin codificar la SecretKey en cada paquete.
	 */
	public static int encrypt(byte[] in, int inOff, int inLen, byte[] out, int outOff,
	                          SecretKey key, byte[] keyBytes) {
		try {
			byte[] iv = nextIv(IV.get());

			if (keyBytes != null && keyBytes.length == 32 && NativeCrypto.isAvailable()) {
				int n = NativeCrypto.seal(keyBytes, iv, in, inOff, inLen, out, outOff + IV_LENGTH);
				if (n < 0) return -1;
				System.arraycopy(iv, 0, out, outOff, IV_LENGTH);
				return IV_LENGTH + n;
			}

			Cipher cipher = CIPHER.get();
			cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_LENGTH, iv));
			System.arraycopy(iv, 0, out, outOff, IV_LENGTH);
			int n = cipher.doFinal(in, inOff, inLen, out, outOff + IV_LENGTH);
			return IV_LENGTH + n;
		} catch (Exception e) {
			return -1;
		}
	}

	/**
	 * Descifra in[inOff..inOff+inLen) (nonce||ct||tag) y escribe el texto plano en
	 * out[outOff..). Devuelve los bytes escritos o -1 si no autentica o no cabe.
	 */
	public static int decrypt(byte[] in, int inOff, int inLen, byte[] out, int outOff, SecretKey key) {
		return decrypt(in, inOff, inLen, out, outOff, key, null);
	}

	public static int decrypt(byte[] in, int inOff, int inLen, byte[] out, int outOff,
	                          SecretKey key, byte[] keyBytes) {
		if (inLen < OVERHEAD) return -1;
		try {
			if (keyBytes != null && keyBytes.length == 32 && NativeCrypto.isAvailable()) {
				byte[] iv = IV.get();
				System.arraycopy(in, inOff, iv, 0, IV_LENGTH);
				return NativeCrypto.open(keyBytes, iv, in, inOff + IV_LENGTH,
						inLen - IV_LENGTH, out, outOff);
			}

			Cipher cipher = CIPHER.get();
			cipher.init(Cipher.DECRYPT_MODE, key,
					new GCMParameterSpec(GCM_TAG_LENGTH, in, inOff, IV_LENGTH));
			return cipher.doFinal(in, inOff + IV_LENGTH, inLen - IV_LENGTH, out, outOff);
		} catch (Exception e) {
			return -1;
		}
	}

	/** Devuelve iv || ciphertext || tag. */
	public static byte[] encrypt(byte[] plaintext, SecretKey key) throws Exception {
		byte[] out = new byte[plaintext.length + OVERHEAD];
		int n = encrypt(plaintext, 0, plaintext.length, out, 0, key);
		if (n < 0) throw new IllegalStateException("Error cifrando");
		return out;
	}

	/** Recibe iv || ciphertext || tag; lanza excepción si la autenticación falla. */
	public static byte[] decrypt(byte[] encryptedData, SecretKey key) throws Exception {
		byte[] out = new byte[encryptedData.length];
		int n = decrypt(encryptedData, 0, encryptedData.length, out, 0, key);
		if (n < 0) throw new IllegalArgumentException("Invalid payload length o tag inválido");
		if (n == out.length) return out;
		return java.util.Arrays.copyOf(out, n);
	}
}
