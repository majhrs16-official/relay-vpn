package org.majhrs16.vpn.shared;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;

public class CryptoUtils {

	public static final int PBKDF2_ITERATIONS = 100000;
	public static final byte[] PBKDF2_SALT = "vpn-relay-psk-v1".getBytes(StandardCharsets.US_ASCII);

	private static final String ALGORITHM = "AES/GCM/NoPadding";
	private static final int GCM_TAG_LENGTH = 128;
	private static final int IV_LENGTH = 12;
	private static final SecureRandom RANDOM = new SecureRandom();

	/** Deriva una clave AES-256 a partir del PSK (PBKDF2-HMAC-SHA256 + salt fijo). */
	public static SecretKey deriveKey(String psk) throws Exception {
		PBEKeySpec spec = new PBEKeySpec(psk.toCharArray(), PBKDF2_SALT, PBKDF2_ITERATIONS, 256);
		SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
		return new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");
	}

	/** Devuelve iv || ciphertext || tag. */
	public static byte[] encrypt(byte[] plaintext, SecretKey key) throws Exception {
		byte[] iv = new byte[IV_LENGTH];
		RANDOM.nextBytes(iv);

		Cipher cipher = Cipher.getInstance(ALGORITHM);
		GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
		cipher.init(Cipher.ENCRYPT_MODE, key, spec);

		byte[] ciphertext = cipher.doFinal(plaintext);

		ByteBuffer buffer = ByteBuffer.allocate(IV_LENGTH + ciphertext.length);
		buffer.put(iv);
		buffer.put(ciphertext);
		return buffer.array();
	}

	/** Recibe iv || ciphertext || tag; lanza excepción si la autenticación falla. */
	public static byte[] decrypt(byte[] encryptedData, SecretKey key) throws Exception {
		if (encryptedData.length < IV_LENGTH + (GCM_TAG_LENGTH / 8)) {
			throw new IllegalArgumentException("Invalid payload length");
		}

		byte[] iv = Arrays.copyOfRange(encryptedData, 0, IV_LENGTH);
		byte[] ciphertext = Arrays.copyOfRange(encryptedData, IV_LENGTH, encryptedData.length);

		Cipher cipher = Cipher.getInstance(ALGORITHM);
		GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
		cipher.init(Cipher.DECRYPT_MODE, key, spec);

		return cipher.doFinal(ciphertext);
	}
}