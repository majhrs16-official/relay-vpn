package org.majhrs16.vpn.shared;

/**
 * AES-256-GCM en C usando el libcrypto (BoringSSL) del sistema vía JNI.
 *
 * Conscrypt reserva un EVP_CIPHER_CTX por mensaje y en este SoC cuesta
 * 100-190 us por paquete, lo que dejaba el túnel en ~2.600 paq/s. Con
 * EVP_AEAD baja a ~3 us. Si la librería no está disponible, CryptoUtils
 * sigue usando Conscrypt sin cambiar el formato del cable.
 */
public final class NativeCrypto {

	private static final boolean AVAILABLE;
	/** Núcleos a los que quedó fijado el último hilo, para diagnóstico. */
	private static volatile String pinStatus = "sin-medir";
	/** Descripción de la ruta activa (o del motivo del fallo), para diagnóstico. */
	private static final String STATUS;

	static {
		String status;
		int method = 0;
		boolean ok = false;
		try {
			/* Fuerza a cargar Conscrypt antes de nada: así libcrypto ya está
			   mapeado en el proceso y la vía de resolución manual tiene algo
			   sobre lo que trabajar. */
			try {
				javax.crypto.Cipher.getInstance("AES/GCM/NoPadding");
			} catch (Throwable ignored) {
				/* da igual: sólo es un calentamiento */
			}

			System.loadLibrary("vpncrypto");
			method = nativeAvailable();
			if (method > 0) {
				String detail = selfTest();
				ok = "ok".equals(detail);
				status = ok ? "nativo(" + method + ")" : "nativo(" + method + ")/" + detail;
			} else {
				status = "carga-fallo[" + nativeDiag() + "]";
			}
		} catch (Throwable t) {
			status = "so-fallo[" + t + "]";
		}
		AVAILABLE = ok;
		STATUS = status;
	}

	private NativeCrypto() {
	}

	public static boolean isAvailable() {
		return AVAILABLE;
	}

	/** Texto corto con la vía activa o el motivo del fallo. */
	public static String mode() {
		return STATUS;
	}

	/**
	 * Comprueba al arrancar que la ruta nativa cifra en el mismo formato que
	 * Conscrypt/OpenSSL (nonce||cifrado||tag). Si algo no cuadra se sigue
	 * usando Conscrypt: el túnel nunca se queda sin cripto funcional.
	 */
	private static String selfTest() {
		try {
			byte[] key = new byte[32];
			byte[] nonce = new byte[12];
			for (int i = 0; i < key.length; i++) key[i] = (byte) (i * 7 + 1);
			for (int i = 0; i < nonce.length; i++) nonce[i] = (byte) (i + 3);

			/* 0 bytes es el caso del latido (cabecera IPv4 sin payload): su
			   bloque cifrado mide exactamente el tag. */
			int[] sizes = {0, 1, 1400};
			for (int pay : sizes) {
				String err = roundTrip(key, nonce, pay);
				if (err != null) return err + "@" + pay;
			}
			return "ok";
		} catch (Throwable t) {
			return "ex:" + t.getClass().getSimpleName();
		}
	}

	/** Ensaya el mismo reparto de offsets que usa el túnel. */
	private static String roundTrip(byte[] key, byte[] nonce, int pay) {
		try {
			final int HDR = 20; /* Frame.HEADER_LEN */
			byte[] plain = new byte[HDR + pay];
			new java.util.Random(pay + 1).nextBytes(plain);
			byte[] wire = new byte[HDR + 12 + pay + 16];

			int n = seal(key, nonce, plain, HDR, pay, wire, HDR + 12);
			if (n != pay + 16) return "seal=" + n;

			byte[] back = new byte[HDR + pay];
			int m = open(key, nonce, wire, HDR + 12, n, back, HDR);
			if (m != pay) return "open=" + m;
			for (int i = 0; i < pay; i++) {
				if (back[HDR + i] != plain[HDR + i]) return "dif@" + i;
			}

			/* Cruce con Conscrypt, que es lo que usa el cliente Linux. */
			javax.crypto.Cipher c = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding");
			c.init(javax.crypto.Cipher.DECRYPT_MODE,
					new javax.crypto.spec.SecretKeySpec(key, "AES"),
					new javax.crypto.spec.GCMParameterSpec(128, nonce));
			byte[] ref = c.doFinal(wire, HDR + 12, n);
			if (ref.length != pay) return "ref=" + ref.length;
			for (int i = 0; i < pay; i++) {
				if (ref[i] != plain[HDR + i]) return "refdif@" + i;
			}
			return null;
		} catch (Throwable t) {
			return "ex:" + t.getClass().getSimpleName();
		}
	}

	/** 0 si no hay libcrypto; si lo hay, la vía usada (1-5). */
	private static native int nativeAvailable();

	/**
	 * Fija el hilo que llama a los núcleos del clúster rápido. En este SoC un
	 * sendto de 1400 B cuesta ~35 us en los A73 y ~80-116 us en los A53, así
	 * que un hilo caliente mal colocado duplica el coste por paquete.
	 *
	 * Devuelve cuántos núcleos se fijaron, o -1 si no se pudo.
	 */
	public static int pinBig() {
		if (!AVAILABLE) return -1;
		try {
			int n = nativePinBig();
			pinStatus = nativePinDiag();
			return n;
		} catch (Throwable t) {
			return -1;
		}
	}

	/** Núcleos elegidos (o el motivo del fallo), para el diagnóstico. */
	public static String pinInfo() {
		return pinStatus;
	}

	/**
	 * Aplica un mapa de CPUs a todos los hilos del proceso.
	 * Acepta "all", "0-5", "6,7". Devuelve el mapa aplicado o null.
	 */
	public static String pinAll(String spec) {
		if (!AVAILABLE || spec == null) return null;
		try {
			return nativePinAll(spec);
		} catch (Throwable t) {
			return null;
		}
	}

	private static native String nativePinAll(String spec);

	private static native int nativePinBig();

	private static native String nativePinDiag();

	/** Motivo del fallo de cada vía intentada. */
	private static native String nativeDiag();

	/**
	 * Cifra in[inOff, inOff+inLen) y escribe cifrado||tag en out[outOff..).
	 * Devuelve los bytes escritos o -1.
	 */
	public static native int seal(byte[] key, byte[] nonce,
	                              byte[] in, int inOff, int inLen,
	                              byte[] out, int outOff);

	/**
	 * Descifra in[inOff, inOff+inLen) (cifrado||tag) y escribe el texto plano
	 * en out[outOff..). Devuelve los bytes escritos o -1 si no autentica.
	 */
	public static native int open(byte[] key, byte[] nonce,
	                              byte[] in, int inOff, int inLen,
	                              byte[] out, int outOff);
}
