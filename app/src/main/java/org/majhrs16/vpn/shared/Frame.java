package org.majhrs16.vpn.shared;

import java.util.Arrays;

/**
 * Codifica/decodifica los datagramas que viajan por el túnel.
 * El encabezado IPv4 (20 bytes) viaja en claro para que el relay pueda enrutar;
 * el payload es lo que se cifra (AES-256-GCM) cuando hay PSK.
 */
public final class Frame {

	public static final int HEADER_LEN = 20;

	private Frame() {}

	public static boolean isIpv4(byte[] data) {
		return data.length >= HEADER_LEN && (data[0] >> 4) == 4;
	}

	/** Heartbeat: cabecera IPv4 sin payload y sin protocolo (no generada nunca por el kernel). */
	public static boolean isHeartbeat(byte[] data) {
		return isIpv4(data) && (data[9] & 0xFF) == 0;
	}

	private static String dotted(byte[] data, int off) {
		return (data[off] & 0xFF) + "." +
				(data[off + 1] & 0xFF) + "." +
				(data[off + 2] & 0xFF) + "." +
				(data[off + 3] & 0xFF);
	}

	public static String sourceVip(byte[] data) {
		return dotted(data, 12);
	}

	public static String destVip(byte[] data) {
		return dotted(data, 16);
	}

	/** Copia los 20 bytes del encabezado IPv4. */
	public static byte[] header(byte[] data) {
		return Arrays.copyOf(data, HEADER_LEN);
	}

	/** Copia el payload (bytes posteriores al encabezado). */
	public static byte[] payload(byte[] data) {
		return Arrays.copyOfRange(data, HEADER_LEN, data.length);
	}

	/** Une cabecera + payload en un solo paquete IP. */
	public static byte[] assemble(byte[] header, byte[] payload) {
		byte[] out = new byte[header.length + payload.length];
		System.arraycopy(header, 0, out, 0, header.length);
		System.arraycopy(payload, 0, out, header.length, payload.length);
		return out;
	}
}