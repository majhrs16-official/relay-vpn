package org.majhrs16.vpn.shared;

/**
 * Codifica/decodifica los datagramas que viajan por el túnel.
 * El encabezado IPv4 (20 bytes) viaja en claro para que el relay pueda enrutar;
 * el payload es lo que se cifra (AES-256-GCM) cuando hay PSK.
 *
 * Las variantes con (byte[], int length) y las VIP empaquetadas en un int
 * existen para el bucle de paquetes: no reservan memoria por paquete.
 */
public final class Frame {

	public static final int HEADER_LEN = 20;
	/** Offset de la IP origen dentro del encabezado IPv4. */
	public static final int SRC_OFFSET = 12;
	/** Offset de la IP destino dentro del encabezado IPv4. */
	public static final int DST_OFFSET = 16;

	private Frame() {}

	public static boolean isIpv4(byte[] data) {
		return data.length >= HEADER_LEN && (data[0] >> 4) == 4;
	}

	public static boolean isIpv4(byte[] data, int length) {
		return length >= HEADER_LEN && (data[0] >> 4) == 4;
	}

	/** Heartbeat: cabecera IPv4 sin payload y sin protocolo (no generada nunca por el kernel). */
	public static boolean isHeartbeat(byte[] data) {
		return isIpv4(data) && (data[9] & 0xFF) == 0;
	}
	public static boolean isHeartbeat(byte[] data, int length) {
		return isIpv4(data, length) && (data[9] & 0xFF) == 0;
	}

	/**
	 * Hash del flujo de un paquete IP en claro: protocolo, IPs y puertos.
	 *
	 * Se usa para repartir paquetes entre hilos sin desordenar ningún flujo:
	 * todos los paquetes de la misma conexión TCP dan el mismo valor y acaban
	 * siempre en el mismo hilo, pero conexiones distintas van a hilos distintos.
	 */
	public static int flowHash(byte[] data, int length) {
		int h = mix(0x811C9DC5, data[9] & 0xFF);
		h = mix(h, vip(data, SRC_OFFSET));
		h = mix(h, vip(data, DST_OFFSET));
		/* Los puertos sólo son legibles si la cabecera no lleva opciones. */
		if ((data[0] & 0x0F) == 5 && length >= HEADER_LEN + 4) {
			h = mix(h, vip(data, HEADER_LEN));
		}
		return h;
	}

	/**
	 * Igual, pero para un datagrama del cable: el payload va cifrado, así que
	 * sólo puede mirarse lo que viaja en claro (protocolo y par de IPs).
	 */
	public static int flowHashWire(byte[] data, int length) {
		int h = mix(0x811C9DC5, data[9] & 0xFF);
		h = mix(h, vip(data, SRC_OFFSET));
		return mix(h, vip(data, DST_OFFSET));
	}

	private static int mix(int h, int value) {
		h ^= value;
		h *= 0x9E3779B1;
		h ^= h >>> 15;
		return h;
	}

	/** Lee una IPv4 como entero big-endian (10.42.0.1 -> 0x0A2A0001). */
	public static int vip(byte[] data, int offset) {
		return ((data[offset] & 0xFF) << 24)
				| ((data[offset + 1] & 0xFF) << 16)
				| ((data[offset + 2] & 0xFF) << 8)
				| (data[offset + 3] & 0xFF);
	}

	/** Empaqueta los 4 bytes de una IPv4 en un entero big-endian. */
	public static int pack(byte[] address) {
		if (address == null || address.length < 4) return 0;
		return ((address[0] & 0xFF) << 24)
				| ((address[1] & 0xFF) << 16)
				| ((address[2] & 0xFF) << 8)
				| (address[3] & 0xFF);
	}

	/** Convierte "a.b.c.d" en entero big-endian; 0 si no es una IPv4 válida. */
	public static int parseVip(String ip) {
		if (ip == null) return 0;
		String s = ip.trim();
		int result = 0;
		int octets = 0;
		int value = 0;
		boolean digit = false;
		for (int i = 0; i < s.length(); i++) {
			char c = s.charAt(i);
			if (c == '.') {
				if (!digit || octets == 3) return 0;
				result = (result << 8) | (value & 0xFF);
				octets++;
				value = 0;
				digit = false;
			} else if (c >= '0' && c <= '9') {
				value = value * 10 + (c - '0');
				if (value > 255) return 0;
				digit = true;
			} else {
				return 0;
			}
		}
		if (!digit || octets != 3) return 0;
		return (result << 8) | (value & 0xFF);
	}

	/** Formatea una VIP empaquetada; solo para logs. */
	public static String vipToString(int vip) {
		return ((vip >>> 24) & 0xFF) + "." +
				((vip >>> 16) & 0xFF) + "." +
				((vip >>> 8) & 0xFF) + "." +
				(vip & 0xFF);
	}

	private static String dotted(byte[] data, int off) {
		return (data[off] & 0xFF) + "." +
				(data[off + 1] & 0xFF) + "." +
				(data[off + 2] & 0xFF) + "." +
				(data[off + 3] & 0xFF);
	}

	public static String sourceVip(byte[] data) {
		return dotted(data, SRC_OFFSET);
	}

	public static String destVip(byte[] data) {
		return dotted(data, DST_OFFSET);
	}

	/** Copia los 20 bytes del encabezado IPv4. */
	public static byte[] header(byte[] data) {
		return java.util.Arrays.copyOf(data, HEADER_LEN);
	}

	/** Copia el payload (bytes posteriores al encabezado). */
	public static byte[] payload(byte[] data) {
		return java.util.Arrays.copyOfRange(data, HEADER_LEN, data.length);
	}

	/** Une cabecera + payload en un solo paquete IP. */
	public static byte[] assemble(byte[] header, byte[] payload) {
		byte[] out = new byte[header.length + payload.length];
		System.arraycopy(header, 0, out, 0, header.length);
		System.arraycopy(payload, 0, out, header.length, payload.length);
		return out;
	}
}
