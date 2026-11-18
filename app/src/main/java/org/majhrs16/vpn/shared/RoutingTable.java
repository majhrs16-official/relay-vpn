package org.majhrs16.vpn.shared;

import java.net.InetAddress;

/**
 * Tabla de enrutamiento: mapea VIP de nodo -> endpoint UDP, con expiración por inactividad.
 *
 * Las VIP se guardan como int big-endian en una tabla abierta con sondeo lineal,
 * para que el bucle de paquetes no tenga que crear un String ni boxear un Integer
 * por cada datagrama.
 */
public class RoutingTable {

	public static final long DEFAULT_TTL_MS = 15000;

	private static final int INITIAL_CAPACITY = 16;

	public static class Endpoint {
		public final InetAddress address;
		public final int port;
		long lastSeen;

		public Endpoint(InetAddress address, int port) {
			this(address, port, System.currentTimeMillis());
		}

		Endpoint(InetAddress address, int port, long now) {
			this.address = address;
			this.port = port;
			this.lastSeen = now;
		}
	}

	/** 0 nunca es una VIP válida (0.0.0.0), así que sirve de hueco libre. */
	private int[] keys = new int[INITIAL_CAPACITY];
	private Endpoint[] values = new Endpoint[INITIAL_CAPACITY];
	private int size;
	private int mask = INITIAL_CAPACITY - 1;

	private static int hash(int vip) {
		int h = vip * 0x9E3779B1;
		return h ^ (h >>> 16);
	}

	private int find(int vip) {
		int i = hash(vip) & mask;
		while (true) {
			int k = keys[i];
			if (k == 0) return -1;
			if (k == vip) return i;
			i = (i + 1) & mask;
		}
	}

	/** Registra (o refresca) una VIP. Devuelve true si es la primera vez que se ve. */
	public synchronized boolean register(int vip, InetAddress address, int port) {
		long now = System.currentTimeMillis();
		int i = find(vip);
		if (i >= 0) {
			Endpoint existing = values[i];
			if (existing.address.equals(address) && existing.port == port) {
				existing.lastSeen = now;
				return false;
			}
			values[i] = new Endpoint(address, port, now);
			return false;
		}
		if ((size + 1) * 2 > keys.length) grow();
		insert(vip, new Endpoint(address, port, now));
		size++;
		return true;
	}

	public synchronized Endpoint lookup(int vip) {
		int i = find(vip);
		if (i < 0) return null;
		Endpoint ep = values[i];
		ep.lastSeen = System.currentTimeMillis();
		return ep;
	}

	/**
	 * Actualiza las entradas que apuntaban a la dirección anterior del relay (por
	 * ejemplo, tras un cambio de IP) para que sigan siendo válidas. Se compara solo
	 * la dirección porque el puerto de origen puede cambiar por NAT.
	 */
	public synchronized void remap(InetAddress oldAddress, InetAddress newAddress, int newPort) {
		long now = System.currentTimeMillis();
		for (int i = 0; i <= mask; i++) {
			Endpoint ep = values[i];
			if (ep != null && ep.address.equals(oldAddress)) {
				values[i] = new Endpoint(newAddress, newPort, now);
			}
		}
	}

	public synchronized void cleanup(long now) {
		boolean removed = false;
		for (int i = 0; i <= mask; i++) {
			Endpoint ep = values[i];
			if (ep != null && now - ep.lastSeen > DEFAULT_TTL_MS) {
				keys[i] = 0;
				values[i] = null;
				size--;
				removed = true;
			}
		}
		if (removed) rebuild();
	}

	public synchronized int size() {
		return size;
	}

	public synchronized void clear() {
		java.util.Arrays.fill(keys, 0);
		java.util.Arrays.fill(values, null);
		size = 0;
	}

	private void insert(int vip, Endpoint ep) {
		int i = hash(vip) & mask;
		while (keys[i] != 0) {
			i = (i + 1) & mask;
		}
		keys[i] = vip;
		values[i] = ep;
	}

	private void grow() {
		int capacity = keys.length * 2;
		rehash(capacity);
	}

	/** Reconstruye con la misma capacidad; necesario tras borrar para no romper el sondeo. */
	private void rebuild() {
		rehash(keys.length);
	}

	private void rehash(int capacity) {
		int[] oldKeys = keys;
		Endpoint[] oldValues = values;

		keys = new int[capacity];
		values = new Endpoint[capacity];
		mask = capacity - 1;
		size = 0;

		for (int i = 0; i < oldKeys.length; i++) {
			if (oldKeys[i] != 0) {
				insert(oldKeys[i], oldValues[i]);
				size++;
			}
		}
	}
}
