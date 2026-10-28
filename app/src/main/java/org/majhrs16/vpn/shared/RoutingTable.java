package org.majhrs16.vpn.shared;

import java.net.InetAddress;
import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/** Tabla de enrutamiento: mapea VIP de nodo -> endpoint UDP, con expiración por inactividad. */
public class RoutingTable {

	public static final long DEFAULT_TTL_MS = 15000;

	public static class Endpoint {
		public final InetAddress address;
		public final int port;
		public long lastSeen;

		public Endpoint(InetAddress address, int port) {
			this.address = address;
			this.port = port;
			this.lastSeen = System.currentTimeMillis();
		}

		public void touch() {
			this.lastSeen = System.currentTimeMillis();
		}
	}

	private final ConcurrentHashMap<String, Endpoint> entries = new ConcurrentHashMap<>();

	/** Registra (o refresca) una VIP. Devuelve true si es la primera vez que se ve. */
	public boolean register(String vip, InetAddress address, int port) {
		Endpoint existing = entries.get(vip);
		if (existing != null && existing.address.equals(address) && existing.port == port) {
			existing.touch();
			return false;
		}
		return entries.put(vip, new Endpoint(address, port)) == null;
	}

	public Endpoint lookup(String vip) {
		Endpoint ep = entries.get(vip);
		if (ep != null) {
			ep.touch();
		}
		return ep;
	}

	/**
	 * Actualiza las entradas que apuntaban a la dirección anterior del relay (por
	 * ejemplo, tras un cambio de IP) para que sigan siendo válidas. Se compara solo
	 * la dirección porque el puerto de origen puede cambiar por NAT.
	 */
	public void remap(InetAddress oldAddress, InetAddress newAddress, int newPort) {
		entries.replaceAll((vip, ep) ->
				ep.address.equals(oldAddress)
						? new Endpoint(newAddress, newPort)
						: ep);
	}

	public void cleanup(long now) {
		Iterator<Map.Entry<String, Endpoint>> it = entries.entrySet().iterator();
		while (it.hasNext()) {
			if (now - it.next().getValue().lastSeen > DEFAULT_TTL_MS) {
				it.remove();
			}
		}
	}

	public int size() {
		return entries.size();
	}

	public void clear() {
		entries.clear();
	}
}