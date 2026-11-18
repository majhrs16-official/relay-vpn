package org.majhrs16.vpn.service;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.content.Intent;
import android.net.VpnService;
import android.os.Build;
import android.os.Handler;
import android.os.Looper;
import android.os.ParcelFileDescriptor;
import android.system.Os;
import android.system.OsConstants;
import android.util.Log;
import android.widget.Toast;

import androidx.core.app.NotificationCompat;

import org.majhrs16.vpn.R;
import org.majhrs16.vpn.data.Config;
import org.majhrs16.vpn.shared.CryptoUtils;
import org.majhrs16.vpn.shared.FlowPool;
import org.majhrs16.vpn.shared.Frame;
import org.majhrs16.vpn.shared.LogConfig;
import org.majhrs16.vpn.shared.NativeCrypto;
import org.majhrs16.vpn.shared.NodeLog;
import org.majhrs16.vpn.shared.RoutingTable;

import java.io.File;
import java.io.FileDescriptor;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.InterfaceAddress;
import java.net.NetworkInterface;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.Locale;

import javax.crypto.SecretKey;

public class VPNService extends VpnService {
	private static final String TAG = "VPNService";
	private static final String CHANNEL_ID = "vpn_tunnel_channel";
	/** Cada cuánto se re-resuelve el dominio del relay para detectar cambios de IP. */
	private static final long RELAY_ADDRESS_CHECK_MS = 5000;
	/** MTU del túnel: deja margen para el sobre UDP+GCM (1428 B) sin fragmentar el enlace. */
	private static final int TUN_MTU = 1400;

	private static final int MAX_PACKET = 32767;
	private static final int MAX_WIRE = MAX_PACKET + CryptoUtils.OVERHEAD;
	private static final int SOCKET_BUFFER = 4 * 1024 * 1024;

	private volatile boolean isRunning = false;
	private Thread workerThread;
	private volatile DatagramSocket udpSocket;
	private volatile DatagramSocket clientSocket;
	private volatile InetSocketAddress relayAddr;
	private volatile boolean clientMode = false;
	private volatile ParcelFileDescriptor vpnInterface;
	private volatile Config config;
	private volatile String overlayIp;
	private volatile int overlayIpInt;
	private volatile SecretKey pskKey;
	/** Misma clave que pskKey, ya codificada, para la ruta nativa (JNI). */
	private volatile byte[] pskBytes;
	/** Último aviso de descarte y cuántos se han agrupado desde entonces. */
	private long dropLogAt;
	private int dropLogCount;
	/** Direcciones IPv4 de este nodo: su VIP y todas las interfaces activas. */
	private volatile int[] localVips = new int[0];
	private FileOutputStream tunOut;

	private final RoutingTable routingTable = new RoutingTable();

	// --- Diagnóstico temporal de rendimiento (se retira al cerrar la optimización) ---
	// Ahora los incrementan varios hilos a la vez, así que son atómicos.
	private final java.util.concurrent.atomic.AtomicLong dTunIn = new java.util.concurrent.atomic.AtomicLong();
	private final java.util.concurrent.atomic.AtomicLong dUdpIn = new java.util.concurrent.atomic.AtomicLong();
	private final java.util.concurrent.atomic.AtomicLong dEncNanos = new java.util.concurrent.atomic.AtomicLong();
	private final java.util.concurrent.atomic.AtomicLong dEncCount = new java.util.concurrent.atomic.AtomicLong();
	private final java.util.concurrent.atomic.AtomicLong dSendTunNanos = new java.util.concurrent.atomic.AtomicLong();
	private final java.util.concurrent.atomic.AtomicLong dSendTunCount = new java.util.concurrent.atomic.AtomicLong();
	private final java.util.concurrent.atomic.AtomicLong dDecNanos = new java.util.concurrent.atomic.AtomicLong();
	private final java.util.concurrent.atomic.AtomicLong dDecCount = new java.util.concurrent.atomic.AtomicLong();
	private final java.util.concurrent.atomic.AtomicLong dInjNanos = new java.util.concurrent.atomic.AtomicLong();
	private final java.util.concurrent.atomic.AtomicLong dInjCount = new java.util.concurrent.atomic.AtomicLong();
	private final java.util.concurrent.atomic.AtomicLong dFwdNanos = new java.util.concurrent.atomic.AtomicLong();
	private final java.util.concurrent.atomic.AtomicLong dFwdCount = new java.util.concurrent.atomic.AtomicLong();

	/**
	 * Reparto de paquetes entre núcleos: un hilo hace la lectura/recepción y
	 * varios se encargan de cifrar, enviar e inyectar, siempre por flujo para
	 * no desordenar ninguna conexión.
	 */
	private volatile FlowPool uploadPool;
	private volatile FlowPool relayPool;
	private volatile FlowPool clientPool;
	/** Firma del reparto activo, para no recrear hilos en cada relectura. */
	private volatile String poolSignature = "";
	/** Último mapa de CPUs aplicado a mano (pool.txt: cpu=...). */
	private volatile String cpuSignature = "";
	/** Buffers de salida por hilo: el cifrado ya no ocurre sólo en el lector. */
	private final ThreadLocal<byte[]> wireScratch =
			ThreadLocal.withInitial(() -> new byte[MAX_WIRE]);
	private final ThreadLocal<byte[]> plainScratch =
			ThreadLocal.withInitial(() -> new byte[MAX_PACKET]);
	private final ThreadLocal<DatagramPacket> sendScratch =
			ThreadLocal.withInitial(() -> new DatagramPacket(new byte[0], 0));

	@Override
	public int onStartCommand(Intent intent, int flags, int startId) {
		if (intent != null && "ACTION_STOP_VPN".equals(intent.getAction())) {
			stopNode();
			return START_NOT_STICKY;
		}

		config = Config.load(this);
		createNotificationChannel();
		boolean usePsk = config.psk != null && !config.psk.trim().isEmpty();
		String statusText = usePsk ? "Servicio activo (cifrado AES-256-GCM)" : "Servicio activo (sin cifrado)";
		Notification notification = new NotificationCompat.Builder(this, CHANNEL_ID)
				.setContentTitle(getString(R.string.notification_title))
				.setContentText(statusText)
				.setSmallIcon(R.drawable.ic_launcher)
				.build();

		startForeground(1, notification);
		initLogFile();
		startVpnTunnel();

		return START_STICKY;
	}

	/** Deja el registro de esta sesión en Android/media/&lt;pkg&gt;/log.txt. */
	private void initLogFile() {
		File[] dirs = getExternalMediaDirs();
		org.majhrs16.vpn.shared.NodeLog.initFile(dirs != null && dirs.length > 0 ? dirs[0] : null);
	}

	private void startVpnTunnel() {
		if (isRunning) return;
		isRunning = true;

		try {
			overlayIp = config.nodeVirtualIp;
			overlayIpInt = Frame.parseVip(overlayIp);

			pskKey = null;
			pskBytes = null;
			if (config.psk != null && !config.psk.trim().isEmpty()) {
				try {
					pskKey = CryptoUtils.deriveKey(config.psk);
					pskBytes = pskKey.getEncoded();
					NodeLog.i(TAG, "Cifrado PSK activo (AES-256-GCM, "
							+ (NativeCrypto.isAvailable() ? "nativo" : "Conscrypt") + ").");
				} catch (Exception e) {
					pskKey = null;
					pskBytes = null;
					NodeLog.e(TAG, "No se pudo derivar la clave PSK: " + e.getMessage());
				}
			}
			if (pskKey == null) {
				NodeLog.w(TAG, "Sin PSK: tráfico en claro por la red.");
			}

			showToast("IP virtual del relay: " + overlayIp + "/" + config.nodePrefix);

			Builder builder = new Builder();
			builder.addAddress(overlayIp, config.nodePrefix);

			// Cálculo dinámico de la subred para evitar secuestrar el internet general del teléfono
			String networkAddress = getNetworkAddress(overlayIp, config.nodePrefix);
			builder.addRoute(networkAddress, config.nodePrefix);
			// Evita que el datagrama exterior (MTU + 20 IP + 8 UDP) se fragmente en el enlace.
			builder.setMtu(TUN_MTU);

			builder.setSession("vpn-tunnel");

			vpnInterface = builder.establish();
			if (vpnInterface == null) {
				throw new IllegalStateException("Permiso de VPN rechazado o no disponible");
			}

			// Android entrega el fd del TUN en modo no bloqueante: read() devuelve 0
			// (EAGAIN) en vez de esperar, y un bucle de lectura "leer y continuar"
			// gira al 100% de CPU sin aportar nada. Lo pasamos a bloqueante para que
			// el hilo duerma hasta que el kernel tenga un paquete que entregar.
			try {
				FileDescriptor tunFd = vpnInterface.getFileDescriptor();
				int flags = Os.fcntlInt(tunFd, OsConstants.F_GETFL, 0);
				if ((flags & OsConstants.O_NONBLOCK) != 0) {
					Os.fcntlInt(tunFd, OsConstants.F_SETFL, flags & ~OsConstants.O_NONBLOCK);
					NodeLog.i(TAG, "TUN en modo bloqueante (O_NONBLOCK desactivado)");
				}
			} catch (Exception e) {
				NodeLog.w(TAG, "No se pudo poner el TUN en bloqueante: " + e.getMessage());
			}

			// Un único stream de salida para todo el servicio: abrir/cerrar uno por
			// paquete era coste puro y arriesgaba cerrar el descriptor del TUN.
			tunOut = new FileOutputStream(vpnInterface.getFileDescriptor());

			clientMode = isClientMode();

			udpSocket = openSocket(new InetSocketAddress(config.serverPort));
			refreshLocalVips();
			String publicIp = findPublicIpv4();
			showToast("Relay en " + (publicIp != null ? publicIp : "0.0.0.0") + ":" + config.serverPort);
			NodeLog.i(TAG, "Relay iniciado. IP virtual: " + overlayIp + "/" + config.nodePrefix);
			NodeLog.i(TAG, "Escuchando en 0.0.0.0:" + config.serverPort
					+ " (IP pública detectada: " + (publicIp != null ? publicIp : "no detectada") + ")");

			if (clientMode) {
				clientSocket = openSocket(null);
				try {
					relayAddr = resolveRelayAddress(config.serverHost.trim(), config.serverPortNode);
				} catch (Exception e) {
					relayAddr = InetSocketAddress.createUnresolved(
							config.serverHost.trim(), config.serverPortNode);
					NodeLog.w(TAG, "No se pudo resolver el relay al iniciar: " + e.getMessage()
							+ " (se reintentará cada 5 s)");
				}
				showToast("Relay remoto: " + config.serverHost + ":" + config.serverPortNode);
				NodeLog.i(TAG, "Modo cliente. Relay remoto: " + config.serverHost + ":" + config.serverPortNode);
			}

			showToast("¡Relay y TUN iniciados!");
			NodeLog.i(TAG, "TUN y hilos de trabajo iniciados.");

			workerThread = new Thread(this::runVpnLoop, "vpn-tun-reader");
			workerThread.start();

		} catch (Exception e) {
			Log.e(TAG, "Error: " + e.getMessage(), e);
			NodeLog.e(TAG, "Error al iniciar VPN: " + e.getMessage(), e);
			showToast("Error al iniciar VPN: " + e.getMessage());
			stopNode();
		}
	}

	/** Socket UDP con buffers grandes: el tráfico de todos los peers comparte este buffer. */
	private DatagramSocket openSocket(InetSocketAddress bind) throws Exception {
		DatagramSocket socket = new DatagramSocket((InetSocketAddress) null);
		socket.setReuseAddress(true);
		try { socket.setReceiveBufferSize(SOCKET_BUFFER); } catch (Exception ignored) {}
		try { socket.setSendBufferSize(SOCKET_BUFFER); } catch (Exception ignored) {}
		if (bind != null) socket.bind(bind);
		return socket;
	}

	/** Recalcula las IPv4 locales (VIP del túnel + interfaces activas). */
	private void refreshLocalVips() {
		List<Integer> vips = new ArrayList<>();
		int overlay = overlayIpInt;
		if (overlay != 0) vips.add(overlay);
		try {
			Enumeration<NetworkInterface> nis = NetworkInterface.getNetworkInterfaces();
			while (nis != null && nis.hasMoreElements()) {
				NetworkInterface ni = nis.nextElement();
				if (ni.isLoopback() || !ni.isUp()) continue;
				for (InterfaceAddress ia : ni.getInterfaceAddresses()) {
					InetAddress addr = ia.getAddress();
					if (!(addr instanceof Inet4Address)) continue;
					int vip = Frame.pack(addr.getAddress());
					if (vip != 0 && !vips.contains(vip)) vips.add(vip);
				}
			}
		} catch (Exception e) {
			NodeLog.w(TAG, "No se pudieron enumerar las interfaces: " + e.getMessage());
		}

		int[] out = new int[vips.size()];
		for (int i = 0; i < out.length; i++) out[i] = vips.get(i);
		localVips = out;
	}

	private boolean isLocalVip(int vip) {
		int[] vips = localVips;
		for (int v : vips) {
			if (v == vip) return true;
		}
		return false;
	}

	/** Cifra un paquete IP de salida en un buffer propio; devuelve la longitud o -1. */
	private int wrapOutbound(byte[] ipPacket, int length, byte[] wire) {
		int payloadLen = length - Frame.HEADER_LEN;
		if (payloadLen < 0) return -1;
		int n = CryptoUtils.encrypt(ipPacket, Frame.HEADER_LEN, payloadLen, wire, Frame.HEADER_LEN, pskKey, pskBytes);
		if (n < 0) {
			NodeLog.e(TAG, "Error cifrando salida");
			return -1;
		}
		System.arraycopy(ipPacket, 0, wire, 0, Frame.HEADER_LEN);
		return Frame.HEADER_LEN + n;
	}

	/** Variante que reserva memoria; solo para el heartbeat (cada 3 s). */
	private byte[] wrapOutbound(byte[] ipPacket) {
		if (pskKey == null) return ipPacket;
		int payloadLen = ipPacket.length - Frame.HEADER_LEN;
		if (payloadLen < 0) return null;
		byte[] wire = new byte[Frame.HEADER_LEN + payloadLen + CryptoUtils.OVERHEAD];
		int n = wrapOutbound(ipPacket, ipPacket.length, wire);
		return n < 0 ? null : wire;
	}

	/**
	 * Descifra un datagrama entrante sobre buffers reutilizados.
	 * Devuelve la longitud del paquete IP resultante o -1 si falla.
	 */
	private int unwrapInbound(byte[] wire, int length, byte[] plain) {
		if (!Frame.isIpv4(wire, length)) return -1;
		if (pskKey == null) {
			System.arraycopy(wire, 0, plain, 0, length);
			return length;
		}
		int n = CryptoUtils.decrypt(wire, Frame.HEADER_LEN, length - Frame.HEADER_LEN,
				plain, Frame.HEADER_LEN, pskKey, pskBytes);
		if (n < 0) return -1;
		System.arraycopy(wire, 0, plain, 0, Frame.HEADER_LEN);
		return Frame.HEADER_LEN + n;
	}

	private String getNetworkAddress(String ip, int prefix) {
		try {
			InetAddress inetAddress = InetAddress.getByName(ip);
			byte[] bytes = inetAddress.getAddress();
			int mask = 0xFFFFFFFF << (32 - prefix);
			int ipInt = ((bytes[0] & 0xFF) << 24) |
						((bytes[1] & 0xFF) << 16) |
						((bytes[2] & 0xFF) << 8) |
						(bytes[3] & 0xFF);
			int networkInt = ipInt & mask;

			return ((networkInt >> 24) & 0xFF) + "." +
				   ((networkInt >> 16) & 0xFF) + "." +
				   ((networkInt >> 8) & 0xFF) + "." +
				   (networkInt & 0xFF);
		} catch (Exception e) {
			int lastDot = ip.lastIndexOf('.');
			return (lastDot != -1) ? ip.substring(0, lastDot + 1) + "0" : "10.42.0.0";
		}
	}

	private String findPublicIpv4() {
		try {
			Enumeration<NetworkInterface> nis = NetworkInterface.getNetworkInterfaces();
			while (nis.hasMoreElements()) {
				NetworkInterface ni = nis.nextElement();
				if (ni.isLoopback() || !ni.isUp()) continue;
				Enumeration<InetAddress> addrs = ni.getInetAddresses();
				while (addrs.hasMoreElements()) {
					InetAddress addr = addrs.nextElement();
					if (addr instanceof Inet4Address
							&& !addr.isLoopbackAddress()
							&& !isPrivateIpv4(addr.getHostAddress())) {
						return addr.getHostAddress();
					}
				}
			}
		} catch (Exception e) {
			NodeLog.e(TAG, "Error buscando IP pública: " + e.getMessage());
		}
		return null;
	}

	private boolean isPrivateIpv4(String ip) {
		try {
			String[] p = ip.split("\\.");
			if (p.length != 4) return true;
			int a = Integer.parseInt(p[0]);
			int b = Integer.parseInt(p[1]);
			if (a == 10) return true;
			if (a == 172 && b >= 16 && b <= 31) return true;
			if (a == 192 && b == 168) return true;
			if (a == 100 && b >= 64 && b <= 127) return true;
			if (a == 169 && b == 254) return true;
			if (a == 127) return true;
			return false;
		} catch (Exception e) {
			return true;
		}
	}

	private static final byte[] PONG_TAG = {'P', 'O', 'N', 'G'};

	private void sendPong(InetAddress from, int fromPort) {
		try {
			byte[] lan = InetAddress.getByName(findPongLanIp(from)).getAddress();
			byte[] pong = new byte[8];
			System.arraycopy(PONG_TAG, 0, pong, 0, 4);
			System.arraycopy(lan, 0, pong, 4, 4);
			DatagramSocket socket = udpSocket;
			if (socket == null || socket.isClosed()) return;
			socket.send(new DatagramPacket(pong, pong.length, from, fromPort));
		} catch (Exception e) {
			NodeLog.e(TAG, "Error PONG: " + e.getMessage());
		}
	}

	private String findPongLanIp(InetAddress from) {
		try {
			Enumeration<NetworkInterface> nis = NetworkInterface.getNetworkInterfaces();
			String fallback = null;
			while (nis.hasMoreElements()) {
				NetworkInterface ni = nis.nextElement();
				if (ni.isLoopback() || !ni.isUp()) continue;
				for (InterfaceAddress ia : ni.getInterfaceAddresses()) {
					InetAddress addr = ia.getAddress();
					if (!(addr instanceof Inet4Address) || addr.isLoopbackAddress()) continue;
					String ip = addr.getHostAddress();
					if (!isPrivateIpv4(ip) || ip.equals(overlayIp)) continue;
					if ((from instanceof Inet4Address)
							&& sameSubnet((Inet4Address) addr, (Inet4Address) from, ia.getNetworkPrefixLength())) {
						return ip;
					}
					if (fallback == null) fallback = ip;
					else if (ip.startsWith("192.168.") && !fallback.startsWith("192.168.")) fallback = ip;
				}
			}
			if (fallback != null) return fallback;
		} catch (Exception e) {
			NodeLog.e(TAG, "Error buscando IP LAN: " + e.getMessage());
		}
		return overlayIp;
	}

	private boolean sameSubnet(Inet4Address a, Inet4Address b, short prefix) {
		byte[] x = a.getAddress(), y = b.getAddress();
		for (int i = 0; i < 4; i++) {
			int bits = Math.min(8, Math.max(0, prefix - i * 8));
			int mask = bits == 0 ? 0 : (0xFF << (8 - bits)) & 0xFF;
			if ((x[i] & mask) != (y[i] & mask)) return false;
		}
		return true;
	}

	private void runVpnLoop() {
		applyPoolConfig(true);

		if (clientMode) {
			Thread heartbeatThread = new Thread(this::clientHeartbeatLoop, "vpn-heartbeat");
			heartbeatThread.start();
			Thread clientReceiverThread = new Thread(this::clientReceiverLoop, "vpn-client-receiver");
			clientReceiverThread.start();
			Thread relayAddressThread = new Thread(this::clientRelayAddressLoop, "vpn-relay-address");
			relayAddressThread.start();
		}

		Thread cleanupThread = new Thread(this::tableCleanupLoop, "vpn-table-cleanup");
		cleanupThread.start();

		Thread diagThread = new Thread(this::diagLoop, "vpn-diag");
		diagThread.setDaemon(true);
		diagThread.start();

		// Hilo 1: Recibir UDP externo y repartir a los hilos de proceso
		Thread receiverThread = new Thread(() -> {
			NodeLog.i(TAG, "Receptor UDP en afinidad libre.");
			byte[] buffer = new byte[MAX_PACKET];
			DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
			while (isRunning) {
				try {
					DatagramSocket socket = udpSocket;
					if (socket == null || socket.isClosed()) break;
					socket.receive(packet);
					dUdpIn.incrementAndGet();
					int length = packet.getLength();
					InetAddress from = packet.getAddress();
					int fromPort = packet.getPort();
					if (!dispatchInbound(relayPool, buffer, length, from, fromPort)) {
						handleUdpPacket(buffer, length, from, fromPort);
					}
				} catch (Exception e) {
					if (!isRunning) break;
					NodeLog.e(TAG, "Error en receive UDP: " + e.getMessage());
				}
			}
		}, "vpn-udp-receiver");
		receiverThread.start();

		// Hilo 2: Leer desde TUN de Android y repartir a los hilos de proceso
		try {
			NodeLog.i(TAG, "Lector TUN en afinidad libre.");
			FileInputStream in = new FileInputStream(vpnInterface.getFileDescriptor());
			byte[] buffer = new byte[MAX_PACKET];
			int emptyReads = 0;
			while (isRunning) {
				int length = in.read(buffer);
				if (length <= 0) {
					// Red de seguridad: si el fd siguiera en modo no bloqueante,
					// no girar en vacío esperando paquetes.
					if (length < 0) break;
					if (++emptyReads > 1000) {
						emptyReads = 0;
						Thread.sleep(1);
					}
					continue;
				}
				emptyReads = 0;
				if (!Frame.isIpv4(buffer, length)) continue;
				dTunIn.incrementAndGet();

				FlowPool pool = uploadPool;
				if (pool == null || !pool.submit(buffer, 0, length,
						Frame.flowHash(buffer, length), null, 0)) {
					processOutbound(buffer, length);
				}
			}
		} catch (Exception e) {
			if (isRunning) NodeLog.e(TAG, "Error en TUN reader: " + e.getMessage());
		}
	}

	/**
	 * Crea (o retira) los hilos que procesan paquetes. Los valores por defecto
	 * (2 de subida, 4 de bajada) son los que mejor rindieron midiendo sobre el
	 * enlace USB: con menos, la cola del TUN desborda; con más, los hilos se
	 * pelean por los núcleos. El número sale de pool.txt si está; se relee cada
	 * pocos segundos para poder ajustar sin recompilar.
	 */
	private void applyPoolConfig(boolean force) {
		int up = 2;
		int down = 4;
		boolean pin = false;
		String cpu = null;
		try {
			File[] dirs = getExternalMediaDirs();
			if (dirs != null && dirs.length > 0 && dirs[0] != null) {
				File f = new File(dirs[0], "pool.txt");
				if (f.isFile()) {
					String text = new String(java.nio.file.Files.readAllBytes(f.toPath()),
							java.nio.charset.StandardCharsets.US_ASCII);
					/* Se parte sólo por espacios: el valor de cpu= puede llevar comas
						   (cpu=6,7) o guiones (cpu=6-7). */
					for (String token : text.split("\\s+")) {
						String t = token.trim().toLowerCase(Locale.US);
						while (t.endsWith(",") || t.endsWith(";")) {
							t = t.substring(0, t.length() - 1);
						}
						try {
							if (t.startsWith("up=")) up = Integer.parseInt(t.substring(3));
							else if (t.startsWith("down=")) down = Integer.parseInt(t.substring(5));
							else if (t.startsWith("pin=")) pin = t.endsWith("big");
							else if (t.startsWith("cpu=")) cpu = t.substring(4);
						} catch (NumberFormatException ignored) {
						}
					}
				}
			}
		} catch (Throwable ignored) {
			/* el ajuste manual es opcional */
		}
		if (up < 0) up = 0;
		if (down < 0) down = 0;
		if (up > 8) up = 8;
		if (down > 8) down = 8;

		/* Mapa de CPUs en vivo: "all", "0-5", "6,7". Sirve para comparar
		   colocaciones sin reinstalar; ausente = sin fijar (lo mejor medido). */
		if (cpu != null && !cpu.equals(cpuSignature)) {
			cpuSignature = cpu;
			String applied = NativeCrypto.pinAll(cpu);
			NodeLog.i(TAG, "CPUs manuales " + cpu + " -> " + applied
					+ " (" + NativeCrypto.pinInfo() + ")");
		}

		String signature = up + "/" + down + "/" + (pin ? "big" : "libre");
		if (!force && signature.equals(poolSignature)) return;
		poolSignature = signature;

		FlowPool oldUp = uploadPool, oldDown = relayPool, oldClient = clientPool;
		uploadPool = up > 0 ? new FlowPool("vpn-up", up, this::onUploadPacket, pin) : null;
		relayPool = down > 0 ? new FlowPool("vpn-down", down, this::onRelayPacket, pin) : null;
		clientPool = down > 0 && clientMode
				? new FlowPool("vpn-client", down, this::onClientPacket, pin) : null;
		if (oldUp != null) oldUp.stop();
		if (oldDown != null) oldDown.stop();
		if (oldClient != null) oldClient.stop();
		NodeLog.i(TAG, "Reparto por flujos: " + signature
				+ (up == 0 && down == 0 ? " (sin hilos: se procesa en el lector)" : ""));
	}

	/** Texto para el diagnóstico: reparto activo. */
	private String poolMode() {
		return "up" + (uploadPool == null ? 0 : uploadPool.size())
				+ "/dn" + (relayPool == null ? 0 : relayPool.size());
	}

	/** Hilo de subida: cifra el paquete del TUN y lo manda a su nodo. */
	private void onUploadPacket(byte[] data, int length, Object tag, int aux, int worker) {
		try {
			processOutbound(data, length);
		} catch (Exception e) {
			NodeLog.e(TAG, "Error enviando paquete: " + e.getMessage());
		}
	}

	/** Hilo de bajada del relay: descifra e inyecta, o reenvía a otro nodo. */
	private void onRelayPacket(byte[] data, int length, Object tag, int aux, int worker) {
		try {
			handleUdpPacket(data, length, (InetAddress) tag, aux);
		} catch (Exception e) {
			NodeLog.e(TAG, "Error procesando UDP: " + e.getMessage());
		}
	}

	/** Hilo de bajada del cliente: lo que llega del relay remoto. */
	private void onClientPacket(byte[] data, int length, Object tag, int aux, int worker) {
		try {
			handleClientPacket(data, length, (InetAddress) tag, aux);
		} catch (Exception e) {
			NodeLog.e(TAG, "Error procesando paquete del relay: " + e.getMessage());
		}
	}

	/**
	 * Manda un datagrama a un hilo de proceso. Devuelve false si ese hilo va
	 * saturado (o el paquete no es IP), en cuyo caso lo procesa el llamante.
	 */
	private boolean dispatchInbound(FlowPool pool, byte[] buffer, int length,
	                                InetAddress from, int fromPort) {
		if (pool == null) return false;
		int flow = Frame.isIpv4(buffer, length)
				? Frame.flowHashWire(buffer, length)
				: fromPort;
		return pool.submit(buffer, 0, length, flow, from, fromPort);
	}

	/**
	 * Cifra un paquete del TUN y lo envía al nodo destino (o al relay si este
	 * teléfono actúa de cliente). Se ejecuta en los hilos del pool, así que
	 * usa buffers propios de cada hilo.
	 */
	private void processOutbound(byte[] buffer, int length) {
		int destVip = Frame.vip(buffer, Frame.DST_OFFSET);

		byte[] payload;
		int wireLen;
		if (pskKey == null) {
			payload = buffer;
			wireLen = length;
		} else {
			byte[] wire = wireScratch.get();
			long tEnc = System.nanoTime();
			wireLen = wrapOutbound(buffer, length, wire);
			dEncNanos.addAndGet(System.nanoTime() - tEnc);
			dEncCount.incrementAndGet();
			if (wireLen < 0) return;
			payload = wire;
		}

		RoutingTable.Endpoint destEndpoint = routingTable.lookup(destVip);
		if (destEndpoint != null) {
			DatagramPacket out = sendScratch.get();
			out.setData(payload, 0, wireLen);
			out.setAddress(destEndpoint.address);
			out.setPort(destEndpoint.port);
			DatagramSocket socket = udpSocket;
			if (socket == null || socket.isClosed()) return;
			long tSend = System.nanoTime();
			try {
				socket.send(out);
			} catch (Exception e) {
				if (isRunning) NodeLog.e(TAG, "Error enviando al nodo: " + e.getMessage());
				return;
			}
			dSendTunNanos.addAndGet(System.nanoTime() - tSend);
			dSendTunCount.incrementAndGet();
		} else if (clientMode) {
			InetSocketAddress relay = relayAddr;
			DatagramSocket socket = clientSocket;
			if (relay != null && !relay.isUnresolved() && socket != null && !socket.isClosed()) {
				DatagramPacket out = sendScratch.get();
				out.setData(payload, 0, wireLen);
				out.setSocketAddress(relay);
				try {
					socket.send(out);
				} catch (Exception e) {
					if (isRunning) NodeLog.e(TAG, "Error enviando al relay: " + e.getMessage());
				}
			}
		}
	}

	/**
	 * Relay: si el destino es este nodo se descifra y se entrega; si es otro nodo
	 * se reenvía el datagrama tal cual, sin pagar el coste de descifrarlo solo
	 * para leer una cabecera IPv4 que ya viaja en claro.
	 */
	/**
	 * El puerto del relay está expuesto (también a internet), así que llegan
	 * datagramas ajenos al túnel. Sin límite, cuatro paquetes de basura llenan
	 * el log de la app; aquí se agrupan y se informa como mucho cada 5 s.
	 */
	private synchronized void logDrop(String reason, InetAddress from, int fromPort, int length) {
		dropLogCount++;
		long now = System.currentTimeMillis();
		if (now - dropLogAt < 5000) return;
		String extra = dropLogCount > 1 ? " (+" + (dropLogCount - 1) + " más en 5 s)" : "";
		NodeLog.w(TAG, reason + " de " + from.getHostAddress() + ":"
				+ fromPort + " (" + length + " bytes)" + extra);
		dropLogAt = now;
		dropLogCount = 0;
	}

	private void handleUdpPacket(byte[] buffer, int length, InetAddress from, int fromPort) {
		try {
			/* PONG: 8 bytes con la IP LAN del relay para el descubrimiento de
			   ruta. No es tráfico IP; el cliente Linux también lo ignora en
			   silencio en su bucle principal. */
			if (length >= 8 && buffer[0] == 'P' && buffer[1] == 'O'
					&& buffer[2] == 'N' && buffer[3] == 'G') {
				return;
			}

			if (!Frame.isIpv4(buffer, length)) {
				logDrop("Paquete no IPv4 descartado", from, fromPort, length);
				return;
			}
			if (pskKey != null && length < Frame.HEADER_LEN + CryptoUtils.OVERHEAD) {
				logDrop("Paquete demasiado corto descartado", from, fromPort, length);
				return;
			}

			int srcVip = Frame.vip(buffer, Frame.SRC_OFFSET);
			int destVip = Frame.vip(buffer, Frame.DST_OFFSET);

			// Actualizar la tabla de rutas dinámicamente con el origen del paquete
			if (routingTable.register(srcVip, from, fromPort)) {
				NodeLog.i(TAG, "Nuevo nodo registrado: " + Frame.vipToString(srcVip) + " @ "
						+ from.getHostAddress() + ":" + fromPort);
			}

			if (isLocalVip(destVip)) {
				byte[] plain = plainScratch.get();
				long tDec = System.nanoTime();
				int ipLen = unwrapInbound(buffer, length, plain);
				dDecNanos.addAndGet(System.nanoTime() - tDec);
				dDecCount.incrementAndGet();
				if (ipLen < 0) {
					logDrop("Paquete no auténtico descartado", from, fromPort, length);
					return;
				}
				if (Frame.isHeartbeat(plain, ipLen)) {
					sendPong(from, fromPort);
				} else {
					// Inyectar en Android TUN0 si va dirigido al propio teléfono
					long tInj = System.nanoTime();
					injectToTun(plain, ipLen);
					dInjNanos.addAndGet(System.nanoTime() - tInj);
					dInjCount.incrementAndGet();
				}
			} else {
				// Reenviar al nodo destino (se reenvía el datagrama tal cual viene, ya cifrado si hay PSK)
				RoutingTable.Endpoint destEndpoint = routingTable.lookup(destVip);
				DatagramSocket socket = udpSocket;
				if (destEndpoint != null && socket != null && !socket.isClosed()) {
					DatagramPacket forward = sendScratch.get();
					forward.setData(buffer, 0, length);
					forward.setAddress(destEndpoint.address);
					forward.setPort(destEndpoint.port);
					long tFwd = System.nanoTime();
					socket.send(forward);
					dFwdNanos.addAndGet(System.nanoTime() - tFwd);
					dFwdCount.incrementAndGet();
				}
			}
		} catch (Exception e) {
			NodeLog.e(TAG, "Error procesando UDP: " + e.getMessage());
		}
	}

	private static long avgUs(long nanos, long count) {
		return count <= 0 ? 0 : nanos / count / 1000;
	}

	/**
	 * Diagnóstico temporal: cada 2 s deja una línea con la CPU del proceso, los
	 * paquetes/s y los microsegundos medios de cada etapa. Escribe en
	 * Android/media/&lt;pkg&gt;/diag.txt, que es legible sin root.
	 */
	private void diagLoop() {
		/* Todo este bucle es instrumentación de desarrollo (medidas y ajuste
		   en vivo por pool.txt). Con los registros de depuración apagados el
		   compilador deja el método en un simple return: ni hilos ni ficheros. */
		if (!LogConfig.DEBUG) return;
		NodeLog.debug("Perf", () -> "arranque crypto=" + NativeCrypto.mode() + " " + poolMode()
				+ " pin=" + NativeCrypto.pinInfo() + " | cpu% | entradas pps |"
				+ " enc dec send inj fwd (us medios, n)");
		long lastNano = System.nanoTime();
		long lastCpu = android.os.Process.getElapsedCpuTime();
		while (isRunning) {
			try {
				Thread.sleep(2000);
			} catch (InterruptedException e) {
				break;
			}
			long now = System.nanoTime();
			double dt = (now - lastNano) / 1e9;
			if (dt < 0.2) continue;
			long cpu = android.os.Process.getElapsedCpuTime();
			applyPoolConfig(false);
			String pool = poolMode();
			String pin = NativeCrypto.pinInfo();
			long tunIn = dTunIn.getAndSet(0), udpIn = dUdpIn.getAndSet(0);
			long encC = dEncCount.getAndSet(0), decC = dDecCount.getAndSet(0),
					sendC = dSendTunCount.getAndSet(0),
					injC = dInjCount.getAndSet(0), fwdC = dFwdCount.getAndSet(0);
			long encN = dEncNanos.getAndSet(0), decN = dDecNanos.getAndSet(0),
					sendN = dSendTunNanos.getAndSet(0),
					injN = dInjNanos.getAndSet(0), fwdN = dFwdNanos.getAndSet(0);
			double cpuPct = (cpu - lastCpu) * 100.0 / (dt * 1000.0);
			lastNano = now;
			lastCpu = cpu;
			/* El mensaje sólo se construye si el registro está activo. */
			NodeLog.debug("Perf", () -> String.format(Locale.US,
					"%s pin=%s cpu=%3.0f%% tun_in=%5d/s udp_in=%5d/s | enc=%3dus(%d) dec=%3dus(%d) "
							+ "send=%3dus(%d) inj=%3dus(%d) fwd=%3dus(%d)",
					pool, pin, cpuPct,
					(long) (tunIn / dt), (long) (udpIn / dt),
					avgUs(encN, encC), encC,
					avgUs(decN, decC), decC,
					avgUs(sendN, sendC), sendC,
					avgUs(injN, injC), injC,
					avgUs(fwdN, fwdC), fwdC));
		}
	}

	private boolean isClientMode() {
		return config.serverHost != null
				&& !config.serverHost.trim().isEmpty()
				&& !"0.0.0.0".equals(config.serverHost.trim());
	}

	private void clientHeartbeatLoop() {
		while (isRunning) {
			try {
				sendClientHeartbeat();
				Thread.sleep(3000);
			} catch (InterruptedException e) {
				break;
			} catch (Exception e) {
				NodeLog.e(TAG, "Heartbeat error: " + e.getMessage());
				try { Thread.sleep(3000); } catch (InterruptedException ie) { break; }
			}
		}
	}

	private void sendClientHeartbeat() {
		DatagramSocket socket = clientSocket;
		InetSocketAddress target = relayAddr;
		if (!isRunning || socket == null || socket.isClosed() || target == null || target.isUnresolved()) return;
		try {
			byte[] dummy = new byte[20];
			dummy[0] = 0x45;
			byte[] src = InetAddress.getByName(overlayIp).getAddress();
			System.arraycopy(src, 0, dummy, 12, 4);
			System.arraycopy(src, 0, dummy, 16, 4);
			byte[] wire = wrapOutbound(dummy);
			if (wire != null) {
				socket.send(new DatagramPacket(wire, wire.length, target));
			}
		} catch (Exception e) {
			NodeLog.e(TAG, "Heartbeat error: " + e.getMessage());
		}
	}

	private InetSocketAddress resolveRelayAddress(String host, int port) throws Exception {
		InetAddress[] resolved = InetAddress.getAllByName(host);
		for (InetAddress address : resolved) {
			if (address instanceof Inet4Address) {
				return new InetSocketAddress(address, port);
			}
		}
		throw new IllegalStateException("El dominio no tiene direcciones IPv4");
	}

	/**
	 * Re-resuelve el dominio del relay cada 5 s. Si el DDNS cambió la IP, actualiza
	 * el endpoint y remapea las rutas aprendidas para no reiniciar la VPN.
	 */
	private void clientRelayAddressLoop() {
		while (isRunning) {
			try {
				Thread.sleep(RELAY_ADDRESS_CHECK_MS);
			} catch (InterruptedException e) {
				break;
			}
			if (!isRunning) break;
			refreshRelayAddress();
		}
	}

	private void refreshRelayAddress() {
		if (config == null || config.serverHost == null) return;
		InetSocketAddress current = relayAddr;
		if (current == null) return;

		String host = config.serverHost.trim();
		InetAddress currentAddress = current.getAddress();
		String currentLabel = currentAddress != null ? currentAddress.getHostAddress() : host;
		try {
			InetAddress[] resolved = InetAddress.getAllByName(host);
			InetAddress selected = null;
			for (InetAddress address : resolved) {
				if (!(address instanceof Inet4Address)) continue;
				// Si la IP actual sigue vigente, no cambiamos para evitar thrashing
				// con dominios que balancean varias direcciones.
				if (currentAddress != null && address.equals(currentAddress)) {
					selected = address;
					break;
				}
				if (selected == null) selected = address;
			}

			if (selected == null) {
				NodeLog.w(TAG, "El dominio " + host + " no tiene direcciones IPv4; se mantiene el relay actual.");
				return;
			}
			if (selected.equals(currentAddress)) return;

			InetSocketAddress updated = new InetSocketAddress(selected, config.serverPortNode);
			relayAddr = updated;
			if (currentAddress != null) {
				routingTable.remap(currentAddress, selected, config.serverPortNode);
			}

			NodeLog.i(TAG, "IP del relay actualizada: " + currentLabel + " -> "
					+ selected.getHostAddress() + ":" + config.serverPortNode);
			sendClientHeartbeat();
		} catch (Exception e) {
			NodeLog.w(TAG, "No se pudo resolver " + host + ": " + e.getMessage()
					+ " (se mantiene " + currentLabel + ")");
		}
	}

	private void clientReceiverLoop() {
		NodeLog.i(TAG, "Receptor del relay en afinidad libre.");
		byte[] buffer = new byte[MAX_PACKET];
		DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
		while (isRunning) {
			try {
				DatagramSocket socket = clientSocket;
				if (socket == null || socket.isClosed()) break;
				socket.receive(packet);
				int length = packet.getLength();
				InetAddress from = packet.getAddress();
				int fromPort = packet.getPort();
				if (!dispatchInbound(clientPool, buffer, length, from, fromPort)) {
					handleClientPacket(buffer, length, from, fromPort);
				}
			} catch (Exception e) {
				if (!isRunning) break;
				NodeLog.e(TAG, "Error en receive del relay: " + e.getMessage());
			}
		}
	}

	private void handleClientPacket(byte[] buffer, int length, InetAddress from, int fromPort) {
		try {
			if (!Frame.isIpv4(buffer, length)) return;
			if (pskKey != null && length < Frame.HEADER_LEN + CryptoUtils.OVERHEAD) return;

			int srcVip = Frame.vip(buffer, Frame.SRC_OFFSET);
			int destVip = Frame.vip(buffer, Frame.DST_OFFSET);

			// Los paquetes llegan del relay remoto: registrar el origen apuntando al relay
			if (routingTable.register(srcVip, from, fromPort)) {
				NodeLog.i(TAG, "Nuevo nodo vía relay: " + Frame.vipToString(srcVip) + " @ "
						+ from.getHostAddress() + ":" + fromPort);
			}

			if (isLocalVip(destVip)) {
				byte[] plain = plainScratch.get();
				int ipLen = unwrapInbound(buffer, length, plain);
				if (ipLen < 0) return;
				injectToTun(plain, ipLen);
			} else {
				RoutingTable.Endpoint destEndpoint = routingTable.lookup(destVip);
				DatagramSocket socket = clientSocket;
				if (destEndpoint != null && socket != null && !socket.isClosed()) {
					DatagramPacket forward = sendScratch.get();
					forward.setData(buffer, 0, length);
					forward.setAddress(destEndpoint.address);
					forward.setPort(destEndpoint.port);
					socket.send(forward);
				}
			}
		} catch (Exception e) {
			NodeLog.e(TAG, "Error procesando paquete del relay: " + e.getMessage());
		}
	}

	private void injectToTun(byte[] data, int length) {
		FileOutputStream out = tunOut;
		if (out == null) return;
		try {
			out.write(data, 0, length);
		} catch (Exception e) {
			NodeLog.e(TAG, "Error inyectando en TUN: " + e.getMessage());
		}
	}

	private void tableCleanupLoop() {
		while (isRunning) {
			try {
				Thread.sleep(5000);
				routingTable.cleanup(System.currentTimeMillis());
				refreshLocalVips();
			} catch (InterruptedException e) {
				break;
			}
		}
	}

	private synchronized void stopNode() {
		isRunning = false;
		FlowPool up = uploadPool, down = relayPool, client = clientPool;
		uploadPool = null;
		relayPool = null;
		clientPool = null;
		if (up != null) up.stop();
		if (down != null) down.stop();
		if (client != null) client.stop();
		routingTable.clear();
		try { if (tunOut != null) tunOut.close(); } catch (Exception e) {}
		tunOut = null;
		try { if (udpSocket != null) udpSocket.close(); } catch (Exception e) {}
		try { if (clientSocket != null) clientSocket.close(); } catch (Exception e) {}
		try { if (vpnInterface != null) vpnInterface.close(); } catch (Exception e) {}
		stopForeground(true);
		stopSelf();
	}

	private void createNotificationChannel() {
		if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
			NotificationChannel channel = new NotificationChannel(
					CHANNEL_ID, getString(R.string.notification_channel_name), NotificationManager.IMPORTANCE_LOW
			);
			NotificationManager manager = getSystemService(NotificationManager.class);
			if (manager != null) manager.createNotificationChannel(channel);
		}
	}

	private void showToast(final String message) {
		new Handler(Looper.getMainLooper()).post(() ->
			Toast.makeText(getApplicationContext(), message, Toast.LENGTH_LONG).show()
		);
	}

	@Override
	public void onDestroy() {
		stopNode();
		super.onDestroy();
	}
}
