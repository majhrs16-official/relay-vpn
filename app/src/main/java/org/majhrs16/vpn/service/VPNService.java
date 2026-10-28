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
import android.util.Log;
import android.widget.Toast;

import androidx.core.app.NotificationCompat;

import org.majhrs16.vpn.R;
import org.majhrs16.vpn.data.Config;
import org.majhrs16.vpn.shared.CryptoUtils;
import org.majhrs16.vpn.shared.Frame;
import org.majhrs16.vpn.shared.NodeLog;
import org.majhrs16.vpn.shared.RoutingTable;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.InterfaceAddress;
import java.net.NetworkInterface;
import java.util.Arrays;
import java.util.Enumeration;

import javax.crypto.SecretKey;

public class VPNService extends VpnService {
	private static final String TAG = "VPNService";
	private static final String CHANNEL_ID = "vpn_tunnel_channel";
	/** Cada cuánto se re-resuelve el dominio del relay para detectar cambios de IP. */
	private static final long RELAY_ADDRESS_CHECK_MS = 5000;

	private boolean isRunning = false;
	private Thread workerThread;
	private DatagramSocket udpSocket;
	private DatagramSocket clientSocket;
	private volatile InetSocketAddress relayAddr;
	private boolean clientMode = false;
	private ParcelFileDescriptor vpnInterface;
	private Config config;
	private String overlayIp;
	private SecretKey pskKey;

	private final RoutingTable routingTable = new RoutingTable();

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
		startVpnTunnel();

		return START_STICKY;
	}

	private void startVpnTunnel() {
		if (isRunning) return;
		isRunning = true;

		try {
			overlayIp = config.nodeVirtualIp;

			pskKey = null;
			if (config.psk != null && !config.psk.trim().isEmpty()) {
				try {
					pskKey = CryptoUtils.deriveKey(config.psk);
					NodeLog.i(TAG, "Cifrado PSK activo (AES-256-GCM).");
				} catch (Exception e) {
					pskKey = null;
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

			builder.setSession("vpn-tunnel");

			vpnInterface = builder.establish();
			if (vpnInterface == null) {
				throw new IllegalStateException("Permiso de VPN rechazado o no disponible");
			}

			clientMode = isClientMode();

			udpSocket = new DatagramSocket(config.serverPort);
			String publicIp = findPublicIpv4();
			showToast("Relay en " + (publicIp != null ? publicIp : "0.0.0.0") + ":" + config.serverPort);
			NodeLog.i(TAG, "Relay iniciado. IP virtual: " + overlayIp + "/" + config.nodePrefix);
			NodeLog.i(TAG, "Escuchando en 0.0.0.0:" + config.serverPort
					+ " (IP pública detectada: " + (publicIp != null ? publicIp : "no detectada") + ")");

			if (clientMode) {
				clientSocket = new DatagramSocket();
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

			workerThread = new Thread(this::runVpnLoop);
			workerThread.start();

		} catch (Exception e) {
			Log.e(TAG, "Error: " + e.getMessage(), e);
			NodeLog.e(TAG, "Error al iniciar VPN: " + e.getMessage(), e);
			showToast("Error al iniciar VPN: " + e.getMessage());
			stopNode();
		}
	}

	/** Cifra un paquete IP de salida; devuelve null si falla. Sin PSK devuelve el paquete tal cual. */
	private byte[] wrapOutbound(byte[] ipPacket) {
		if (pskKey == null) return ipPacket;
		try {
			byte[] wrapped = CryptoUtils.encrypt(Frame.payload(ipPacket), pskKey);
			return Frame.assemble(Frame.header(ipPacket), wrapped);
		} catch (Exception e) {
			NodeLog.e(TAG, "Error cifrando salida: " + e.getMessage());
			return null;
		}
	}

	/** Descifra/un-autentica un datagrama entrante; devuelve null si falla o no es IPv4. */
	private byte[] unwrapInbound(byte[] wire) {
		if (!Frame.isIpv4(wire)) return null;
		if (pskKey == null) return wire;
		try {
			byte[] payload = CryptoUtils.decrypt(Frame.payload(wire), pskKey);
			return Frame.assemble(Frame.header(wire), payload);
		} catch (Exception e) {
			return null;
		}
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

	private void sendPong(DatagramPacket incoming) {
		try {
			byte[] lan = InetAddress.getByName(findPongLanIp(incoming.getAddress())).getAddress();
			byte[] pong = new byte[8];
			System.arraycopy(PONG_TAG, 0, pong, 0, 4);
			System.arraycopy(lan, 0, pong, 4, 4);
			udpSocket.send(new DatagramPacket(pong, pong.length, incoming.getAddress(), incoming.getPort()));
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
		if (clientMode) {
			Thread heartbeatThread = new Thread(this::clientHeartbeatLoop);
			heartbeatThread.start();
			Thread clientReceiverThread = new Thread(this::clientReceiverLoop);
			clientReceiverThread.start();
			Thread relayAddressThread = new Thread(this::clientRelayAddressLoop);
			relayAddressThread.start();
		}

		Thread cleanupThread = new Thread(this::tableCleanupLoop);
		cleanupThread.start();

		// Hilo 1: Recibir UDP externo y reenviar a TUN o enrutar
		Thread receiverThread = new Thread(() -> {
			byte[] buffer = new byte[32767];
			while (isRunning) {
				try {
					if (udpSocket == null || udpSocket.isClosed()) break;
					DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
					udpSocket.receive(packet);
					handleUdpPacket(packet);
				} catch (Exception e) {
					if (!isRunning) break;
					NodeLog.e(TAG, "Error en receive UDP: " + e.getMessage());
				}
			}
		});
		receiverThread.start();

		// Hilo 2: Leer desde TUN de Android y enviar al endpoint correspondiente
		try {
			FileInputStream in = new FileInputStream(vpnInterface.getFileDescriptor());
			byte[] buffer = new byte[32767];
			while (isRunning) {
				int length = in.read(buffer);
				if (length > 0) {
					byte[] packetData = Arrays.copyOf(buffer, length);
					if (Frame.isIpv4(packetData)) {
						String destVip = Frame.destVip(packetData);
						byte[] wire = wrapOutbound(packetData);
						if (wire == null) continue;

						RoutingTable.Endpoint destEndpoint = routingTable.lookup(destVip);
						if (destEndpoint != null) {
							udpSocket.send(new DatagramPacket(wire, wire.length, destEndpoint.address, destEndpoint.port));
						} else if (clientMode && relayAddr != null && !relayAddr.isUnresolved()) {
							clientSocket.send(new DatagramPacket(wire, wire.length, relayAddr));
						}
					}
				}
			}
		} catch (Exception e) {
			if (isRunning) NodeLog.e(TAG, "Error en TUN reader: " + e.getMessage());
		}
	}

	private void handleUdpPacket(DatagramPacket packet) {
		try {
			byte[] data = Arrays.copyOf(packet.getData(), packet.getLength());
			byte[] ipPacket = unwrapInbound(data);
			if (ipPacket == null) {
				NodeLog.w(TAG, "Paquete no auténtico/inválido descartado de "
						+ packet.getAddress().getHostAddress() + ":" + packet.getPort()
						+ " (" + data.length + " bytes)");
				return;
			}

			String srcVip = Frame.sourceVip(ipPacket);
			String destVip = Frame.destVip(ipPacket);

			// Actualizar la tabla de rutas dinámicamente con el origen del paquete
			if (routingTable.register(srcVip, packet.getAddress(), packet.getPort())) {
				NodeLog.i(TAG, "Nuevo nodo registrado: " + srcVip + " @ "
						+ packet.getAddress().getHostAddress() + ":" + packet.getPort());
			}

			if (destVip.equals(overlayIp)) {
				if (Frame.isHeartbeat(ipPacket)) {
					sendPong(packet);
				} else {
					// Inyectar en Android TUN0 si va dirigido al propio teléfono
					injectToTun(ipPacket);
				}
			} else {
				// Reenviar al nodo destino (se reenvía el datagrama tal cual viene, ya cifrado si hay PSK)
				RoutingTable.Endpoint destEndpoint = routingTable.lookup(destVip);
				if (destEndpoint != null) {
					udpSocket.send(new DatagramPacket(data, data.length, destEndpoint.address, destEndpoint.port));
				}
			}
		} catch (Exception e) {
			NodeLog.e(TAG, "Error procesando UDP: " + e.getMessage());
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
				routingTable.remap(currentAddress, current.getPort(), selected, config.serverPortNode);
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
		byte[] buffer = new byte[32767];
		while (isRunning) {
			try {
				if (clientSocket == null || clientSocket.isClosed()) break;
				DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
				clientSocket.receive(packet);
				handleClientPacket(packet);
			} catch (Exception e) {
				if (!isRunning) break;
				NodeLog.e(TAG, "Error en receive del relay: " + e.getMessage());
			}
		}
	}

	private void handleClientPacket(DatagramPacket packet) {
		try {
			byte[] data = Arrays.copyOf(packet.getData(), packet.getLength());
			byte[] ipPacket = unwrapInbound(data);
			if (ipPacket == null) return;

			String srcVip = Frame.sourceVip(ipPacket);
			String destVip = Frame.destVip(ipPacket);

			// Los paquetes llegan del relay remoto: registrar el origen apuntando al relay
			if (routingTable.register(srcVip, packet.getAddress(), packet.getPort())) {
				NodeLog.i(TAG, "Nuevo nodo vía relay: " + srcVip + " @ "
						+ packet.getAddress().getHostAddress() + ":" + packet.getPort());
			}

			if (destVip.equals(overlayIp)) {
				injectToTun(ipPacket);
			} else {
				RoutingTable.Endpoint destEndpoint = routingTable.lookup(destVip);
				if (destEndpoint != null) {
					clientSocket.send(new DatagramPacket(data, data.length, destEndpoint.address, destEndpoint.port));
				}
			}
		} catch (Exception e) {
			NodeLog.e(TAG, "Error procesando paquete del relay: " + e.getMessage());
		}
	}

	private void injectToTun(byte[] data) {
		if (vpnInterface == null) return;
		try (FileOutputStream out = new FileOutputStream(vpnInterface.getFileDescriptor())) {
			out.write(data);
		} catch (Exception e) {
			NodeLog.e(TAG, "Error inyectando en TUN: " + e.getMessage());
		}
	}

	private void tableCleanupLoop() {
		while (isRunning) {
			try {
				Thread.sleep(5000);
				routingTable.cleanup(System.currentTimeMillis());
			} catch (InterruptedException e) {
				break;
			}
		}
	}

	private synchronized void stopNode() {
		isRunning = false;
		routingTable.clear();
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