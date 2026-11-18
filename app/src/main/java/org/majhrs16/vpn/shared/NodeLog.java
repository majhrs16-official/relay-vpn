package org.majhrs16.vpn.shared;

import android.util.Log;

import java.io.File;
import java.io.FileOutputStream;
import java.text.SimpleDateFormat;
import java.util.ArrayDeque;
import java.util.Date;
import java.util.Deque;
import java.util.Locale;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.function.Supplier;

/**
 * Registro único de la aplicación: alimenta la vista de logs de la interfaz y,
 * además, un fichero que se puede leer sin root (Android/media/&lt;pkg&gt;/log.txt).
 *
 * El fichero se trunca al arrancar el proceso, así que siempre contiene la
 * sesión actual, y las líneas se escriben en un hilo aparte para que ningún
 * punto de registro pueda frenar el túnel.
 *
 * Para trazas de depuración hay que usar debug() y, en código caliente,
 * envolverlo en "if (LogConfig.DEBUG)": al ser una constante de compilación,
 * javac elimina el bloque entero cuando el registro está desactivado.
 */
public final class NodeLog {

	public interface Listener {
		void onLogUpdated();
	}

	/** Nombre del fichero de registro dentro de Android/media/&lt;pkg&gt;/. */
	public static final String FILE_NAME = "log.txt";
	/** Tope del fichero: al superarlo se trunca y se avisa con una línea. */
	private static final long MAX_FILE_BYTES = 4L * 1024 * 1024;
	private static final int MAX_LINES = 500;

	private static final ThreadLocal<SimpleDateFormat> TIME = ThreadLocal.withInitial(
			() -> new SimpleDateFormat("HH:mm:ss.SSS", Locale.US));
	private static final Deque<String> lines = new ArrayDeque<>();
	private static volatile Listener listener = null;

	/* Cola hacia el fichero: aparte para no bloquear a quien registra. */
	private static final LinkedBlockingQueue<String> PENDING = new LinkedBlockingQueue<>(8192);
	private static volatile File logFile;
	private static volatile FileOutputStream fileOut;
	private static volatile long fileBytes;
	private static volatile boolean fileStarted;

	private NodeLog() {}

	/**
	 * Arranca el volcado a fichero dentro de dir (Android/media/&lt;pkg&gt;).
	 * Idempotente: sólo la primera llamada del proceso tiene efecto, y es la
	 * que trunca el fichero de la sesión anterior.
	 */
	public static void initFile(File dir) {
		if (fileStarted) return;
		synchronized (NodeLog.class) {
			if (fileStarted) return;
			fileStarted = true;
			try {
				if (dir == null) return;
				if (!dir.exists() && !dir.mkdirs()) return;
				File target = new File(dir, FILE_NAME);
				FileOutputStream out = new FileOutputStream(target, false);
				logFile = target;
				fileOut = out;
				fileBytes = 0;
				/* Lo registrado antes de tener fichero (arranque del servicio). */
				String early = getText();
				if (!early.isEmpty()) {
					byte[] bytes = early.getBytes();
					out.write(bytes);
					fileBytes += bytes.length;
				}
				Thread writer = new Thread(NodeLog::writeLoop, "vpn-log-file");
				writer.setDaemon(true);
				writer.start();
			} catch (Throwable ignored) {
				/* sin fichero se sigue viendo todo en pantalla */
			}
		}
	}

	private static void writeLoop() {
		while (true) {
			try {
				String first = PENDING.take();
				StringBuilder batch = new StringBuilder(first).append('\n');
				String next;
				while ((next = PENDING.poll()) != null) {
					batch.append(next).append('\n');
				}
				synchronized (NodeLog.class) {
					FileOutputStream out = fileOut;
					if (out == null) continue;
					byte[] bytes = batch.toString().getBytes();
					if (fileBytes + bytes.length > MAX_FILE_BYTES) {
						out.close();
						File target = logFile;
						out = target != null ? new FileOutputStream(target, false) : null;
						fileOut = out;
						fileBytes = 0;
						bytes = ("--- registro truncado ---\n" + batch).getBytes();
					}
					if (out != null) {
						out.write(bytes);
						out.flush();
						fileBytes += bytes.length;
					}
				}
			} catch (InterruptedException e) {
				return;
			} catch (Throwable ignored) {
				/* un fallo de disco no puede tumbar la aplicación */
			}
		}
	}

	public static void setListener(Listener l) {
		listener = l;
	}

	/** Vacía la vista y el fichero (el fichero se reabre vacío). */
	public static void clear() {
		synchronized (lines) {
			lines.clear();
		}
		PENDING.clear();
		synchronized (NodeLog.class) {
			try {
				if (fileOut != null) fileOut.close();
			} catch (Throwable ignored) {
			}
			try {
				fileOut = logFile != null ? new FileOutputStream(logFile, false) : null;
				fileBytes = 0;
			} catch (Throwable ignored) {
				fileOut = null;
			}
		}
		notifyListener();
	}

	public static String getText() {
		synchronized (lines) {
			StringBuilder sb = new StringBuilder();
			for (String s : lines) {
				sb.append(s).append('\n');
			}
			return sb.toString();
		}
	}

	private static void append(char level, String tag, String msg) {
		String line = TIME.get().format(new Date()) + " " + level + "/" + tag + ": " + msg;
		synchronized (lines) {
			lines.addLast(line);
			while (lines.size() > MAX_LINES) {
				lines.removeFirst();
			}
		}
		if (fileStarted) PENDING.offer(line);
		notifyListener();
	}

	private static void notifyListener() {
		Listener l = listener;
		if (l != null) {
			l.onLogUpdated();
		}
	}

	/**
	 * Traza de depuración. El mensaje sólo se construye si el registro está
	 * activo, así que puede describir cálculos caros sin coste en release.
	 */
	public static void debug(String tag, Supplier<String> msg) {
		if (!LogConfig.DEBUG) return;
		String text;
		try {
			text = msg.get();
		} catch (Throwable t) {
			return;
		}
		if (text == null) return;
		Log.d(tag, text);
		append('D', tag, text);
	}

	/** Igual, para mensajes ya formados. */
	public static void debug(String tag, String msg) {
		if (!LogConfig.DEBUG) return;
		Log.d(tag, msg);
		append('D', tag, msg);
	}

	/** Traza de depuración con excepción. */
	public static void debug(String tag, Supplier<String> msg, Throwable tr) {
		if (!LogConfig.DEBUG) return;
		String text;
		try {
			text = msg.get();
		} catch (Throwable t) {
			text = null;
		}
		String suffix = tr != null && tr.getMessage() != null ? " | " + tr.getMessage() : "";
		Log.d(tag, String.valueOf(text) + suffix, tr);
		append('D', tag, String.valueOf(text) + suffix);
	}

	public static void v(String tag, String msg) {
		Log.v(tag, msg);
		append('V', tag, msg);
	}

	public static void d(String tag, String msg) {
		Log.d(tag, msg);
		append('D', tag, msg);
	}

	public static void i(String tag, String msg) {
		Log.i(tag, msg);
		append('I', tag, msg);
	}

	public static void w(String tag, String msg) {
		Log.w(tag, msg);
		append('W', tag, msg);
	}

	public static void e(String tag, String msg) {
		Log.e(tag, msg);
		append('E', tag, msg);
	}

	public static void e(String tag, String msg, Throwable tr) {
		Log.e(tag, msg, tr);
		append('E', tag, msg + " | " + (tr != null && tr.getMessage() != null ? tr.getMessage() : String.valueOf(tr)));
	}
}
