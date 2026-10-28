package org.majhrs16.vpn.shared;

import android.util.Log;

import java.text.SimpleDateFormat;
import java.util.ArrayDeque;
import java.util.Date;
import java.util.Deque;
import java.util.Locale;

public final class NodeLog {

	public interface Listener {
		void onLogUpdated();
	}

	private static final int MAX_LINES = 500;
	private static final ThreadLocal<SimpleDateFormat> TIME = ThreadLocal.withInitial(
			() -> new SimpleDateFormat("HH:mm:ss.SSS", Locale.US));
	private static final Deque<String> lines = new ArrayDeque<>();
	private static volatile Listener listener = null;

	private NodeLog() {}

	public static void setListener(Listener l) {
		listener = l;
	}

	public static void clear() {
		synchronized (lines) {
			lines.clear();
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
		notifyListener();
	}

	private static void notifyListener() {
		Listener l = listener;
		if (l != null) {
			l.onLogUpdated();
		}
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
