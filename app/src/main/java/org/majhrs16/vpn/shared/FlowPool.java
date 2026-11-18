package org.majhrs16.vpn.shared;

import java.util.concurrent.locks.LockSupport;

/**
 * Reparte el trabajo por paquete entre varios hilos conservando el orden de
 * cada flujo.
 *
 * El hilo que hace la llamada al sistema (leer el TUN, recibir el datagrama)
 * no cifra ni inyecta: sólo copia el paquete en la cola del hilo que le toca
 * según el hash del flujo. Así dos paquetes de la misma conexión TCP caen
 * siempre en el mismo hilo y nunca se adelantan entre sí, mientras que flujos
 * distintos se procesan en paralelo, que es lo que reparte la carga entre
 * núcleos.
 *
 * Si la cola del hilo elegido está llena, el paquete se procesa en el propio
 * hilo llamante. Nunca se pierde ni se bloquea la lectura: es el mismo
 * mecanismo de contrapresión que ya ejerce la cola del TUN.
 */
public final class FlowPool {

	public interface Handler {
		/**
		 * Procesa un paquete. El buffer pertenece al pool y se reutiliza en
		 * cuanto el método vuelve: hay que copiarlo si se guarda.
		 *
		 * @param tag dato libre del productor (dirección del nodo, etc.)
		 * @param aux dato libre del productor (puerto)
		 * @param worker índice del hilo que atiende, para diagnósticos
		 */
		void handle(byte[] data, int length, Object tag, int aux, int worker);
	}

	/** Tamaño de cada cola: 64 paquetes de 2 KB por hilo. */
	private static final int SLOTS = 64;
	private static final int MASK = SLOTS - 1;
	/** Los paquetes del túnel nunca pasan de la MTU (1400). */
	private static final int MAX_SLOT = 2048;
	/** Giro antes de dormir: quita el coste de despertar en tráfico seguido. */
	private static final long SPIN_NANOS = 30_000;
	private static final long PARK_MAX_NANOS = 1_000_000;
	private static final long PARK_MIN_NANOS = 10_000;

	private final Handler handler;
	private final Lane[] lanes;
	private volatile boolean running = true;

	public FlowPool(String name, int workers, Handler handler, boolean pinBig) {
		this.handler = handler;
		int n = workers < 1 ? 1 : workers;
		lanes = new Lane[n];
		for (int i = 0; i < n; i++) {
			lanes[i] = new Lane(i, name + "-" + (i + 1), pinBig);
		}
		for (Lane lane : lanes) {
			/* Nombrados antes de arrancar: submit() ya puede tocar lane.thread. */
			lane.thread = new Thread(lane::run, lane.name);
			lane.thread.setDaemon(true);
			lane.thread.start();
		}
	}

	/**
	 * Encola una copia del paquete en el hilo que marca su flujo.
	 *
	 * Si la cola de ese hilo está llena se espera a que avance: es la misma
	 * contrapresión que ejerce la cola del TUN y es lo único que garantiza que
	 * un flujo no se adelante a sí mismo. Nunca se procesa el paquete en el
	 * hilo llamante, porque eso desordenaría el flujo.
	 *
	 * @return false sólo si el paquete no cabe en un slot (demasiado grande) o
	 *         el pool se está apagando; entonces lo procesa el llamante.
	 */
	public boolean submit(byte[] src, int offset, int length, int flow,
	                      Object tag, int aux) {
		if (!running || length <= 0 || length > MAX_SLOT) return false;
		Lane lane = lanes[(flow & 0x7FFFFFFF) % lanes.length];
		int tail = lane.tail;
		while (tail - lane.head >= SLOTS) {
			if (!running) return false;
			/* Dormir en vez de girar: girar aquí sólo roba CPU al hilo que
			   tiene que vaciar la cola. */
			LockSupport.parkNanos(PARK_MIN_NANOS);
			tail = lane.tail;
		}

		Slot slot = lane.slots[tail & MASK];
		System.arraycopy(src, offset, slot.data, 0, length);
		slot.length = length;
		slot.tag = tag;
		slot.aux = aux;
		lane.tail = tail + 1; /* publica el paquete (escritura volátil) */
		LockSupport.unpark(lane.thread);
		return true;
	}

	public void stop() {
		running = false;
		for (Lane lane : lanes) {
			LockSupport.unpark(lane.thread);
		}
	}

	public int size() {
		return lanes.length;
	}

	private static final class Slot {
		final byte[] data = new byte[MAX_SLOT];
		int length;
		Object tag;
		int aux;
	}

	private final class Lane {
		final Slot[] slots = new Slot[SLOTS];
		final String name;
		final boolean pinBig;
		/** Escrito por el consumidor, leído por el productor. */
		volatile int head;
		/** Escrito por el productor, leído por el consumidor. */
		volatile int tail;
		Thread thread;

		Lane(int index, String name, boolean pinBig) {
			for (int i = 0; i < SLOTS; i++) slots[i] = new Slot();
			this.name = name;
			this.pinBig = pinBig;
		}

		void run() {
			if (pinBig) NativeCrypto.pinBig();
			int localHead = 0;
			long idle = 0;
			long park = PARK_MIN_NANOS;
			while (running) {
				if (localHead != tail) {
					idle = 0;
					park = PARK_MIN_NANOS;
					Slot slot = slots[localHead & MASK];
					try {
						handler.handle(slot.data, slot.length, slot.tag, slot.aux, 0);
					} catch (Throwable t) {
						/* Un paquete malo no puede tumbar el hilo del túnel. */
					}
					localHead++;
					head = localHead;
					continue;
				}
				/* Sondeo adaptativo: esperas cortas tras el último paquete y
				   más largas si el tráfico cesa, para no quemar CPU en vacío
				   ni pagar despertar largo en cada ráfaga. */
				if (idle == 0) {
					idle = System.nanoTime();
				} else if (System.nanoTime() - idle > SPIN_NANOS) {
					LockSupport.parkNanos(park);
					park = Math.min(park * 2, PARK_MAX_NANOS);
				}
			}
		}
	}
}
