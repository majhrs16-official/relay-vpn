# Relay VPN

VPN de relay punto a punto con túneles IP sobre UDP, cifrado opcional con
AES-256-GCM y PSK compartida. Incluye una aplicación Android y un nodo cliente
para Linux.

> Uso responsable: este software no oculta el origen del tráfico por sí mismo ni
> sustituye a una VPN comercial. Despliega y usa los nodos únicamente en redes
> propias o con autorización expresa.

## Componentes

```text
app/      Aplicación Android (relay y nodo cliente)
linux/    Nodo cliente para Linux (C + OpenSSL)
docs/     Documentación y plan de cambios
```

### Modos

- **Relay / servidor:** la app Android escucha en un puerto UDP y enruta los
  paquetes entre las IP virtuales de los nodos.
- **Nodo cliente:** cualquier nodo (Android o Linux) que se conecta al relay.
  En Android se activa configurando un *Host del Relay Remoto* distinto de
  `0.0.0.0`.

## Compilar Android

Requisitos: JDK 17+, Android SDK con `platforms;android-34` y
`build-tools;34.0.0`.

```sh
# local.properties debe apuntar al SDK
echo 'sdk.dir=/ruta/a/android-sdk' > local.properties

./gradlew assembleDebug
# o
./make
```

El APK queda en `app/build/outputs/apk/debug/app-debug.apk` y, al usar `./make`,
también en `dist/vpn-debug.apk`.

## Compilar el cliente Linux

Requisitos para x86_64: `gcc`, `make` y las cabeceras de OpenSSL (`libssl-dev`).
Para i686 (x86) además se necesita el soporte multilib:
`gcc-multilib`, `libc6-dev-i386` y `libssl-dev:i386`.

```sh
cd linux

# x86_64 -> bin/vpn
make

# i686 (32 bits) -> bin/vpn-x86
make x86
```

Si faltan dependencias:

```sh
make deps       # x86_64
make deps-x86   # añade i386 y las dependencias de 32 bits
```

Uso:

```sh
sudo ./bin/vpn -l relay.dominio.com:4242 -i 10.42.0.2 -r 10.42.0.1 -k 'PSK'
sudo ./bin/vpn-x86 -l relay.dominio.com:4242 -i 10.42.0.2 -r 10.42.0.1 -k 'PSK'
```

Opciones:

| Opción | Descripción |
| --- | --- |
| `-l host:puerto` | Dominio o IP del relay y su puerto UDP. |
| `-i IP` | IP virtual única del nodo dentro de la VPN. |
| `-r IP` | IP virtual del relay (por defecto `10.42.0.1`). |
| `-k PSK` | Frase compartida para cifrar con AES-256-GCM. |

El cliente Linux necesita `CAP_NET_ADMIN` (o ejecutarse con `sudo`) para crear
la interfaz TUN y configurar la ruta.

## Rendimiento

El camino de paquetes está escrito para no reservar memoria ni crear objetos por
paquete, y para repartir el trabajo entre núcleos sin desordenar ningún flujo:

- **Cifrado nativo (JNI).** AES-256-GCM se ejecuta contra el `libEVP_AEAD` del
  sistema (BoringSSL de Android), con resolución manual de símbolos como último
  recurso y respaldo automático al proveedor de la JVM si el dispositivo no lo
  expone. El formato en el cable no cambia: `nonce(12) || ciphertext || tag(16)`,
  así que clientes nuevos y viejos siguen interoperando. El nonce es un prefijo
  aleatorio de 6 bytes por proceso más un contador de 48 bits, sin `SecureRandom`
  en el camino caliente.
- **Hilos por flujo.** Los paquetes se reparten por un hash de flujo (protocolo,
  IPs y puertos): todos los de una misma conexión van siempre al mismo hilo, de
  modo que el orden se conserva, y conexiones distintas se procesan en paralelo.
- **Sin fijar núcleos.** La afinidad se deja al planificador: fijar los hilos a
  los núcleos «rápidos» (medidos a mano) resultó más lento, porque hay más
  hilos que núcleos rápidos.
- **TUN bloqueante y buffers reutilizados.** El lector de TUN no gira en vacío y
  los sockets usan buffers de 4 MB; el TUN va con MTU 1400 para que el paquete
  externo (1400 + 48 de cifrado + 28 de UDP/IP) quepa en una MTU de 1500.

Medido entre un SM-A305G (Exynos 7904, relay) y un portátil por USB 2.0
(~190 Mbps de enlace crudo):

| Prueba | Antes | Ahora |
| --- | --- | --- |
| Subida teléfono → nodo (TCP) | 83-91 Mbps | **112 Mbps** |
| Bajada nodo → teléfono (TCP) | ~80 Mbps | **96 Mbps** |
| Sin reparto por flujos | 83 Mbps | 91 Mbps |

El techo ya no es CPU ni ancho de banda, sino el número de paquetes por segundo
del enlace (se usa ~91% de su capacidad). Los detalles están en
[`docs/OPTIMIZATION.md`](docs/OPTIMIZATION.md).

### Ajuste en vivo (opcional)

En `Android/media/org.majhrs16.vpn/pool.txt` se pueden fijar los hilos de cada
sentido y, en compilaciones con registros de depuración, la afinidad de CPU:

```text
up=2 down=4 pin=big cpu=0-7
```

- `up`/`down`: hilos de subida y bajada (`0` = procesar en el propio lector).
- `pin=big`/`libre`: fijar los hilos a los núcleos rápidos o dejar libre.
- `cpu=all|0-5|6,7`: mapa de CPUs manual (en vivo sólo se relee con
  `-PvpnDebugLogs=true`; si no, se aplica al arrancar).

Sin fichero se usan los valores por defecto (`up=2 down=4`, sin fijar núcleos),
que son los mejores medidos.

> Si el enlace USB rinde ~7 Mbps y no más, revisa el puerto: en equipos viejos
> sólo algunos son USB 2.0. `cat /sys/bus/usb/devices/*/speed` debe dar `480`.

## Registros y diagnóstico

`NodeLog` alimenta la vista de logs de la interfaz y, además, un fichero legible
sin root en `Android/media/org.majhrs16.vpn/log.txt`. El fichero se trunca al
arrancar el proceso (siempre contiene la sesión actual), tiene un tope de 4 MB y
se escribe desde un hilo aparte, de modo que ningún registro puede frenar el
túnel.

Las trazas de depuración (`NodeLog.debug`) y las medidas por paquete (pps,
microsegundos por operación) se activan al compilar:

```sh
./gradlew assembleRelease -PvpnDebugLogs=true    # trazas y medidas
./gradlew assembleRelease                        # limpio (por defecto)
```

`LogConfig.DEBUG` es una constante de compilación: con `false`, javac elimina
del APK los bloques de depuración y el hilo de diagnóstico, así que no cuestan
nada en ejecución. Los mensajes `I/W/E` normales se siguen registrando siempre.

## Actualización automática de la IP del relay

Ambos clientes re-resuelven el dominio del relay cada **5 segundos**. Si el
DDNS/ISP cambia la IP pública, el cliente actualiza el endpoint sin reiniciar:

- Android remapea las rutas aprendidas y envía un heartbeat inmediato.
- Linux vuelve a seleccionar el mejor camino (LAN, LAN publicitada o pública)
  y hace la resolución DNS en un hilo aparte para no bloquear el túnel.

El servidor no necesita reiniciarse en el caso normal. El plan y los criterios
de validación están en [`docs/PLAN.md`](docs/PLAN.md).

## Seguridad

- La PSK se deriva con PBKDF2-HMAC-SHA256 (100 000 iteraciones) a una clave
  AES-256. La cabecera IPv4 viaja en claro para permitir el enrutamiento; el
  payload se cifra y autentica.
- Sin `-k`/PSK, el tráfico viaja sin cifrar. No se recomienda en redes no
  confiables.
- El salt del protocolo es `vpn-relay-psk-v1`. Clientes y servidores deben usar
  la misma versión para interoperar.
- No se incluyen claves, keystores ni `local.properties` en el repositorio.

## Licencia

GPL-3.0. Consulta [`LICENSE`](LICENSE).
