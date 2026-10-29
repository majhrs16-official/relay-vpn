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
