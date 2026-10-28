# Plan de trabajo — Relay VPN

## 1. Estado del repositorio

El proyecto se unificó en un monorepo con dos ejecutables y sus archivos separados:

```text
.
├── app/                  # Aplicación Android (relay y nodo cliente)
├── linux/                # Nodo cliente para Linux (C + OpenSSL)
│   ├── Makefile
│   ├── install
│   └── src/
├── docs/PLAN.md
├── gradle/ gradlew*      # Wrapper de Android
├── build.gradle
└── settings.gradle
```

- Android se construye desde la raíz con Gradle.
- El cliente Linux se construye desde `linux/` con `make`.
- El repositorio remoto `majhrs16-official/relay-vpn` ya contiene `LICENSE`
  (GPL-3.0). No se elimina ni se reemplaza: se conserva al sincronizar `main`.

## 2. Problema: desincronización cuando cambia la IP pública

La VPN se conecta usando un dominio (DDNS). Cuando el ISP cambia la IP pública
del relay:

- El servidor queda escuchando en una IP nueva.
- El cliente conserva la IP resuelta al arrancar y sigue enviando tráfico a la
  dirección anterior.
- El resultado observable es que el túnel deja de pasar tráfico hasta que se
  reinicia el cliente; en algunos casos también fue necesario reiniciar el
  servidor.

El cliente Linux ya tenía una re-evaluación reactiva basada en silencio
(12–15 s), pero no una comprobación periódica del dominio. El cliente Android
resolvía el dominio una sola vez al crear `InetSocketAddress`, por lo que un
cambio de DDNS no se detectaba nunca durante la ejecución.

## 3. Decisión de implementación (fase 1: solo cliente)

Para no tocar el servidor si no es necesario, la primera versión se limita al
lado cliente:

- **Android (modo cliente):** un hilo re-resuelve el dominio del relay cada
  5 segundos y actualiza el endpoint si la IP cambió.
- **Linux (siempre cliente):** el bucle principal re-resuelve el dominio cada
  5 segundos y, si cambió la IP pública, vuelve a seleccionar el mejor endpoint
  (LAN, LAN publicitada o pública) y recablea el relay.
- **Servidor Android (modo relay):** sin cambios. Su tabla de rutas ya se
  refresca con los heartbeats de los clientes, por lo que un cliente que vuelve
  a conectarse desde una IP/NAT nuevos se registra solo.

### 3.1 Detalle Android

Archivo: `app/src/main/java/org/majhrs16/vpn/service/VPNService.java`

- Nuevo hilo `clientRelayAddressLoop` que espera 5 s entre comprobaciones.
- `refreshRelayAddress()` usa `InetAddress.getAllByName()` y prioriza IPv4.
  Si la IP actual sigue apareciendo en la respuesta DNS, no se cambia (evita
  oscilaciones con dominios con varias direcciones).
- Si cambia, actualiza el campo `volatile relayAddr`, remapea las entradas de
  `RoutingTable` que apuntaban al relay anterior y envía un heartbeat inmediato
  para que el servidor registre el nuevo endpoint.
- Un fallo de DNS no corta el túnel: se mantiene la última dirección válida y
  se registra una advertencia.
- `RoutingTable.remap()` reemplaza únicamente los endpoints que coinciden con la
  dirección anterior del relay (se ignora el puerto porque puede cambiar por
  NAT); los peers directos de otras IP no se tocan.

### 3.2 Detalle Linux

Archivo: `linux/src/main.c`

- Se guarda la última IP pública resuelta (`last_public_ip`) separada del
  endpoint efectivo (`relay_addr`), que puede ser el gateway de la LAN o una IP
  LAN publicitada por el relay.
- Cada `DNS_CHECK_INTERVAL_MS` (5 s) se resuelve el dominio. Solo si la IP
  pública cambió se vuelve a ejecutar `select_relay_endpoint()` y se actualiza
  `relay_addr`.
- Se fuerza un heartbeat inmediato y se reinician los temporizadores de
  silencio para no duplicar la re-evaluación.
- Los errores de DNS se registran como máximo cada 30 s para no llenar la
  salida cuando el enlace está caído.
- La lógica reactiva anterior (silencio de 12–15 s) se conserva como respaldo.

## 4. Cambio de compatibilidad importante

El salt de PBKDF2 contenía el nombre del proyecto anterior. Para poder publicar
la aplicación sin esa marca se cambió a un identificador funcional del
protocolo:

```text
vpn-relay-psk-v1
```

Se actualizó tanto en Android (`CryptoUtils.java`) como en Linux
(`crypto.h`). **Ambos extremos deben actualizarse juntos**: un cliente viejo y
un servidor nuevo (o viceversa) derivarán claves distintas y el tráfico
autenticado se descartará.

## 5. Pruebas recomendadas

1. Arrancar el relay Android con un dominio DDNS y TTL bajo.
2. Conectar el cliente Android y el cliente Linux; verificar tráfico.
3. Cambiar la red del servidor (Wi-Fi → datos móviles o reiniciar el router)
   para forzar una IP pública nueva y esperar la actualización del DDNS.
4. Confirmar en los logs:
   - Android: `IP del relay actualizada: <old> -> <new>:<port>`.
   - Linux: `IP pública del relay actualizada: <old> -> <new>` y
     `Relay recableado a <new>:<port>`.
5. Verificar que el tráfico se recupera en menos de ~10 s sin reiniciar
   ninguno de los dos procesos.
6. Repetir el cambio varias veces, incluyendo pérdida temporal de DNS y
   retorno a la red anterior.
7. Probar un dominio con múltiples registros A para confirmar que no hay
   oscilación.

## 6. Criterio para considerar la fase 1 "production ready"

Mantener esta implementación solo en el cliente durante un periodo de uso real
(sugerido: al menos una semana o varios cambios de IP) y validar que:

- El cliente se recupera solo en todos los cambios de IP observados.
- No aparecen bucles de reconexión ni cambios innecesarios de endpoint.
- No fue necesario reiniciar el servidor.

Si vuelve a fallar, se pasa a la fase 2.

## 7. Fase 2 (solo si la fase 1 falla): cambios en el servidor

Posibles acciones, a evaluar según el fallo observado:

- Detectar cambios de IP local/pública en el relay y recrear el socket UDP o
  rebindear explícitamente la interfaz.
- Forzar la actualización del DDNS desde el propio servidor.
- Añadir un heartbeat servidor→cliente para que el cliente detecte la nueva IP
  incluso si el DNS tarda en propagarse.
- Añadir un identificador de sesión/epoch al protocolo para invalidar rutas
  viejas de forma explícita.

No se implementa nada de esto todavía.

## 8. Rollback

- Revertir el commit de la fase 1 restaura la resolución única al arranque.
- Si se necesita volver al salt anterior por compatibilidad, hay que revertir
  simultáneamente `CryptoUtils.java` y `linux/src/crypto.h`.

## 9. Publicación en GitHub

- Repositorio: `git@github.com:majhrs16-official/relay-vpn.git`.
- Rama: `main`.
- El `LICENSE` existente en el remoto se conserva.
- La app se muestra como **Relay VPN**; los nombres internos (paquete, clases,
  sesión, canal, proyecto Gradle) son funcionales y no dependen de la marca.
