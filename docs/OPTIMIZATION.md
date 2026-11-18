Nombre de la sesion: VPN
Objetivo: Optimizar el bucle de redireccion de la VPN.
Resultados obtenidos: Un techo limite de 10/20Mbps, incluso en enlaces de 200Mbps.
Resultados esperados: Una retransmision entre dos clientes diferentes de hasta 200Mbps (o mas).
Implementaciones posibles:
- Micro optimizar el codigo java al extremo
- Migrar la implementacion critica de la VPN hacia C e importarlo por JNI (implica compilar para x86, x64, arm32, arm64, en la misma apk).
- Micro optimizar el codigo C al extremo
Limites:
- No se vale alterar el comportamiento logico de la VPN logrado hasta ahora.
- No se va a cambiar la UI.
Recomendaciones:
- Primero intentar optimizar la JVM al extremo, si falla, migrar a C.
- Leer el contexto del proyecto (/docs)
- Releer este archivo de contexto para no perder el rumbo.

## Estado final (medido sobre USB K3 <-> S5, formato de trama intacto)

| Escenario | Antes | Ahora |
|---|---|---|
| Subida K3 -> S5 (TCP) | 83-91 Mbps | **110 Mbps** |
| Bajada S5 -> K3 (TCP) | ~80 Mbps | **96 Mbps** |
| Subida sin pool (1 hilo por sentido) | 83 Mbps | 91 Mbps |
| Enlace crudo TCP (control) | 209 Mbps | 191 Mbps |
| Enlace crudo UDP `-l 1472` | 228 Mbps | ~228 Mbps |

## Que se hizo (todo en Java/JNI, sin tocar la trama)

- Crypto AES-256-GCM nativa por JNI contra el BoringSSL del sistema
  (`libEVP_AEAD`, con resolucion manual de simbolos como ultimo recurso):
  `seal` 2,96 us / `open` 5,93 us frente a ~15 us del proveedor de la JVM.
- Contextos, `Cipher`, `DatagramPacket` y `FileOutputStream` del TUN reusados
  por hilo; nonce = prefijo aleatorio de 6 bytes por proceso + contador atomico
  de 48 bits (sin colisiones ni `SecureRandom` en el camino caliente).
- Lector de TUN con `FileInputStream` bloqueante: se elimino el giro en vacio
  que quemaba CPU sin mover paquetes.
- Reparto por flujos (`FlowPool`) con contrapresion bloqueante: 2 hilos de
  subida y 4 de bajada, que es el optimo medido (con 1/1 se pierde ~20%, con
  4/6 no se gana nada).
- Sin fijar hilos a nucleos: el microbenchmark de calibracion identificaba mal
  los nucleos rapidos y fijar a los A73 baja a 62 Mbps (hay mas hilos que
  nucleos). La afinidad libre es lo mas rapido y se deja como opcion manual
  (`pool.txt`, solo en compilaciones con registros de depuracion).
- Cliente Linux reescrito en tres hilos (subida, bajada, control) con
  contextos `__thread`: el bucle anterior de un paquete por iteracion con
  `select()` estaba clavado en ~9.900 pps.
- Registros: `LogConfig.DEBUG` va como `static final` inyectado por Gradle
  (`-PvpnDebugLogs=true|false`). Con `false`, `NodeLog.debug` y `diagLoop`
  compilan a un simple `return`: ni formateo, ni fichero, ni medidas.

## Por que no se llega a 200 Mbps

El techo no es CPU ni ancho de banda: es el **ritmo de paquetes del enlace
USB**. Con TCP crudo el enlace sostiene ~16.500 pps; el tunel mueve ~10.200
pps de datos mas ~4.900 de ACKs, es decir, el 91% de esa capacidad. Cada
paquete externo lleva como maximo 1.400 bytes utiles (MTU del TUN 1400 para
que 1400+48+28 = 1.476 entre en una MTU de 1.500), asi que mas ancho de banda
exigiria mas bytes por paquete, no menos CPU:

- Subir el MTU interno a 1.424 daria +1,7% y dejaria el paquete externo justo
  en 1.500, sin margen para PPPoE/WAN. No compensa el riesgo.
- Agrupar varios paquetes internos en un datagrama externo rompe el formato de
  trama y la interoperabilidad con clientes ya instalados. Descartado.

## Aviso de hardware

Durante las pruebas el telefono se reenumero en un **puerto USB 1.1**
(12 Mbps, buses `usb3`-`usb8` del S5): todo cae a ~7 Mbps y no es un fallo del
software. Los unicos puertos utiles son los de los buses `usb1`/`usb2`
(480 Mbps). Comprobacion:

    cat /sys/bus/usb/devices/*/speed
