#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <linux/if_tun.h>
#include <time.h>
#include <netdb.h>

#include "crypto.h"

#define BUFFER_SIZE 4096

typedef struct {
	char relay_host[128];
	int relay_port;
	char virtual_ip[32];
	char relay_virtual_ip[32];
	char psk[128];
} config_t;

static volatile int is_running = 1;
static char global_dev_name[IFNAMSIZ] = {0};
static char global_net_str[32] = {0};
static int psk_enabled = 0;
static unsigned char psk_key[KEY_LEN];

void handle_signal(int sig) {
	(void)sig;
	is_running = 0;
}

int resolve_host(const char *hostname, int port, struct sockaddr_in *addr) {
	struct hostent *he = gethostbyname(hostname);
	if (he == NULL) {
		return -1;
	}
	memset(addr, 0, sizeof(struct sockaddr_in));
	addr->sin_family = AF_INET;
	addr->sin_port = htons(port);
	memcpy(&addr->sin_addr, he->h_addr_list[0], he->h_length);
	return 0;
}

#define PONG_TAG "PONG"
#define PONG_TAG_LEN 4

/* Cada cuánto se vuelve a resolver el dominio del relay para detectar
   cambios de IP del lado servidor sin reiniciar el cliente. */
#define DNS_CHECK_INTERVAL_MS 5000
#define DNS_ERROR_LOG_INTERVAL_MS 30000

int get_default_gateway(struct in_addr *gw) {
	FILE *f = fopen("/proc/net/route", "r");
	if (!f) return -1;
	char line[256];
	int found = 0;
	while (fgets(line, sizeof(line), f)) {
		char iface[32];
		unsigned int dest = 0, g = 0;
		char flags[16];
		if (sscanf(line, "%31s %x %x %15s", iface, &dest, &g, flags) == 4 && dest == 0) {
			// /proc/net/route está en orden little-endian
			unsigned char b0 = g & 0xFF, b1 = (g >> 8) & 0xFF;
			unsigned char b2 = (g >> 16) & 0xFF, b3 = (g >> 24) & 0xFF;
			gw->s_addr = (b0 << 24) | (b1 << 16) | (b2 << 8) | b3;
			found = 1;
			break;
		}
	}
	fclose(f);
	return found ? 0 : -1;
}

static long long now_ms(void) {
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

void build_heartbeat(unsigned char *hb, const char *src_ip, const char *dst_ip) {
	memset(hb, 0, 20);
	hb[0] = 0x45; // Version 4, IHL 5
	struct in_addr a;
	if (inet_pton(AF_INET, src_ip, &a) == 1) memcpy(&hb[12], &a.s_addr, 4);
	if (inet_pton(AF_INET, dst_ip, &a) == 1) memcpy(&hb[16], &a.s_addr, 4);
}

/* Envía un paquete IP (header+payload). Con PSK, cifra el payload y antepone la cabecera en claro. */
static int wrap_send_packet(int fd, const struct sockaddr_in *to, const unsigned char *pkt, size_t len) {
	if (psk_enabled) {
		if (len < 20) return -1;
		unsigned char cipher[BUFFER_SIZE];
		int c = aes_gcm_encrypt(pkt + 20, len - 20, psk_key, cipher);
		if (c < 0) {
			fprintf(stderr, "[ERROR] Cifrado falló\n");
			return -1;
		}
		unsigned char wire[BUFFER_SIZE];
		memcpy(wire, pkt, 20);
		memcpy(wire + 20, cipher, c);
		return (int)sendto(fd, wire, 20 + c, 0, (const struct sockaddr *)to, sizeof(*to));
	}
	return (int)sendto(fd, pkt, len, 0, (const struct sockaddr *)to, sizeof(*to));
}

/* Reconstruye el paquete IP original desde un datagrama recibido.
   Con PSK, descifra el payload; devuelve -1 si no es IPv4 o no autentica. */
static int unwrap_packet(const unsigned char *buf, size_t n, unsigned char *out, size_t out_cap) {
	if (n < 20 || (buf[0] >> 4) != 4) return -1;
	memcpy(out, buf, 20);
	if (!psk_enabled) {
		memcpy(out + 20, buf + 20, n - 20);
		return (int)n;
	}
	int plen = aes_gcm_decrypt(buf + 20, n - 20, psk_key, out + 20);
	if (plen < 0 || 20 + plen > (int)out_cap) return -1;
	return 20 + plen;
}

int ip_is_private(in_addr_t s) {
	unsigned int a = (s >> 24) & 0xFF, b = (s >> 16) & 0xFF;
	if (a == 10 || a == 127) return 1;
	if (a == 172 && b >= 16 && b <= 31) return 1;
	if (a == 192 && b == 168) return 1;
	if (a == 100 && b >= 64 && b <= 127) return 1;
	if (a == 169 && b == 254) return 1;
	return 0;
}

static int same_endpoint(const struct sockaddr_in *a, const struct sockaddr_in *b) {
	return a->sin_family == b->sin_family
		&& a->sin_port == b->sin_port
		&& a->sin_addr.s_addr == b->sin_addr.s_addr;
}

int probe_one(int fd, const struct sockaddr_in *addr, const unsigned char *hb, int timeout_ms,
              struct sockaddr_in *from_out, unsigned char out_ip[4]) {
	if (wrap_send_packet(fd, addr, hb, 20) < 0) return 0;
	long long deadline = now_ms() + timeout_ms;
	fd_set rfds;
	unsigned char buf[32];
	while (now_ms() < deadline) {
		FD_ZERO(&rfds);
		FD_SET(fd, &rfds);
		long long remain = deadline - now_ms();
		if (remain <= 0) break;
		struct timeval tv = { .tv_sec = remain / 1000, .tv_usec = (remain % 1000) * 1000 };
		int r = select(fd + 1, &rfds, NULL, NULL, &tv);
		if (r < 0) { if (errno == EINTR) continue; break; }
		if (r == 0) continue;
		struct sockaddr_in from;
		socklen_t flen = sizeof(from);
		ssize_t n = recvfrom(fd, buf, sizeof(buf), 0, (struct sockaddr *)&from, &flen);
		if (n < 0) continue;
		if (n >= PONG_TAG_LEN + 4 && memcmp(buf, PONG_TAG, PONG_TAG_LEN) == 0) {
			if (from_out) *from_out = from;
			if (out_ip) {
				out_ip[0] = buf[4]; out_ip[1] = buf[5];
				out_ip[2] = buf[6]; out_ip[3] = buf[7];
			}
			return 1;
		}
	}
	return 0;
}

/* Devuelve: 1=gateway(LAN), 2=pública(con PONG), 3=pública(sin PONG), 4=LAN publicitada por el relay */
int select_relay_endpoint(const struct sockaddr_in *public_addr, const struct in_addr *gw_ip, int relay_port,
                          const char *virtual_ip, const char *relay_virtual_ip, struct sockaddr_in *out) {
	memset(out, 0, sizeof(*out));
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) { *out = *public_addr; return 3; }

	struct sockaddr_in gw_addr;
	memset(&gw_addr, 0, sizeof(gw_addr));
	gw_addr.sin_family = AF_INET;
	gw_addr.sin_port = htons(relay_port);
	gw_addr.sin_addr = *gw_ip;

	unsigned char hb[20];
	build_heartbeat(hb, virtual_ip, relay_virtual_ip);

	wrap_send_packet(fd, public_addr, hb, sizeof(hb));
	if (gw_ip->s_addr != 0 && gw_ip->s_addr != public_addr->sin_addr.s_addr)
		wrap_send_packet(fd, &gw_addr, hb, sizeof(hb));

	unsigned char adv[4] = {0};
	unsigned char buf[32];
	long long deadline = now_ms() + 1200;
	int result = 3;
	while (now_ms() < deadline) {
		fd_set rfds;
		FD_ZERO(&rfds);
		FD_SET(fd, &rfds);
		long long remain = deadline - now_ms();
		if (remain <= 0) break;
		struct timeval tv = { .tv_sec = remain / 1000, .tv_usec = (remain % 1000) * 1000 };
		int r = select(fd + 1, &rfds, NULL, NULL, &tv);
		if (r < 0) { if (errno == EINTR) continue; break; }
		if (r == 0) continue;
		struct sockaddr_in from;
		socklen_t flen = sizeof(from);
		ssize_t n = recvfrom(fd, buf, sizeof(buf), 0, (struct sockaddr *)&from, &flen);
		if (n < 0) continue;
		if (n < PONG_TAG_LEN + 4 || memcmp(buf, PONG_TAG, PONG_TAG_LEN) != 0) continue;
		if (gw_ip->s_addr != 0 && from.sin_addr.s_addr == gw_addr.sin_addr.s_addr) {
			close(fd);
			*out = gw_addr;
			return 1;
		}
		memcpy(adv, &buf[4], 4);
		result = 2;
	}

	int self_is_private = 0;
	{
		struct sockaddr_in self;
		socklen_t slen = sizeof(self);
		if (getsockname(fd, (struct sockaddr *)&self, &slen) == 0)
			self_is_private = ip_is_private(self.sin_addr.s_addr);
	}
	close(fd);

	if (result == 2 && self_is_private) {
		unsigned int a = (adv[0] << 24) | (adv[1] << 16) | (adv[2] << 8) | adv[3];
		if (a != 0 && a != public_addr->sin_addr.s_addr) {
			struct sockaddr_in lan_addr;
			memset(&lan_addr, 0, sizeof(lan_addr));
			lan_addr.sin_family = AF_INET;
			lan_addr.sin_port = htons(relay_port);
			lan_addr.sin_addr.s_addr = a;
			int fd2 = socket(AF_INET, SOCK_DGRAM, 0);
			if (fd2 >= 0) {
				struct sockaddr_in from2;
				unsigned char ip2[4];
				if (probe_one(fd2, &lan_addr, hb, 800, &from2, ip2)
						&& from2.sin_addr.s_addr == a) {
					close(fd2);
					*out = lan_addr;
					return 4;
				}
				close(fd2);
			}
		}
	}

	*out = *public_addr;
	return result;
}

int configure_tun_ip(const char *dev_name, const char *ip_str) {
	int sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0) return -1;

	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, dev_name, IFNAMSIZ - 1);

	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	inet_pton(AF_INET, ip_str, &sin.sin_addr);

	memcpy(&ifr.ifr_addr, &sin, sizeof(struct sockaddr));

	if (ioctl(sock, SIOCSIFADDR, &ifr) < 0) {
		close(sock);
		return -1;
	}

	if (ioctl(sock, SIOCGIFFLAGS, &ifr) >= 0) {
		ifr.ifr_flags |= IFF_UP;
		if (ioctl(sock, SIOCSIFFLAGS, &ifr) < 0) {
			perror("[WARN] No se pudo subir la interfaz");
		}
	}

	if (ioctl(sock, SIOCGIFFLAGS, &ifr) >= 0) {
		printf("[INFO] Estado de %s: %s\n", dev_name,
		       (ifr.ifr_flags & IFF_UP) ? "UP" : "DOWN");
	}

	close(sock);

	uint32_t net_prefix = ntohl(sin.sin_addr.s_addr) & 0xFFFFFF00;
	struct in_addr net_addr;
	net_addr.s_addr = htonl(net_prefix);

	strncpy(global_dev_name, dev_name, IFNAMSIZ - 1);
	inet_ntop(AF_INET, &net_addr, global_net_str, sizeof(global_net_str));

	char cmd[256];
	snprintf(cmd, sizeof(cmd), "ip route add %s/24 dev %s", global_net_str, dev_name);
	if (system(cmd) != 0) {
		fprintf(stderr, "[WARN] No se pudo agregar la ruta %s/24 dev %s (revisa con 'ip route')\n", global_net_str, dev_name);
		fprintf(stderr, "[WARN] Si %s/24 coincide con tu red local, tu tun secuestra la LAN\n", global_net_str);
	}

	return 0;
}

void cleanup_tun_network() {
	if (strlen(global_dev_name) > 0 && strlen(global_net_str) > 0) {
		char cmd[256];
		snprintf(cmd, sizeof(cmd), "ip route del %s/24 dev %s >/dev/null 2>&1", global_net_str, global_dev_name);
		system(cmd);
		snprintf(cmd, sizeof(cmd), "ip link set dev %s down >/dev/null 2>&1", global_dev_name);
		system(cmd);
	}
}

int tun_alloc(char *dev) {
	struct ifreq ifr;
	int fd, err;

	if ((fd = open("/dev/net/tun", O_RDWR)) < 0) {
		perror("[ERROR] No se pudo abrir /dev/net/tun");
		return fd;
	}

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

	if (*dev) strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);

	if ((err = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0) {
		perror("[ERROR] Fallo ioctl(TUNSETIFF)");
		close(fd);
		return err;
	}

	strcpy(dev, ifr.ifr_name);
	return fd;
}

void print_usage(const char *prog_name) {
	printf("Uso: sudo %s -l <relay_ip:port> -i <virtual_ip> [-r <relay_virtual_ip>] [-k <psk>]\n", prog_name);
	printf("     -k <psk>: cifra el tráfico con AES-256-GCM derivado del PSK (mismo en todos los nodos)\n");
}

int main(int argc, char *argv[]) {
	config_t config = { .relay_port = 4242 };
	strncpy(config.relay_virtual_ip, "10.42.0.1", sizeof(config.relay_virtual_ip) - 1);
	char tun_name[IFNAMSIZ] = "tun%d";

	int opt;
	while ((opt = getopt(argc, argv, "l:i:r:k:h")) != -1) {
		switch (opt) {
			case 'l': {
				char *colon = strchr(optarg, ':');
				if (colon) {
					*colon = '\0';
					config.relay_port = atoi(colon + 1);
				}
				strncpy(config.relay_host, optarg, sizeof(config.relay_host) - 1);
				break;
			}
			case 'i':
				strncpy(config.virtual_ip, optarg, sizeof(config.virtual_ip) - 1);
				break;
			case 'r':
				strncpy(config.relay_virtual_ip, optarg, sizeof(config.relay_virtual_ip) - 1);
				break;
			case 'k':
				strncpy(config.psk, optarg, sizeof(config.psk) - 1);
				break;
			default:
				print_usage(argv[0]);
				return 0;
		}
	}

	if (!strlen(config.relay_host) || !strlen(config.virtual_ip)) {
		print_usage(argv[0]);
		return 1;
	}

	if (strlen(config.psk) > 0) {
		if (psk_derive(config.psk, psk_key) != 0) {
			fprintf(stderr, "[ERROR] No se pudo derivar la clave PSK\n");
			return 1;
		}
		psk_enabled = 1;
		printf("[INFO] Cifrado PSK activo (AES-256-GCM).\n");
	} else {
		printf("[WARN] Sin PSK: el tráfico viaja en claro por la red.\n");
	}

	signal(SIGINT, handle_signal);
	signal(SIGTERM, handle_signal);

	int tun_fd = tun_alloc(tun_name);
	if (tun_fd < 0) return 1;

	if (configure_tun_ip(tun_name, config.virtual_ip) < 0) {
		fprintf(stderr, "[ERROR] Error asignando IP %s\n", config.virtual_ip);
		close(tun_fd);
		return 1;
	}
	printf("[INFO] Interfaz %s activa con IP %s/24\n", tun_name, config.virtual_ip);

	int udp_fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (udp_fd < 0) {
		perror("[ERROR] Socket UDP falló");
		cleanup_tun_network();
		close(tun_fd);
		return 1;
	}

	struct sockaddr_in relay_addr;
	if (resolve_host(config.relay_host, config.relay_port, &relay_addr) < 0) {
		fprintf(stderr, "[ERROR] No se pudo resolver el hostname: %s\n", config.relay_host);
		cleanup_tun_network();
		close(udp_fd);
		close(tun_fd);
		return 1;
	}

	// Selección de ruta rápida: probar el gateway local (LAN) vs la vía pública
	struct sockaddr_in relay_used = relay_addr;
	struct in_addr last_public_ip = relay_addr.sin_addr;
	struct in_addr gw_ip;
	if (get_default_gateway(&gw_ip) == 0) {
		int mode = select_relay_endpoint(&relay_addr, &gw_ip, config.relay_port,
		                                 config.virtual_ip, config.relay_virtual_ip, &relay_used);
		char gw_str[INET_ADDRSTRLEN];
		inet_ntop(AF_INET, &gw_ip, gw_str, sizeof(gw_str));
		char relay_str[INET_ADDRSTRLEN];
		inet_ntop(AF_INET, &relay_used.sin_addr, relay_str, sizeof(relay_str));
		if (mode == 1) {
			printf("[INFO] Ruta rápida: relay vía GATEWAY %s:%d (LAN directa)\n", gw_str, config.relay_port);
		} else if (mode == 4) {
			printf("[INFO] Ruta rápida: relay vía LAN publicitada %s:%d\n", relay_str, config.relay_port);
		} else {
			printf("[INFO] Relay vía PÚBLICA %s (%s:%d); gateway %s sin relay.\n",
			       config.relay_host, relay_str, config.relay_port, gw_str);
		}
	} else {
		printf("[INFO] Relay vía %s:%d (gateway no detectado)\n", config.relay_host, config.relay_port);
	}
	relay_addr = relay_used;

	fd_set readfds;
	unsigned char raw_buf[BUFFER_SIZE];
	time_t last_heartbeat = 0;
	long long last_udp_recv = now_ms();
	long long last_eval = now_ms();
	long long last_dns_check = now_ms();
	long long last_dns_error = 0;

	while (is_running) {
		time_t now = time(NULL);

		// Envía un paquete IP dummy inicial/periódico cada 3 segundos para registrar el puerto en la APK
		if (now - last_heartbeat >= 3) {
			// Cabecera IPv4 mínima: origen = IP virtual del cliente, destino = IP virtual del relay
			unsigned char dummy[20] = {0};
			dummy[0] = 0x45; // Version 4, IHL 5
			// IP origen (bytes 12-15)
			struct in_addr src_addr;
			inet_pton(AF_INET, config.virtual_ip, &src_addr);
			memcpy(&dummy[12], &src_addr.s_addr, 4);
			// IP destino (bytes 16-19) = IP virtual del relay
			struct in_addr dst_addr;
			inet_pton(AF_INET, config.relay_virtual_ip, &dst_addr);
			memcpy(&dummy[16], &dst_addr.s_addr, 4);

			wrap_send_packet(udp_fd, &relay_addr, dummy, sizeof(dummy));
			last_heartbeat = now;
		}

		FD_ZERO(&readfds);
		FD_SET(tun_fd, &readfds);
		FD_SET(udp_fd, &readfds);

		int max_fd = (tun_fd > udp_fd) ? tun_fd : udp_fd;
		struct timeval timeout = { .tv_sec = 1, .tv_usec = 0 };

		if (select(max_fd + 1, &readfds, NULL, NULL, &timeout) < 0) {
			if (errno == EINTR) continue;
			break;
		}

		// Tráfico de TUN hacia el Relay UDP
		if (FD_ISSET(tun_fd, &readfds)) {
			ssize_t nread = read(tun_fd, raw_buf, sizeof(raw_buf));
			if (nread > 0) {
				wrap_send_packet(udp_fd, &relay_addr, raw_buf, nread);
			}
		}

		// Tráfico del Relay UDP hacia TUN
		if (FD_ISSET(udp_fd, &readfds)) {
			struct sockaddr_in from_addr;
			socklen_t from_len = sizeof(from_addr);
			ssize_t nread = recvfrom(udp_fd, raw_buf, sizeof(raw_buf), 0, (struct sockaddr *)&from_addr, &from_len);
			if (nread > 0) {
				last_udp_recv = now_ms();
				if (nread >= PONG_TAG_LEN + 4 && memcmp(raw_buf, PONG_TAG, PONG_TAG_LEN) == 0) continue;
				unsigned char unpacked[BUFFER_SIZE];
				int plen = unwrap_packet(raw_buf, nread, unpacked, sizeof(unpacked));
				if (plen < 0) {
					char src_str[INET_ADDRSTRLEN];
					inet_ntop(AF_INET, &from_addr.sin_addr, src_str, sizeof(src_str));
					fprintf(stderr, "[WARN] Paquete no auténtico/inválido descartado de %s:%d (%zu bytes)\n",
					        src_str, ntohs(from_addr.sin_port), nread);
					continue;
				}
				write(tun_fd, unpacked, plen);
			}
		}

		// Comprobación periódica del dominio: si el ISP/DDNS cambió la IP
		// pública del relay, re-resolvemos y recableamos sin reiniciar.
		long long tnow = now_ms();
		if (tnow - last_dns_check >= DNS_CHECK_INTERVAL_MS) {
			last_dns_check = tnow;
			struct sockaddr_in resolved_public;
			if (resolve_host(config.relay_host, config.relay_port, &resolved_public) == 0) {
				if (resolved_public.sin_addr.s_addr != last_public_ip.s_addr) {
					char old_ip[INET_ADDRSTRLEN], new_ip[INET_ADDRSTRLEN];
					inet_ntop(AF_INET, &last_public_ip, old_ip, sizeof(old_ip));
					inet_ntop(AF_INET, &resolved_public.sin_addr, new_ip, sizeof(new_ip));
					printf("[INFO] IP pública del relay actualizada: %s -> %s\n", old_ip, new_ip);
					last_public_ip = resolved_public.sin_addr;

					struct in_addr gw;
					struct sockaddr_in chosen;
					if (get_default_gateway(&gw) == 0) {
						int m = select_relay_endpoint(&resolved_public, &gw, config.relay_port,
						                              config.virtual_ip, config.relay_virtual_ip, &chosen);
						relay_addr = (m == 1 || m == 4 || m == 2) ? chosen : resolved_public;
					} else {
						relay_addr = resolved_public;
					}

					char relay_str[INET_ADDRSTRLEN];
					inet_ntop(AF_INET, &relay_addr.sin_addr, relay_str, sizeof(relay_str));
					printf("[INFO] Relay recableado a %s:%d\n", relay_str, ntohs(relay_addr.sin_port));

					/* Heartbeat inmediato para que el relay registre el nuevo
					   endpoint, y reset del detector de silencio. */
					unsigned char hb[20];
					build_heartbeat(hb, config.virtual_ip, config.relay_virtual_ip);
					wrap_send_packet(udp_fd, &relay_addr, hb, sizeof(hb));
					last_heartbeat = time(NULL);
					last_udp_recv = tnow;
					last_eval = tnow;
				}
			} else if (tnow - last_dns_error >= DNS_ERROR_LOG_INTERVAL_MS) {
				last_dns_error = tnow;
				fprintf(stderr, "[WARN] No se pudo resolver %s; se mantiene el relay actual.\n",
				        config.relay_host);
			}
		}

		// Re-evaluación periódica del relay: si el enlace queda mudo, re-resuelve el
		// DOMINIO (tolerante a renumeración del ISP) y re-probea gateway / LAN
		// publicitada / pública para recablearse solo (nunca se hardcodea IP local).
		if (tnow - last_udp_recv >= 12000 && tnow - last_eval >= 15000) {
			last_eval = tnow;
			struct sockaddr_in new_public;
			if (resolve_host(config.relay_host, config.relay_port, &new_public) == 0) {
				last_public_ip = new_public.sin_addr;
				struct in_addr gw;
				struct sockaddr_in chosen;
				if (get_default_gateway(&gw) == 0) {
					int m = select_relay_endpoint(&new_public, &gw, config.relay_port,
					                              config.virtual_ip, config.relay_virtual_ip, &chosen);
					if ((m == 1 || m == 4 || m == 2) && !same_endpoint(&chosen, &relay_addr)) {
						char old_s[INET_ADDRSTRLEN], new_s[INET_ADDRSTRLEN];
						inet_ntop(AF_INET, &relay_addr.sin_addr, old_s, sizeof(old_s));
						inet_ntop(AF_INET, &chosen.sin_addr, new_s, sizeof(new_s));
						printf("[INFO] Relay recableado: %s:%d -> %s:%d\n",
						       old_s, ntohs(relay_addr.sin_port), new_s, ntohs(chosen.sin_port));
						relay_addr = chosen;
					}
				}
			} else if (tnow - last_dns_error >= DNS_ERROR_LOG_INTERVAL_MS) {
				last_dns_error = tnow;
				fprintf(stderr, "[WARN] No se pudo resolver %s; se mantiene el relay actual.\n",
				        config.relay_host);
			}
			last_udp_recv = now_ms();
		}
	}

	cleanup_tun_network();
	close(udp_fd);
	close(tun_fd);
	return 0;
}
