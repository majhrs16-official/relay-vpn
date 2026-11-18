/*
 * AES-256-GCM acelerado con el libcrypto (BoringSSL) que el sistema ya tiene
 * cargado para Conscrypt.
 *
 * Motivación: en este SoC `javax.crypto` (Conscrypt) cuesta 100-190 us por
 * mensaje porque reserva un EVP_CIPHER_CTX nuevo en cada operación; el túnel
 * se queda en ~2.600 paq/s. Con EVP_AEAD y contexto por paquete baja a ~3 us.
 *
 * libcrypto.so no es Biblioteca Pública para las apps, así que el namespace de
 * ART bloquea dlopen. Se prueban cinco vías, de la más limpia a la más
 * artesanal, y se guarda en g_diag por qué falla cada una:
 *   1. dlopen por ruta absoluta
 *   2. carga en el namespace que el sistema creó para Conscrypt
 *   3. carga por descriptor de fichero (esquiva el filtro de rutas)
 *   4. librería ya cargada en el proceso (RTLD_NOLOAD)
 *   5. resolución manual de símbolos sobre el ELF ya mapeado
 */
#define _GNU_SOURCE
#include <jni.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sched.h>
#include <dirent.h>
#include <time.h>
#include <android/dlext.h>
#include <android/log.h>
#include <link.h>

#define TAG "VpnCrypto"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, TAG, __VA_ARGS__)

typedef struct evp_aead_ctx_st EVP_AEAD_CTX;
typedef struct evp_aead_st EVP_AEAD;

static EVP_AEAD *(*g_aead_gcm)(void);
static EVP_AEAD_CTX *(*g_ctx_new)(const EVP_AEAD *, const uint8_t *, size_t, size_t);
static void (*g_ctx_free)(EVP_AEAD_CTX *);
static int (*g_seal)(const EVP_AEAD_CTX *, uint8_t *, size_t *, size_t,
                     const uint8_t *, size_t, const uint8_t *, size_t,
                     const uint8_t *, size_t);
static int (*g_open)(const EVP_AEAD_CTX *, uint8_t *, size_t *, size_t,
                     const uint8_t *, size_t, const uint8_t *, size_t,
                     const uint8_t *, size_t);

/** 0 = sin intentar, 1 = disponible, -1 = no disponible. */
static int g_state = 0;
/** Vía por la que se consiguió el libcrypto (para diagnóstico). */
static int g_method = 0;
/** Motivo del último fallo de cada vía. */
static char g_diag[600];

struct android_namespace_t;

/* Formato del cable: AES-256-GCM, nonce de 12 y tag de 16. */
#define KEY_LEN 32
#define NONCE_LEN 12
#define TAG_LEN 16

static void diag_add(const char *what, const char *why) {
	size_t len = strlen(g_diag);
	if (len >= sizeof(g_diag) - 2) return;
	snprintf(g_diag + len, sizeof(g_diag) - len, "%s=%s;", what, why ? why : "?");
}

static int bind_syms(void *h) {
	g_aead_gcm = (EVP_AEAD * (*)(void)) dlsym(h, "EVP_aead_aes_256_gcm");
	g_ctx_new = (EVP_AEAD_CTX * (*)(const EVP_AEAD *, const uint8_t *, size_t, size_t))
		dlsym(h, "EVP_AEAD_CTX_new");
	g_ctx_free = (void (*)(EVP_AEAD_CTX *)) dlsym(h, "EVP_AEAD_CTX_free");
	g_seal = (int (*)(const EVP_AEAD_CTX *, uint8_t *, size_t *, size_t,
	                  const uint8_t *, size_t, const uint8_t *, size_t,
	                  const uint8_t *, size_t)) dlsym(h, "EVP_AEAD_CTX_seal");
	g_open = (int (*)(const EVP_AEAD_CTX *, uint8_t *, size_t *, size_t,
	                  const uint8_t *, size_t, const uint8_t *, size_t,
	                  const uint8_t *, size_t)) dlsym(h, "EVP_AEAD_CTX_open");
	return g_aead_gcm && g_ctx_new && g_ctx_free && g_seal && g_open;
}

/** Acepta el handle sólo si expone toda la API EVP_AEAD de BoringSSL. */
static int accept(void *h, int method, const char *what) {
	if (!h) {
		diag_add(what, dlerror());
		return 0;
	}
	if (!bind_syms(h)) {
		diag_add(what, "sin-EVP_AEAD");
		dlclose(h);
		return 0;
	}
	g_method = method;
	LOGI("libcrypto de BoringSSL disponible (vía %d)", method);
	return 1;
}

/** Vía 2: cargar dentro del namespace que el sistema ya creó para Conscrypt. */
static void *load_in_conscrypt_ns(const char *path) {
	static struct android_namespace_t *(*get_ns)(const char *);
	if (!get_ns) {
		void *dl = dlopen("libdl.so", RTLD_NOW | RTLD_NOLOAD);
		if (!dl) dl = dlopen("libdl.so", RTLD_NOW);
		if (!dl) {
			diag_add("v2-libdl", dlerror());
			return NULL;
		}
		get_ns = (struct android_namespace_t * (*)(const char *))
			dlsym(dl, "android_get_exported_namespace");
		if (!get_ns) {
			diag_add("v2-sym", "sin android_get_exported_namespace");
			return NULL;
		}
	}
	struct android_namespace_t *ns = get_ns("com_android_conscrypt");
	if (!ns) {
		diag_add("v2-ns", "namespace no exportado");
		return NULL;
	}
	android_dlextinfo info;
	memset(&info, 0, sizeof(info));
	info.flags = ANDROID_DLEXT_USE_NAMESPACE;
	info.library_namespace = ns;
	void *h = android_dlopen_ext(path, RTLD_NOW, &info);
	if (!h) diag_add("v2-dlopen", dlerror());
	return h;
}

/** Vía 3: cargar por descriptor: el filtro de rutas sólo mira el nombre. */
static void *load_by_fd(const char *path) {
	int fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		char buf[48];
		snprintf(buf, sizeof(buf), "open errno %d", errno);
		diag_add("v3-open", buf);
		return NULL;
	}
	android_dlextinfo info;
	memset(&info, 0, sizeof(info));
	info.flags = ANDROID_DLEXT_USE_LIBRARY_FD;
	info.library_fd = fd;
	void *h = android_dlopen_ext("libcrypto.so", RTLD_NOW, &info);
	if (!h) diag_add("v3-dlopen", dlerror());
	close(fd);
	return h;
}

/* ------- Vía 5: autodescubrimiento de símbolos sobre el ELF mapeado -------
 *
 * No depende de rutas, nombres exactos ni de una compilación concreta: recorre
 * TODOS los módulos mapeados cuyo nombre contenga "crypto", resuelve la tabla
 * de símbolos dinámica de cada uno y sólo acepta el que además supere una
 * prueba funcional (nonce de 12, tag de 16, ida y vuelta, y rechazo del tag
 * manipulado). Así funciona igual en otra ROM con otra versión de BoringSSL,
 * con varias copias de libcrypto o con el binario en otra ruta.
 */

typedef struct {
	uintptr_t lo, hi;
} range_t;

#define MAX_CANDS 8
#define MAX_RANGES 12

typedef struct {
	uintptr_t base;
	const ElfW(Sym) *symtab;
	const char *strtab;
	const uint32_t *gnu_hash;
	const uint32_t *hash;
	range_t ranges[MAX_RANGES];
	int nranges;
	char name[96];
} cand_t;

typedef int (*seal_fn)(const EVP_AEAD_CTX *, uint8_t *, size_t *, size_t,
                       const uint8_t *, size_t, const uint8_t *, size_t,
                       const uint8_t *, size_t);
typedef int (*open_fn)(const EVP_AEAD_CTX *, uint8_t *, size_t *, size_t,
                       const uint8_t *, size_t, const uint8_t *, size_t,
                       const uint8_t *, size_t);

static cand_t g_cands[MAX_CANDS];
static int g_ncands = 0;
static cand_t *g_cur = NULL;

/** Nada fuera de los PT_LOAD del módulo en curso se dereferencia. */
static int in_mod(const void *p, size_t len) {
	if (!g_cur) return 0;
	uintptr_t a = (uintptr_t) p;
	uintptr_t b = a + len;
	if (b < a) return 0;
	for (int i = 0; i < g_cur->nranges; i++) {
		if (a >= g_cur->ranges[i].lo && b <= g_cur->ranges[i].hi) return 1;
	}
	return 0;
}

static int phdr_cb(struct dl_phdr_info *info, size_t size, void *data) {
	(void) size;
	(void) data;
	if (!info->dlpi_name || !info->dlpi_name[0]) return 0;
	/* Filtro amplio a propósito: el nombre puede variar entre ROMs. */
	if (!strstr(info->dlpi_name, "crypto")) return 0;
	if (g_ncands >= MAX_CANDS) return 1;

	uintptr_t base = (uintptr_t) info->dlpi_addr;
	const ElfW(Phdr) *dyn_ph = NULL;
	cand_t c;
	memset(&c, 0, sizeof(c));
	c.base = base;
	snprintf(c.name, sizeof(c.name), "%s", info->dlpi_name);
	for (int i = 0; i < info->dlpi_phnum; i++) {
		if (info->dlpi_phdr[i].p_type == PT_DYNAMIC) dyn_ph = &info->dlpi_phdr[i];
		if (info->dlpi_phdr[i].p_type == PT_LOAD && c.nranges < MAX_RANGES) {
			c.ranges[c.nranges].lo = base + info->dlpi_phdr[i].p_vaddr;
			c.ranges[c.nranges].hi = c.ranges[c.nranges].lo
				+ info->dlpi_phdr[i].p_memsz;
			c.nranges++;
		}
	}
	if (!dyn_ph || !c.nranges) return 0;

	const ElfW(Dyn) *d = (const ElfW(Dyn) *) (base + dyn_ph->p_vaddr);
	for (; d->d_tag != DT_NULL; d++) {
		/* En memoria los punteros suelen venir relocalizados; se acepta
		   también el valor como desplazamiento por si no lo están. */
		#define FIX(p) ((uintptr_t) (p) >= base ? (uintptr_t) (p) : (uintptr_t) (p) + base)
		switch (d->d_tag) {
			case DT_SYMTAB: c.symtab = (const ElfW(Sym) *) FIX(d->d_un.d_ptr); break;
			case DT_STRTAB: c.strtab = (const char *) FIX(d->d_un.d_ptr); break;
			case 0x6ffffef5: /* DT_GNU_HASH */
				c.gnu_hash = (const uint32_t *) FIX(d->d_un.d_ptr); break;
			case DT_HASH: c.hash = (const uint32_t *) FIX(d->d_un.d_ptr); break;
			default: break;
		}
		#undef FIX
	}
	if (!c.symtab || !c.strtab) return 0;
	if (!c.hash && !c.gnu_hash) return 0;

	g_cur = &c;
	if (!in_mod(c.symtab, sizeof(ElfW(Sym))) || !in_mod(c.strtab, 1)) return 0;
	if (c.hash && !in_mod(c.hash, 8)) return 0;
	if (c.gnu_hash && !in_mod(c.gnu_hash, 16)) return 0;

	g_cands[g_ncands++] = c;
	return 0; /* seguir: se prueban todos después */
}

static uint32_t gnu_hash_str(const char *name) {
	uint32_t h = 5381;
	const uint8_t *p = (const uint8_t *) name;
	while (*p) h = (h << 5) + h + *p++;
	return h;
}

/** Busca un símbolo en el módulo en curso (g_cur). */
static void *elf_sym(const char *name) {
	if (!g_cur) return NULL;
	const ElfW(Sym) *s = NULL;

	if (g_cur->gnu_hash) {
		const uint32_t *gh = g_cur->gnu_hash;
		uint32_t nbuckets = gh[0], symoffset = gh[1], bloom_size = gh[2];
		/* Layout: cabecera, bloom[bloom_size], buckets[nbuckets], chain[]. */
		const uint32_t *buckets = gh + 4 + bloom_size * (sizeof(uintptr_t) / 4);
		const uint32_t *chain = buckets + nbuckets;
		uint32_t h = gnu_hash_str(name);
		uint32_t idx = buckets[h % nbuckets];
		long guard = 1000000;
		if (idx >= symoffset) {
			for (;;) {
				if (--guard < 0) break;
				if (!in_mod(&chain[idx - symoffset], 4)) break;
				uint32_t ch = chain[idx - symoffset];
				if ((ch | 1) == (h | 1)) {
					const ElfW(Sym) *cand = &g_cur->symtab[idx];
					if (in_mod(cand, sizeof(ElfW(Sym)))
					    && in_mod(g_cur->strtab + cand->st_name, 1)
					    && strcmp(g_cur->strtab + cand->st_name, name) == 0) {
						s = cand;
						break;
					}
				}
				if (ch & 1) break;
				idx++;
			}
		}
	} else {
		uint32_t nchain = g_cur->hash[1];
		if (nchain > 200000) nchain = 200000;
		for (uint32_t i = 1; i < nchain; i++) {
			if (!in_mod(&g_cur->symtab[i], sizeof(ElfW(Sym)))) break;
			if (g_cur->symtab[i].st_name == 0) continue;
			if (!in_mod(g_cur->strtab + g_cur->symtab[i].st_name, 1)) continue;
			if (strcmp(g_cur->strtab + g_cur->symtab[i].st_name, name) == 0) {
				s = &g_cur->symtab[i];
				break;
			}
		}
	}
	if (!s || !s->st_value) return NULL;
	return (void *) (g_cur->base + s->st_value);
}

/** Prueba funcional: formato esperado, ida y vuelta y rechazo del tag falso. */
static int aead_selftest(const EVP_AEAD *aead,
                         EVP_AEAD_CTX *(*ctx_new)(const EVP_AEAD *, const uint8_t *, size_t, size_t),
                         void (*ctx_free)(EVP_AEAD_CTX *),
                         seal_fn seal, open_fn open_) {
	uint8_t key[32], nonce[12], in[64], out[64 + 16], back[64];
	for (int i = 0; i < 32; i++) key[i] = (uint8_t) (i * 7 + 1);
	for (int i = 0; i < 12; i++) nonce[i] = (uint8_t) (i + 3);
	for (int i = 0; i < 64; i++) in[i] = (uint8_t) (i * 3);

	EVP_AEAD_CTX *ctx = ctx_new(aead, key, sizeof(key), 16);
	if (!ctx) return 0;

	size_t n = 0, m = 0;
	int ok = seal(ctx, out, &n, sizeof(out), nonce, sizeof(nonce),
	              in, sizeof(in), NULL, 0) && n == sizeof(in) + 16;
	if (ok) {
		ok = open_(ctx, back, &m, sizeof(back), nonce, sizeof(nonce),
		           out, n, NULL, 0) && m == sizeof(in)
		     && memcmp(in, back, sizeof(in)) == 0;
	}
	if (ok) {
		out[0] ^= 0x80; /* un tag manipulado tiene que fallar */
		ok = !open_(ctx, back, &m, sizeof(back), nonce, sizeof(nonce),
		            out, n, NULL, 0);
	}
	ctx_free(ctx);
	return ok;
}

/** Prueba un candidato; sólo si todo cuadra publica los punteros globales. */
static int try_cand(cand_t *c, char *why, size_t whylen) {
	g_cur = c;

	EVP_AEAD *(*aead_gcm)(void) = (EVP_AEAD * (*)(void))
		elf_sym("EVP_aead_aes_256_gcm");
	EVP_AEAD_CTX *(*ctx_new)(const EVP_AEAD *, const uint8_t *, size_t, size_t) =
		(EVP_AEAD_CTX * (*)(const EVP_AEAD *, const uint8_t *, size_t, size_t))
		elf_sym("EVP_AEAD_CTX_new");
	void (*ctx_free)(EVP_AEAD_CTX *) = (void (*)(EVP_AEAD_CTX *))
		elf_sym("EVP_AEAD_CTX_free");
	seal_fn seal = (seal_fn) elf_sym("EVP_AEAD_CTX_seal");
	open_fn open_ = (open_fn) elf_sym("EVP_AEAD_CTX_open");
	size_t (*nonce_length)(const EVP_AEAD *) = (size_t (*)(const EVP_AEAD *))
		elf_sym("EVP_AEAD_nonce_length");
	size_t (*max_overhead)(const EVP_AEAD *) = (size_t (*)(const EVP_AEAD *))
		elf_sym("EVP_AEAD_max_overhead");

	if (!aead_gcm || !ctx_new || !ctx_free || !seal || !open_
	    || !nonce_length || !max_overhead) {
		snprintf(why, whylen, "sin-EVP_AEAD");
		return 0;
	}

	const EVP_AEAD *aead = aead_gcm();
	if (!aead) {
		snprintf(why, whylen, "aead-nulo");
		return 0;
	}
	size_t nl = nonce_length(aead);
	size_t mo = max_overhead(aead);
	if (nl != NONCE_LEN || mo != TAG_LEN) {
		snprintf(why, whylen, "formato-%zu-%zu", nl, mo);
		return 0;
	}
	if (!aead_selftest(aead, ctx_new, ctx_free, seal, open_)) {
		snprintf(why, whylen, "prueba-funcional");
		return 0;
	}

	g_aead_gcm = aead_gcm;
	g_ctx_new = ctx_new;
	g_ctx_free = ctx_free;
	g_seal = seal;
	g_open = open_;
	return 1;
}

/** Vía 5: recorre los candidatos mapeados y se queda con el que funcione. */
static int load_from_mapped_elf(void) {
	g_ncands = 0;
	dl_iterate_phdr(phdr_cb, NULL);
	if (!g_ncands) {
		diag_add("v5", "sin-candidatos");
		return 0;
	}

	char why[64];
	for (int i = 0; i < g_ncands; i++) {
		why[0] = '\0';
		if (try_cand(&g_cands[i], why, sizeof(why))) {
			g_method = 5;
			LOGI("v5: usando %s (candidato %d de %d)",
			     g_cands[i].name, i + 1, g_ncands);
			return 1;
		}
		LOGW("v5: descartado %s (%s)", g_cands[i].name, why);
		diag_add(g_cands[i].name, why);
	}
	return 0;
}

static int load(void) {
	if (g_state != 0) return g_state > 0;

	const char *paths[] = {
		"/apex/com.android.conscrypt/lib64/libcrypto.so",
		"/system/lib64/libcrypto.so",
		"/apex/com.android.conscrypt/lib/libcrypto.so",
		"/system/lib/libcrypto.so",
		NULL
	};

	for (int i = 0; paths[i]; i++) {
		if (accept(dlopen(paths[i], RTLD_NOW | RTLD_LOCAL), 1, "v1")) goto ok;
	}
	if (accept(load_in_conscrypt_ns(paths[0]), 2, "v2")) goto ok;
	if (accept(load_by_fd(paths[0]), 3, "v3")) goto ok;
	if (accept(dlopen("libcrypto.so", RTLD_NOW | RTLD_NOLOAD), 4, "v4")) goto ok;
	if (load_from_mapped_elf()) goto ok;

	LOGW("sin libcrypto utilizable; se usará Conscrypt [%s]", g_diag);
	g_state = -1;
	return 0;

ok:
	g_state = 1;
	LOGI("vía %d, diagnóstico: [%s]", g_method, g_diag);
	return 1;
}

/**
 * Valida los índices antes de entrar en sección crítica.
 * outNeed es lo que se va a escribir en out: inLen+TAG al cifrar y
 * inLen-TAG al descifrar (el tag no forma parte del texto plano).
 */
static int check_bounds(JNIEnv *env, jbyteArray in, jint inOff, jint inLen,
                        jbyteArray out, jint outOff, jint outNeed) {
	jsize inSize = (*env)->GetArrayLength(env, in);
	jsize outSize = (*env)->GetArrayLength(env, out);
	if (inOff < 0 || inLen < 0 || inOff > inSize - inLen) return 0;
	if (outNeed < 0) return 0;
	if (outOff < 0 || outOff > outSize - outNeed) return 0;
	return 1;
}

/** Cifra in[inOff..) y deja ciphertext||tag en out[outOff..). */
JNIEXPORT jint JNICALL
Java_org_majhrs16_vpn_shared_NativeCrypto_seal(JNIEnv *env, jclass cls,
                                               jbyteArray key, jbyteArray nonce,
                                               jbyteArray in, jint inOff, jint inLen,
                                               jbyteArray out, jint outOff) {
	(void) cls;
	if (!load()) return -1;
	if ((*env)->GetArrayLength(env, key) != KEY_LEN) return -1;
	if ((*env)->GetArrayLength(env, nonce) != NONCE_LEN) return -1;
	if (!check_bounds(env, in, inOff, inLen, out, outOff, inLen + TAG_LEN)) return -1;

	jbyte *kb = (*env)->GetByteArrayElements(env, key, NULL);
	jbyte *nb = (*env)->GetByteArrayElements(env, nonce, NULL);
	if (!kb || !nb) {
		if (kb) (*env)->ReleaseByteArrayElements(env, key, kb, JNI_ABORT);
		if (nb) (*env)->ReleaseByteArrayElements(env, nonce, nb, JNI_ABORT);
		return -1;
	}

	/* Las longitudes se leen ANTES de la sección crítica: dentro no se puede
	   llamar a la JNI. */
	const size_t cap = (size_t) ((*env)->GetArrayLength(env, out) - outOff);
	jint result = -1;
	jbyte *inBuf = (*env)->GetPrimitiveArrayCritical(env, in, NULL);
	jbyte *outBuf = (*env)->GetPrimitiveArrayCritical(env, out, NULL);
	if (inBuf && outBuf) {
		EVP_AEAD_CTX *ctx = g_ctx_new(g_aead_gcm(), (const uint8_t *) kb, KEY_LEN, TAG_LEN);
		if (ctx) {
			size_t written = 0;
			if (g_seal(ctx, (uint8_t *) outBuf + outOff, &written, cap,
			           (const uint8_t *) nb, NONCE_LEN,
			           (const uint8_t *) inBuf + inOff, (size_t) inLen, NULL, 0)) {
				result = (jint) written;
			}
			g_ctx_free(ctx);
		}
	}
	if (outBuf) (*env)->ReleasePrimitiveArrayCritical(env, out, outBuf, 0);
	if (inBuf) (*env)->ReleasePrimitiveArrayCritical(env, in, inBuf, JNI_ABORT);
	(*env)->ReleaseByteArrayElements(env, nonce, nb, JNI_ABORT);
	(*env)->ReleaseByteArrayElements(env, key, kb, JNI_ABORT);
	return result;
}

/** Descifra in[inOff..) (ciphertext||tag) y deja el texto plano en out[outOff..). */
JNIEXPORT jint JNICALL
Java_org_majhrs16_vpn_shared_NativeCrypto_open(JNIEnv *env, jclass cls,
                                               jbyteArray key, jbyteArray nonce,
                                               jbyteArray in, jint inOff, jint inLen,
                                               jbyteArray out, jint outOff) {
	(void) cls;
	if (!load()) return -1;
	/* inLen == TAG_LEN es válido: el latido es una cabecera IPv4 sin payload y
	   su bloque cifrado sólo lleva el tag. */
	if (inLen < TAG_LEN) return -1;
	if ((*env)->GetArrayLength(env, key) != KEY_LEN) return -1;
	if ((*env)->GetArrayLength(env, nonce) != NONCE_LEN) return -1;
	if (!check_bounds(env, in, inOff, inLen, out, outOff, inLen - TAG_LEN)) return -1;

	jbyte *kb = (*env)->GetByteArrayElements(env, key, NULL);
	jbyte *nb = (*env)->GetByteArrayElements(env, nonce, NULL);
	if (!kb || !nb) {
		if (kb) (*env)->ReleaseByteArrayElements(env, key, kb, JNI_ABORT);
		if (nb) (*env)->ReleaseByteArrayElements(env, nonce, nb, JNI_ABORT);
		return -1;
	}

	const size_t cap = (size_t) ((*env)->GetArrayLength(env, out) - outOff);
	jint result = -1;
	jbyte *inBuf = (*env)->GetPrimitiveArrayCritical(env, in, NULL);
	jbyte *outBuf = (*env)->GetPrimitiveArrayCritical(env, out, NULL);
	if (inBuf && outBuf) {
		EVP_AEAD_CTX *ctx = g_ctx_new(g_aead_gcm(), (const uint8_t *) kb, KEY_LEN, TAG_LEN);
		if (ctx) {
			size_t written = 0;
			if (g_open(ctx, (uint8_t *) outBuf + outOff, &written, cap,
			           (const uint8_t *) nb, NONCE_LEN,
			           (const uint8_t *) inBuf + inOff, (size_t) inLen, NULL, 0)) {
				result = (jint) written;
			}
			g_ctx_free(ctx);
		}
	}
	if (outBuf) (*env)->ReleasePrimitiveArrayCritical(env, out, outBuf, 0);
	if (inBuf) (*env)->ReleasePrimitiveArrayCritical(env, in, inBuf, JNI_ABORT);
	(*env)->ReleaseByteArrayElements(env, nonce, nb, JNI_ABORT);
	(*env)->ReleaseByteArrayElements(env, key, kb, JNI_ABORT);
	return result;
}

JNIEXPORT jint JNICALL
Java_org_majhrs16_vpn_shared_NativeCrypto_nativeAvailable(JNIEnv *env, jclass cls) {
	(void) env;
	(void) cls;
	return load() ? g_method : 0;
}

JNIEXPORT jstring JNICALL
Java_org_majhrs16_vpn_shared_NativeCrypto_nativeDiag(JNIEnv *env, jclass cls) {
	(void) cls;
	load();
	return (*env)->NewStringUTF(env, g_diag[0] ? g_diag : "sin-incidencias");
}

/** Texto con el resultado de la última elección de núcleos. */
static char g_pin[224] = "sin-medir";
/** Coste medido por núcleo, para el diagnóstico. */
static char g_costs_text[160] = "";
/** Máscara elegida (se mide una sola vez por proceso). */
static cpu_set_t g_fast;
static int g_fast_count = -1;
/** Máscara original del proceso, antes de que la tocáramos: es el "all". */
static cpu_set_t g_orig;
static int g_orig_valid = 0;
static unsigned long g_best_ns = 0;

/**
 * Calienta el núcleo y mide después cinco pasadas del bucle, quedándose con la
 * mejor (ns).
 *
 * El calentamiento es imprescindible: el governor tarda decenas de milisegundos
 * en subir la frecuencia, y sin él los A73 -que suelen estar dormidos- se
 * medían a su frecuencia mínima y salían más lentos que los A53 ya calientes.
 * Así la primera versión fijaba los hilos a los núcleos pequeños y el túnel
 * caía de 83 a 27 Mbps.
 */
static unsigned long cpu_loop_ns(void) {
	unsigned long x = 1;
	struct timespec a, b;
	clock_gettime(CLOCK_MONOTONIC, &a);
	for (;;) {
		for (unsigned long i = 0; i < 200000UL; i++) {
			x = x * 2862933555777941757UL + 3037000493UL;
		}
		/* Evita que el compilador elimine el bucle sin forzar memoria. */
		__asm__ __volatile__("" : "+r"(x));
		clock_gettime(CLOCK_MONOTONIC, &b);
		double ms = (double) (b.tv_sec - a.tv_sec) * 1000.0
		          + (double) (b.tv_nsec - a.tv_nsec) / 1e6;
		if (ms >= 25.0) break;
	}

	unsigned long best = ~0UL;
	for (int r = 0; r < 5; r++) {
		clock_gettime(CLOCK_MONOTONIC, &a);
		for (unsigned long i = 0; i < 200000UL; i++) {
			x = x * 2862933555777941757UL + 3037000493UL;
		}
		__asm__ __volatile__("" : "+r"(x));
		clock_gettime(CLOCK_MONOTONIC, &b);
		unsigned long ns = (unsigned long) (b.tv_sec - a.tv_sec) * 1000000000UL
		                 + (unsigned long) (b.tv_nsec - a.tv_nsec);
		if (ns < best) best = ns;
	}
	return best;
}

/** Escribe la máscara como "0,1,6,7". */
static void pin_format(const cpu_set_t *mask, int ncpu, char *out, size_t cap) {
	size_t used = 0;
	int first = 1;
	if (cap == 0) return;
	out[0] = '\0';
	for (int i = 0; i < ncpu && i < CPU_SETSIZE; i++) {
		if (!CPU_ISSET(i, mask)) continue;
		int n = snprintf(out + used, cap - used, "%s%d", first ? "" : ",", i);
		if (n <= 0 || (size_t) n >= cap - used) break;
		used += (size_t) n;
		first = 0;
	}
}

/**
 * Aplica la máscara a todos los hilos del proceso. Se puede hacer desde un hilo
 * cualquiera: basta con el TID, que se lee de /proc/self/task (legible por la
 * propia app).
 */
static void pin_all_threads(const cpu_set_t *mask) {
	sched_setaffinity(0, sizeof(cpu_set_t), mask);
	DIR *dir = opendir("/proc/self/task");
	if (!dir) return;
	struct dirent *e;
	while ((e = readdir(dir)) != NULL) {
		if (e->d_name[0] < '0' || e->d_name[0] > '9') continue;
		int tid = atoi(e->d_name);
		if (tid > 0) sched_setaffinity(tid, sizeof(cpu_set_t), mask);
	}
	closedir(dir);
}

/** Elige los núcleos más rápidos midiendo cada uno (una vez por proceso). */
static int medir_nucleos(void) {
	int ncpu = (int) sysconf(_SC_NPROCESSORS_CONF);
	if (ncpu <= 0 || ncpu > CPU_SETSIZE) {
		snprintf(g_pin, sizeof(g_pin), "sin-cpus");
		return -1;
	}
	if (g_fast_count >= 0) return g_fast_count;

	if (!g_orig_valid) {
		CPU_ZERO(&g_orig);
		if (sched_getaffinity(0, sizeof(g_orig), &g_orig) != 0) {
			snprintf(g_pin, sizeof(g_pin), "getaffinity-errno%d", errno);
			return -1;
		}
		g_orig_valid = 1;
	}
	cpu_set_t allowed = g_orig;

	unsigned long cost[CPU_SETSIZE];
	unsigned long best = ~0UL;
	for (int i = 0; i < ncpu; i++) {
		cost[i] = 0;
		if (!CPU_ISSET(i, &allowed)) continue;
		cpu_set_t one;
		CPU_ZERO(&one);
		CPU_SET(i, &one);
		if (sched_setaffinity(0, sizeof(one), &one) != 0) continue;
		cost[i] = cpu_loop_ns();
		if (cost[i] > 0 && cost[i] < best) best = cost[i];
	}
	sched_setaffinity(0, sizeof(allowed), &allowed);
	if (best == 0 || best == ~0UL) {
		snprintf(g_pin, sizeof(g_pin), "sin-medida");
		return -1;
	}

	g_best_ns = best;
	size_t used = 0;
	g_costs_text[0] = '\0';
	for (int i = 0; i < ncpu && used < sizeof(g_costs_text); i++) {
		if (!cost[i]) continue;
		int n = snprintf(g_costs_text + used, sizeof(g_costs_text) - used,
				"%s%d:%lu", used ? " " : "", i, cost[i] / 1000);
		if (n <= 0 || (size_t) n >= sizeof(g_costs_text) - used) break;
		used += (size_t) n;
	}

	CPU_ZERO(&g_fast);
	int count = 0;
	for (int i = 0; i < ncpu; i++) {
		if (!cost[i]) continue;
		if (cost[i] * 100 > best * 125) continue;
		CPU_SET(i, &g_fast);
		count++;
	}
	if (count == 0) {
		snprintf(g_pin, sizeof(g_pin), "sin-nucleos [%s]", g_costs_text);
		return -1;
	}
	g_fast_count = count;
	return count;
}

/**
 * Fija el hilo que llama (y el resto del proceso, la primera vez) a los núcleos
 * más rápidos. Coste: ~250 ms una sola vez por proceso.
 */
JNIEXPORT jint JNICALL
Java_org_majhrs16_vpn_shared_NativeCrypto_nativePinBig(JNIEnv *env, jclass cls) {
	(void) env;
	(void) cls;
	if (medir_nucleos() < 0) return -1;
	pin_all_threads(&g_fast);
	int ncpu = (int) sysconf(_SC_NPROCESSORS_CONF);
	char list[72];
	pin_format(&g_fast, ncpu, list, sizeof(list));
	snprintf(g_pin, sizeof(g_pin), "%s(%.2fms) [%s]", list,
			(double) g_best_ns / 1e6, g_costs_text);
	return g_fast_count;
}

JNIEXPORT jstring JNICALL
Java_org_majhrs16_vpn_shared_NativeCrypto_nativePinDiag(JNIEnv *env, jclass cls) {
	(void) cls;
	return (*env)->NewStringUTF(env, g_pin);
}

/**
 * Aplica a todos los hilos del proceso el mapa de CPUs indicado:
 *   "all"  -> todos los permitidos
 *   "0-5"  -> rango
 *   "6,7"  -> lista
 * Devuelve el mapa aplicado, o NULL si el texto no es válido.
 */
JNIEXPORT jstring JNICALL
Java_org_majhrs16_vpn_shared_NativeCrypto_nativePinAll(JNIEnv *env, jclass cls, jstring spec) {
	(void) cls;
	if (!spec) return NULL;
	const char *s = (*env)->GetStringUTFChars(env, spec, NULL);
	if (!s) return NULL;

	int ncpu = (int) sysconf(_SC_NPROCESSORS_CONF);
	cpu_set_t mask;
	CPU_ZERO(&mask);

	if (strcmp(s, "all") == 0 || strcmp(s, "auto") == 0) {
		if (!g_orig_valid) {
			CPU_ZERO(&g_orig);
			if (sched_getaffinity(0, sizeof(g_orig), &g_orig) != 0) {
				(*env)->ReleaseStringUTFChars(env, spec, s);
				return NULL;
			}
			g_orig_valid = 1;
		}
		mask = g_orig;
	} else {
		/* Acepta 6,7 / 6-7 / 6+7 */
		char norm[64];
		size_t j = 0;
		for (size_t i = 0; s[i] && j + 1 < sizeof(norm); i++) {
			norm[j++] = (s[i] == '+' || s[i] == ',') ? ',' : s[i];
		}
		norm[j] = '\0';
		const char *p = norm;
		while (*p) {
			while (*p == ',' || *p == ' ' || *p == ':') p++;
			if (!*p) break;
			if (*p < '0' || *p > '9') break;
			int a = (int) strtol(p, (char **) &p, 10);
			int b = a;
			if (*p == '-') {
				p++;
				b = (int) strtol(p, (char **) &p, 10);
			}
			if (a < 0) a = 0;
			if (b >= ncpu) b = ncpu - 1;
			for (int i = a; i <= b; i++) CPU_SET(i, &mask);
		}
	}
	(*env)->ReleaseStringUTFChars(env, spec, s);
	if (CPU_COUNT(&mask) == 0) return NULL;

	pin_all_threads(&mask);
	char list[72];
	pin_format(&mask, ncpu, list, sizeof(list));
	snprintf(g_pin, sizeof(g_pin), "manual:%s", list);
	return (*env)->NewStringUTF(env, list);
}
