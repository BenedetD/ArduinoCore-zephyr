/* =============================================================================
 *  eura_fota_apply.c  -  Fase 3-B: apply dello sketch staged, lato LOADER.
 * -----------------------------------------------------------------------------
 *  Compilato DENTRO il loader Arduino-Zephyr (fork ArduinoCore-zephyr 0.55.2).
 *  Va chiamato come PRIMA istruzione di loader() in loader/main.c, prima di
 *  flash_area_open(user_sketch) (vedi build-opta-loader.yml: patch automatica).
 *
 *  CONTRATTO con lo sketch (FOTAService.cpp::stagePendingSketchUpdate):
 *    - storage_partition (LittleFS, QSPI) contiene alla root:
 *        pending_sketch.bin   = immagine bin-zsk verbatim (header zsk 16B + payload)
 *        pending_sketch.json  = {"sha256":"<64hex>","size":N,...,"status":"pending"}
 *    - Lo sketch monta quella partizione su "/fs"; qui il loader la rimonta su un
 *      mount-point proprio. In LittleFS i path file sono relativi alla root della
 *      partizione, quindi il mount-name e' irrilevante: stesso file.
 *
 *  SICUREZZA:
 *    - GUARDIA CRITICA: rifiuta QUALSIASI scrittura se flash_area(user_sketch) non
 *      e' esattamente off=0xE0000 size=0x100000 -> protegge loader/bootloader/DFU.
 *    - DRY-RUN (default): NESSUNA scrittura flash. Monta, legge, verifica SHA e la
 *      guardia, logga. Per attivare l'apply reale: rimuovere #define EURA_FOTA_DRYRUN
 *      (lo fa il workflow solo quando richiesto), MAI alla cieca senza banco+DFU.
 * =============================================================================
 */

/* ===> APPLY REALE abilitato (due passate). Per tornare al dry-run di sicurezza
 *      (nessuna scrittura flash) ridefinire EURA_FOTA_DRYRUN a 1.            */
/* #define EURA_FOTA_DRYRUN 1 */

#include <zephyr/kernel.h>
#include <zephyr/storage/flash_map.h>
#include <zephyr/fs/fs.h>
#include <zephyr/fs/littlefs.h>
#include <zephyr/devicetree.h>
#include <mbedtls/sha256.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

#include "eura_fota_apply.h"

/* Mount point proprio del loader (diverso da "/fs" dello sketch: lo sketch non gira
 * ancora qui). Stessa partizione fisica -> stesso file alla root. */
#define EURA_MNT          "/eura_fota"
#define EURA_STAGED_BIN   EURA_MNT "/pending_sketch.bin"
#define EURA_STAGED_META  EURA_MNT "/pending_sketch.json"
#define EURA_APPLYING     EURA_MNT "/pending_sketch.applying"
#define EURA_VERDICT_FILE EURA_MNT "/eura_fota_dryrun.txt"

#define EURA_US_OFF       0x000E0000u   /* user_sketch offset atteso (flash interna) */
#define EURA_US_SIZE      0x00100000u   /* user_sketch size attesa (1 MiB)           */
#define EURA_WBS          32u           /* STM32H7 write-block-size (256 bit)        */
#define EURA_BUF          4096u

/* Stessa config LittleFS dello sketch (storage_compat.cpp usa il default config):
 * garantisce compatibilita' di geometria col filesystem gia' formattato. */
FS_LITTLEFS_DECLARE_DEFAULT_CONFIG(eura_fota_lfs);
static struct fs_mount_t eura_fota_mp = {
	.type        = FS_LITTLEFS,
	.fs_data     = &eura_fota_lfs,
	.storage_dev = (void *)(uintptr_t)FIXED_PARTITION_ID(storage_partition),
	.mnt_point   = EURA_MNT,
};

static int hex2nib(char c)
{
	if (c >= '0' && c <= '9') return c - '0';
	if (c >= 'a' && c <= 'f') return c - 'a' + 10;
	if (c >= 'A' && c <= 'F') return c - 'A' + 10;
	return -1;
}

/* Estrae 32 byte SHA256 dal marker JSON (cerca "sha256":"<64hex>"). 0 = ok. */
static int parse_marker_sha(uint8_t out[32])
{
	struct fs_file_t f;
	fs_file_t_init(&f);
	if (fs_open(&f, EURA_STAGED_META, FS_O_READ) != 0) {
		return -1;
	}
	char buf[256];
	int n = fs_read(&f, buf, sizeof(buf) - 1);
	fs_close(&f);
	if (n <= 0) return -1;
	buf[n] = '\0';

	const char *key = strstr(buf, "\"sha256\"");
	if (!key) return -1;
	const char *p = strchr(key + 8, '"');   /* apre il valore */
	if (!p) return -1;
	p++;
	const char *q = strchr(p, '"');         /* chiude il valore */
	if (!q || (q - p) != 64) return -1;

	for (int i = 0; i < 32; i++) {
		int hi = hex2nib(p[2 * i]);
		int lo = hex2nib(p[2 * i + 1]);
		if (hi < 0 || lo < 0) return -1;
		out[i] = (uint8_t)((hi << 4) | lo);
	}
	return 0;
}

/* Scrive il verdetto su file (stessa partizione che lo sketch monta su /fs), cosi'
 * l'esito e' leggibile sulla USB anche se il printk del loader va su usart6. */
static void eura_write_verdict(const char *s)
{
	fs_unlink(EURA_VERDICT_FILE);
	struct fs_file_t vf;
	fs_file_t_init(&vf);
	if (fs_open(&vf, EURA_VERDICT_FILE, FS_O_CREATE | FS_O_WRITE) == 0) {
		fs_write(&vf, s, strlen(s));
		fs_close(&vf);
	}
}

/* Buffer condiviso fra le passate (loader monothread: nessuna rientranza). */
static uint8_t eura_buf[EURA_BUF];

/* ---------------------------------------------------------------------------
 * PASSATA 1: legge l'INTERA immagine dal file e calcola lo SHA256, SENZA MAI
 * toccare la flash interna. Serve a validare il pending prima di qualunque
 * erase/write: se qui fallisce, lo user_sketch corrente resta intatto.
 *   0  = SHA combacia col marker
 *  -1  = open file fallita
 *  -2  = lettura corta / errore I/O
 *  -3  = SHA non combacia
 * ------------------------------------------------------------------------- */
static int eura_pass1_verify(const uint8_t want_sha[32], size_t img)
{
	struct fs_file_t bf;
	fs_file_t_init(&bf);
	if (fs_open(&bf, EURA_STAGED_BIN, FS_O_READ) != 0) {
		return -1;
	}

	mbedtls_sha256_context sha;
	mbedtls_sha256_init(&sha);
	mbedtls_sha256_starts(&sha, 0);

	size_t off = 0;
	int rc = 0;
	while (off < img) {
		int rd = fs_read(&bf, eura_buf, sizeof(eura_buf));
		if (rd <= 0) { rc = -2; break; }
		mbedtls_sha256_update(&sha, eura_buf, (size_t)rd);
		off += (size_t)rd;
	}
	fs_close(&bf);

	uint8_t got_sha[32];
	mbedtls_sha256_finish(&sha, got_sha);
	mbedtls_sha256_free(&sha);

	if (rc != 0 || off != img) return -2;
	if (memcmp(got_sha, want_sha, 32) != 0) return -3;
	return 0;
}

/* ---------------------------------------------------------------------------
 * PASSATA 2: erase di user_sketch, riscrittura dell'immagine dal file e
 * READ-BACK dalla flash con ricalcolo SHA (verifica cio' che e' realmente
 * finito sul silicio, non cio' che credevamo di scrivere).
 *   0  = scritto e riletto OK
 *  -1  = erase fallito
 *  -2  = open file fallita
 *  -3  = write fallita / lettura corta
 *  -4  = read-back fallito
 *  -5  = SHA read-back non combacia
 * ------------------------------------------------------------------------- */
static int eura_pass2_write(const struct flash_area *fa,
                            const uint8_t want_sha[32], size_t img)
{
	if (flash_area_erase(fa, 0, fa->fa_size) != 0) {
		return -1;
	}

	struct fs_file_t bf;
	fs_file_t_init(&bf);
	if (fs_open(&bf, EURA_STAGED_BIN, FS_O_READ) != 0) {
		return -2;
	}

	size_t off = 0;
	int rc = 0;
	while (off < img) {
		int rd = fs_read(&bf, eura_buf, sizeof(eura_buf));
		if (rd <= 0) { rc = -3; break; }
		/* Padding a EURA_WBS: corretto perche' solo l'ULTIMO read e' parziale
		 * (EURA_BUF=4096 e' multiplo di EURA_WBS). I read intermedi sono pieni. */
		size_t w = (size_t)rd;
		if (w % EURA_WBS) {
			size_t pad = EURA_WBS - (w % EURA_WBS);
			memset(eura_buf + w, 0xFF, pad);
			w += pad;
		}
		if (flash_area_write(fa, off, eura_buf, w) != 0) { rc = -3; break; }
		off += (size_t)rd;
	}
	fs_close(&bf);
	if (rc != 0 || off != img) return (rc != 0) ? rc : -3;

	/* READ-BACK: rileggi dalla flash e ricalcola lo SHA sull'immagine reale. */
	mbedtls_sha256_context sha;
	mbedtls_sha256_init(&sha);
	mbedtls_sha256_starts(&sha, 0);
	off = 0;
	while (off < img) {
		size_t chunk = (img - off < EURA_BUF) ? (img - off) : EURA_BUF;
		if (flash_area_read(fa, off, eura_buf, chunk) != 0) { rc = -4; break; }
		mbedtls_sha256_update(&sha, eura_buf, chunk);
		off += chunk;
	}
	uint8_t got_sha[32];
	mbedtls_sha256_finish(&sha, got_sha);
	mbedtls_sha256_free(&sha);
	if (rc != 0) return rc;
	if (memcmp(got_sha, want_sha, 32) != 0) return -5;
	return 0;
}

/* Ritorna 0 = applicato o niente-da-fare; <0 = abort sicuro (prosegue boot normale). */
int eura_fota_apply_pending(void)
{
	int mrc = fs_mount(&eura_fota_mp);
	if (mrc != 0 && mrc != -EBUSY) {
		printk("[EURA-FOTA] mount storage rc=%d -> skip\n", mrc);
		return -1;
	}

	int result = 0;
	char verdict[160];
	bool write_verdict = false;
	struct fs_dirent meta_ent, bin_ent;

	if (fs_stat(EURA_STAGED_META, &meta_ent) != 0) {
		/* nessun pending: caso normale, niente da fare (non scrivo verdetto) */
		goto out_unmount;
	}
	/* da qui in poi c'e' un pending: scriveremo sempre un verdetto leggibile su /fs */
	write_verdict = true;
	if (fs_stat(EURA_STAGED_BIN, &bin_ent) != 0) {
		printk("[EURA-FOTA] marker presente ma .bin assente -> skip\n");
		snprintf(verdict, sizeof(verdict), "FAIL: marker presente ma pending_sketch.bin assente\n");
		result = -1;
		goto out_unmount;
	}

	const size_t img = (size_t)bin_ent.size;
	if (img <= 16u || img > EURA_US_SIZE) {
		printk("[EURA-FOTA] size fuori range (%zu) -> skip\n", img);
		snprintf(verdict, sizeof(verdict), "FAIL: size fuori range (%zu byte)\n", img);
		result = -1;
		goto out_unmount;
	}

	const struct flash_area *fa;
	if (flash_area_open(FIXED_PARTITION_ID(user_sketch), &fa) != 0) {
		printk("[EURA-FOTA] flash_area_open(user_sketch) fallita -> skip\n");
		snprintf(verdict, sizeof(verdict), "FAIL: flash_area_open(user_sketch)\n");
		result = -1;
		goto out_unmount;
	}

	/* GUARDIA CRITICA: niente scritture fuori da user_sketch. */
	if (fa->fa_off != EURA_US_OFF || fa->fa_size != EURA_US_SIZE || fa->fa_size < img) {
		printk("[EURA-FOTA] ABORT guardia: off=%lx size=%zx img=%zu\n",
		       (unsigned long)fa->fa_off, (size_t)fa->fa_size, img);
		snprintf(verdict, sizeof(verdict),
		        "ABORT guardia: off=%lx size=%zx img=%zu (atteso off=e0000 size=100000)\n",
		        (unsigned long)fa->fa_off, (size_t)fa->fa_size, img);
		flash_area_close(fa);
		result = -2;
		goto out_unmount;
	}
	printk("[EURA-FOTA] guardia OK: user_sketch off=%lx size=%zx, img=%zu byte\n",
	       (unsigned long)fa->fa_off, (size_t)fa->fa_size, img);

	/* SHA256 atteso dal marker */
	uint8_t want_sha[32];
	bool have_sha = (parse_marker_sha(want_sha) == 0);
	if (!have_sha) {
		printk("[EURA-FOTA] SHA marker non parsabile -> skip\n");
		snprintf(verdict, sizeof(verdict), "FAIL: SHA del marker non parsabile\n");
		flash_area_close(fa);
		result = -1;
		goto out_unmount;
	}

	/* ===================================================================== *
	 *  PASSATA 1 - VERIFICA (nessuna scrittura flash)                       *
	 *  Legge tutto il file e confronta lo SHA col marker. Se fallisce qui,  *
	 *  lo user_sketch attuale NON viene toccato: boot normale.              *
	 * ===================================================================== */
	int p1 = eura_pass1_verify(want_sha, img);
	if (p1 != 0) {
		printk("[EURA-FOTA] PASSATA1 verifica fallita rc=%d -> skip (nessuna scrittura)\n", p1);
		snprintf(verdict, sizeof(verdict),
		        "FAIL: passata1 verifica SHA (rc=%d) - nessuna scrittura\n", p1);
		flash_area_close(fa);
		result = -1;
		goto out_unmount;
	}
	printk("[EURA-FOTA] PASSATA1 OK: img=%zu byte, SHA match (nessuna scrittura).\n", img);

#if defined(EURA_FOTA_DRYRUN)
	/* DRY-RUN: ci fermiamo dopo la verifica, senza toccare la flash. */
	printk("[EURA-FOTA] DRY-RUN OK: pending valido, SHA match, guardia OK. "
	       "NESSUNA scrittura eseguita.\n");
	snprintf(verdict, sizeof(verdict),
	        "DRY-RUN OK: img=%zu byte, SHA match, guardia OK. Nessuna scrittura.\n", img);
	/* In dry-run NON rimuoviamo il pending: cosi' resta per i test ripetuti. */
	flash_area_close(fa);
	result = 0;
#else
	/* ===================================================================== *
	 *  PASSATA 2 - APPLY REALE (solo se PASSATA 1 OK)                        *
	 *  Erase -> write -> READ-BACK con ricalcolo SHA dalla flash.           *
	 * ===================================================================== */
	int p2 = eura_pass2_write(fa, want_sha, img);
	flash_area_close(fa);
	if (p2 != 0) {
		printk("[EURA-FOTA] PASSATA2 apply fallita rc=%d\n", p2);
		snprintf(verdict, sizeof(verdict), "FAIL: passata2 apply (rc=%d)\n", p2);
		/* NON rimuoviamo il pending: si potra' ritentare al prossimo boot. */
		result = -1;
		goto out_unmount;
	}

	/* APPLY REALE riuscito: rimuovi pending solo dopo read-back SHA OK. */
	fs_unlink(EURA_STAGED_BIN);
	fs_unlink(EURA_STAGED_META);
	fs_unlink(EURA_APPLYING);
	printk("[EURA-FOTA] applicato (%zu byte, read-back SHA OK) -> boot nuovo sketch\n", img);
	snprintf(verdict, sizeof(verdict),
	        "APPLIED: img=%zu byte, read-back SHA OK -> nuovo sketch\n", img);
	result = 0;
#endif

out_unmount:
	if (write_verdict) {
		eura_write_verdict(verdict);
	}
	fs_unmount(&eura_fota_mp);
	return result;
}
