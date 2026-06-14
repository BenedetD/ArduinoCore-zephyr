/* =============================================================================
 *  eura_fota_apply.h  -  Fase 3-B: prototipo dell'apply staged lato LOADER.
 * -----------------------------------------------------------------------------
 *  Incluso da loader/main.c (patch automatica del workflow) per chiamare
 *  eura_fota_apply_pending() come PRIMA istruzione di loader().
 * =============================================================================
 */
#ifndef EURA_FOTA_APPLY_H
#define EURA_FOTA_APPLY_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Applica (o, in dry-run, verifica soltanto) lo sketch staged su QSPI.
 *
 * Va chiamata all'inizio di loader(), prima di flash_area_open(user_sketch).
 *
 * @return 0  = applicato con successo OPPURE niente da fare (nessun pending);
 *         <0 = abort sicuro (nessuna scrittura o scrittura non avviata):
 *              il boot prosegue normalmente con lo sketch corrente.
 */
int eura_fota_apply_pending(void);

#ifdef __cplusplus
}
#endif

#endif /* EURA_FOTA_APPLY_H */
