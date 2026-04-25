#include "zk-download.h"
#include "main.h"

#include <euicc/es10b.h>
#include <euicc/es12p.h>
#include <euicc/es9p.h>
#include <euicc/base64.h>
#include <euicc/euicc.h>
#include <euicc/tostr.h>
#include <lpac/utils.h>

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *opt_string = "n:s:i:h?";

static int applet_main(int argc, char **argv) {
    int fret;
    const char *error_function_name = NULL;
    _cleanup_free_ char *error_detail = NULL;

    int opt;
    char *mno_addr = NULL;
    char *smdp = NULL;
    char *imei = NULL;

    _cleanup_free_ char *b64_zk_resp = NULL;
    uint8_t *bf43_raw = NULL;
    int bf43_len;

    struct es12p_challenge_result challenge;
    struct es12p_zk_request_result zk_result;
    struct es10b_load_bound_profile_package_result download_result = {0};

    memset(&challenge, 0, sizeof(challenge));
    memset(&zk_result, 0, sizeof(zk_result));

    while ((opt = getopt(argc, argv, opt_string)) != -1) {
        switch (opt) {
        case 'n':
            mno_addr = strdup(optarg);
            break;
        case 's':
            smdp = strdup(optarg);
            break;
        case 'i':
            imei = strdup(optarg);
            break;
        case 'h':
        case '?':
            printf("Usage: %s [OPTIONS]\n", argv[0]);
            printf("\t -n MNO Server Address (required)\n");
            printf("\t -s SM-DP+ Address (optional; overrides MNO-provided address)\n");
            printf("\t -i IMEI (optional)\n");
            printf("\t -h This help info\n");
            return -1;
        default:
            break;
        }
    }

    if (!mno_addr) {
        error_function_name = "mno_addr";
        error_detail = strdup("required");
        goto err;
    }

    /* Phase 1: obtain MNO challenge */
    jprint_progress("es12p_get_mno_challenge", mno_addr);
    if (es12p_get_mno_challenge(&euicc_ctx, mno_addr, &challenge) < 0) {
        error_function_name = "es12p_get_mno_challenge";
        goto err;
    }

    /* Phase 1: run BF42 ZKProfileRequest on the eUICC */
    jprint_progress("es10b_zk_profile_request", NULL);
    if (es10b_zk_profile_request_r(&euicc_ctx, &b64_zk_resp,
                                    challenge.mnoChallenge, 16) < 0) {
        error_function_name = "es10b_zk_profile_request";
        goto err;
    }

    /* Phase 2: send ZK proof to MNO, receive eligibility credentials */
    jprint_progress("es12p_zk_request", mno_addr);
    if (es12p_zk_request(&euicc_ctx, mno_addr, challenge.requestId,
                          b64_zk_resp, &zk_result) < 0) {
        error_function_name = "es12p_zk_request";
        goto err;
    }

    /* Phase 2: decode BF43 TLV and write credentials into the eUICC */
    bf43_raw = malloc((size_t)euicc_base64_decode_len(zk_result.setEligibilityDataB64));
    if (!bf43_raw) {
        error_function_name = "bf43_alloc";
        goto err;
    }
    if ((bf43_len = euicc_base64_decode(bf43_raw, zk_result.setEligibilityDataB64)) < 0) {
        error_function_name = "bf43_decode";
        goto err;
    }

    jprint_progress("es10b_set_eligibility_data", NULL);
    if (es10b_set_eligibility_data_r(&euicc_ctx, bf43_raw, (uint32_t)bf43_len) < 0) {
        error_function_name = "es10b_set_eligibility_data";
        goto err;
    }

    /* Phase 2: acknowledge to MNO (best-effort, non-fatal) */
    jprint_progress("es12p_ack", mno_addr);
    es12p_ack(&euicc_ctx, mno_addr, challenge.requestId, 1);

    /* Use SM-DP+ address from MNO response unless overridden by -s */
    if (!smdp && zk_result.smdpAddress) {
        smdp = strdup(zk_result.smdpAddress);
    }
    if (!smdp) {
        error_function_name = "smdpAddress";
        error_detail = strdup("empty");
        goto err;
    }

    euicc_ctx.http.server_address = smdp;

    /* Phase 3-4: standard SGP.22 profile download against the SM-DP+ */
    jprint_progress("es10b_get_euicc_challenge_and_info", smdp);
    if (es10b_get_euicc_challenge_and_info(&euicc_ctx)) {
        error_function_name = "es10b_get_euicc_challenge_and_info";
        goto err;
    }

    jprint_progress("es9p_initiate_authentication", smdp);
    if (es9p_initiate_authentication(&euicc_ctx)) {
        error_function_name = "es9p_initiate_authentication";
        error_detail = strdup(euicc_ctx.http.status.message);
        goto err;
    }

    jprint_progress("es10b_authenticate_server", smdp);
    if (es10b_authenticate_server(&euicc_ctx, zk_result.matchingId, imei)) {
        error_function_name = "es10b_authenticate_server";
        goto err;
    }

    jprint_progress("es9p_authenticate_client", smdp);
    if (es9p_authenticate_client(&euicc_ctx)) {
        error_function_name = "es9p_authenticate_client";
        error_detail = strdup(euicc_ctx.http.status.message);
        goto err;
    }

    jprint_progress("es10b_prepare_download", smdp);
    if (es10b_prepare_download(&euicc_ctx, NULL)) {
        error_function_name = "es10b_prepare_download";
        goto err;
    }

    jprint_progress("es9p_get_bound_profile_package", smdp);
    if (es9p_get_bound_profile_package(&euicc_ctx)) {
        error_function_name = "es9p_get_bound_profile_package";
        error_detail = strdup(euicc_ctx.http.status.message);
        goto err;
    }

    jprint_progress("es10b_load_bound_profile_package", smdp);
    if (es10b_load_bound_profile_package(&euicc_ctx, &download_result)) {
        char buffer[256];
        snprintf(buffer, sizeof(buffer), "%s,%s",
                 euicc_bppcommandid2str(download_result.bppCommandId),
                 euicc_errorreason2str(download_result.errorReason));
        error_function_name = "es10b_load_bound_profile_package";
        error_detail = strdup(buffer);
        goto err;
    }

    jprint_success(NULL);

    fret = 0;
    goto exit;

err:
    fret = -1;
    es10b_cancel_session(&euicc_ctx, ES10B_CANCEL_SESSION_REASON_ENDUSERREJECTION);
    es9p_cancel_session(&euicc_ctx);
    jprint_error(error_function_name, error_detail);
exit:
    free(mno_addr);
    free(smdp);
    free(imei);
    free(bf43_raw);
    es12p_challenge_result_free(&challenge);
    es12p_zk_request_result_free(&zk_result);
    euicc_http_cleanup(&euicc_ctx);
    return fret;
}

struct applet_entry applet_profile_zk_download = {
    .name = "zk-download",
    .main = applet_main,
};
