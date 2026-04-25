#include "zk-download.h"
#include "main.h"

#include <euicc/base64.h>
#include <euicc/es9p.h>
#include <euicc/es10b.h>
#include <euicc/es12p.h>
#include <euicc/tostr.h>
#include <lpac/utils.h>

#include <cjson-ext/cJSON_ex.h>

#include <getopt.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static volatile int cancelled = 0;

#define CANCELPOINT() \
    if (cancelled) {  \
        goto err;     \
    }

static void sigint_handler(__attribute__((unused)) int x) { cancelled = 1; }

static cJSON *build_download_result_json(const struct es10b_load_bound_profile_package_result *result) {
    cJSON *jdata = cJSON_CreateObject();
    if (!jdata) {
        return NULL;
    }
    cJSON_AddNumberToObject(jdata, "seqNumber", (double)result->seqNumber);
    cJSON_AddStringOrNullToObject(jdata, "iccid", result->iccid);
    cJSON_AddStringToObject(jdata, "bppCommandId", euicc_bppcommandid2str(result->bppCommandId));
    cJSON_AddStringToObject(jdata, "errorReason", euicc_errorreason2str(result->errorReason));
    return jdata;
}

static int applet_main(int argc, char **argv) {
    int fret = -1;
    int opt;
    int option_index = 0;
    const char *error_function_name = NULL;
    _cleanup_free_ char *error_detail = NULL;

    char *mno = NULL;
    char *smdp = NULL;
    char *matching_id = NULL;
    char *confirmation_code = NULL;
    char *mno_cacert = NULL;
    char *b64_mno_challenge = NULL;
    char *request_id = NULL;
    char *b64_zk_profile_response = NULL;
    char *b64_set_eligibility_req = NULL;
    char *iccid = NULL;
    char *issued_matching_id = NULL;
    char *smdp_address = NULL;
    uint8_t *set_eligibility_req = NULL;
    int set_eligibility_req_len = 0;
    int set_eligibility_result = -1;
    struct es10b_load_bound_profile_package_result download_result = {0};

    static struct option long_options[] = {
        {"mno-cacert", required_argument, 0, 1000},
        {0, 0, 0, 0},
    };

    while ((opt = getopt_long(argc, argv, "m:d:i:c:h?", long_options, &option_index)) != -1) {
        switch (opt) {
        case 'm':
            mno = strdup(optarg);
            break;
        case 'd':
            smdp = strdup(optarg);
            break;
        case 'i':
            matching_id = strdup(optarg);
            break;
        case 'c':
            confirmation_code = strdup(optarg);
            break;
        case 1000:
            mno_cacert = strdup(optarg);
            break;
        case 'h':
        case '?':
            printf("Usage: %s -m MNO_URL -d SMDP_URL [-i MatchingId] [-c ConfirmationCode] [--mno-cacert PATH]\n", argv[0]);
            return -1;
        default:
            break;
        }
    }

    if (!mno || !smdp) {
        error_function_name = "arguments";
        error_detail = strdup("missing -m MNO_URL or -d SMDP_URL");
        goto err;
    }

    signal(SIGINT, sigint_handler);

    /* Use the MNO CA bundle (if supplied) for the Phase 1/2 hops to the MNO
     * server.  The SMDP+ leg below clears it again because the SMDP+ test
     * cert isn't in this bundle. */
    euicc_ctx.http.cainfo = mno_cacert;

    CANCELPOINT();
    jprint_progress("es12p_get_mno_challenge", mno);
    if (es12p_get_mno_challenge(&euicc_ctx, mno, &b64_mno_challenge, &request_id)) {
        error_function_name = "es12p_get_mno_challenge";
        goto err;
    }

    CANCELPOINT();
    jprint_progress("es10b_zk_profile_request", NULL);
    if (es10b_zk_profile_request(&euicc_ctx, b64_mno_challenge, &b64_zk_profile_response)) {
        error_function_name = "es10b_zk_profile_request";
        goto err;
    }

    CANCELPOINT();
    jprint_progress("es12p_zk_request", mno);
    if (es12p_zk_request(&euicc_ctx, mno, request_id, b64_zk_profile_response, matching_id,
                         &b64_set_eligibility_req, &iccid, &issued_matching_id, &smdp_address)) {
        error_function_name = "es12p_zk_request";
        goto err;
    }

    int set_eligibility_req_alloc = euicc_base64_decode_len(b64_set_eligibility_req);
    if (set_eligibility_req_alloc <= 0) {
        error_function_name = "base64_decode";
        goto err;
    }
    set_eligibility_req = malloc((size_t)set_eligibility_req_alloc);
    if (!set_eligibility_req) {
        error_function_name = "base64_decode";
        goto err;
    }
    set_eligibility_req_len = euicc_base64_decode(set_eligibility_req, b64_set_eligibility_req);
    if (set_eligibility_req_len < 0) {
        error_function_name = "base64_decode";
        goto err;
    }

    CANCELPOINT();
    jprint_progress("es10b_set_eligibility_data", iccid);
    if (es10b_set_eligibility_data(&euicc_ctx, set_eligibility_req,
                                   (uint32_t)set_eligibility_req_len, &set_eligibility_result)) {
        error_function_name = "es10b_set_eligibility_data";
        error_detail = malloc(32);
        if (error_detail) {
            snprintf(error_detail, 32, "result=%d", set_eligibility_result);
        }
        goto err;
    }

    es12p_ack(&euicc_ctx, mno, request_id, true);

    /* Done with MNO traffic; clear the cacert so the SMDP+ leg keeps
     * matching the existing dev-mode behaviour (no peer verification). */
    euicc_ctx.http.cainfo = NULL;

    euicc_ctx.http.server_address = smdp_address ? smdp_address : smdp;

    CANCELPOINT();
    jprint_progress("es10b_get_euicc_challenge_and_info", euicc_ctx.http.server_address);
    if (es10b_get_euicc_challenge_and_info(&euicc_ctx)) {
        error_function_name = "es10b_get_euicc_challenge_and_info";
        goto err;
    }

    CANCELPOINT();
    jprint_progress("es9p_initiate_authentication", euicc_ctx.http.server_address);
    if (es9p_initiate_authentication(&euicc_ctx)) {
        error_function_name = "es9p_initiate_authentication";
        error_detail = strdup(euicc_ctx.http.status.message);
        goto err;
    }

    CANCELPOINT();
    jprint_progress("es10b_authenticate_server", issued_matching_id);
    if (es10b_authenticate_server(&euicc_ctx, issued_matching_id, NULL)) {
        error_function_name = "es10b_authenticate_server";
        goto err;
    }

    CANCELPOINT();
    jprint_progress("es9p_authenticate_client", euicc_ctx.http.server_address);
    if (es9p_authenticate_client(&euicc_ctx)) {
        error_function_name = "es9p_authenticate_client";
        error_detail = strdup(euicc_ctx.http.status.message);
        goto err;
    }

    CANCELPOINT();
    jprint_progress("es10b_prepare_download", NULL);
    if (es10b_prepare_download(&euicc_ctx, confirmation_code)) {
        error_function_name = "es10b_prepare_download";
        goto err;
    }

    CANCELPOINT();
    jprint_progress("es9p_get_bound_profile_package", euicc_ctx.http.server_address);
    if (es9p_get_bound_profile_package(&euicc_ctx)) {
        error_function_name = "es9p_get_bound_profile_package";
        error_detail = strdup(euicc_ctx.http.status.message);
        goto err;
    }

    CANCELPOINT();
    jprint_progress("es10b_load_bound_profile_package", euicc_ctx.http.server_address);
    if (es10b_load_bound_profile_package(&euicc_ctx, &download_result)) {
        jprint_progress_obj("es10b_load_bound_profile_package:result", build_download_result_json(&download_result));
        error_function_name = "es10b_load_bound_profile_package";
        error_detail = strdup("load failed");
        goto err;
    }

    jprint_success(build_download_result_json(&download_result));
    fret = 0;
    goto exit;

err:
    if (request_id) {
        /* Restore the MNO cacert in case the failure happened on the SMDP+
         * leg (which clears it). */
        euicc_ctx.http.cainfo = mno_cacert;
        es12p_ack(&euicc_ctx, mno, request_id, false);
    }
    if (!cancelled) {
        jprint_error(error_function_name, error_detail);
    } else {
        jprint_error("cancelled", NULL);
    }
exit:
    euicc_http_cleanup(&euicc_ctx);
    free(mno);
    free(smdp);
    free(matching_id);
    free(confirmation_code);
    free(mno_cacert);
    free(b64_mno_challenge);
    free(request_id);
    free(b64_zk_profile_response);
    free(b64_set_eligibility_req);
    free(iccid);
    free(issued_matching_id);
    free(smdp_address);
    free(set_eligibility_req);
    return fret;
}

struct applet_entry applet_profile_zk_download = {
    .name = "zk-download",
    .main = applet_main,
};
