#include "zk-order.h"
#include "main.h"

#include <euicc/base64.h>
#include <euicc/es10b.h>
#include <euicc/es12p.h>
#include <lpac/utils.h>

#include <cjson/cJSON.h>
#include <getopt.h>
#include <stdint.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *opt_string = "n:s:h?";

static volatile int cancelled = 0;

#define CANCELPOINT() \
    if (cancelled) {  \
        goto err;     \
    }

static void sigint_handler(__attribute__((unused)) int x) { cancelled = 1; }

static cJSON *build_order_result_json(const struct es12p_zk_request_result *result) {
    cJSON *jdata = cJSON_CreateObject();
    if (!jdata) {
        return NULL;
    }
    cJSON_AddStringOrNullToObject(jdata, "iccid", result->iccid);
    cJSON_AddStringOrNullToObject(jdata, "matchingId", result->matchingId);
    cJSON_AddStringOrNullToObject(jdata, "smdpAddress", result->smdpAddress);
    return jdata;
}

static int applet_main(int argc, char **argv) {
    int fret;
    const char *error_function_name = NULL;
    _cleanup_free_ char *error_detail = NULL;

    int opt;
    int should_ack_mno = 0;
    char *mno_addr = NULL;
    char *smdp_override = NULL;

    _cleanup_free_ char *b64_zk_resp = NULL;
    uint8_t *bf43_raw = NULL;
    int bf43_alloc_len;
    int bf43_len;

    struct es12p_challenge_result challenge;
    struct es12p_zk_request_result zk_result;

    memset(&challenge, 0, sizeof(challenge));
    memset(&zk_result, 0, sizeof(zk_result));

    while ((opt = getopt(argc, argv, opt_string)) != -1) {
        switch (opt) {
        case 'n':
            mno_addr = strdup(optarg);
            break;
        case 's':
            smdp_override = strdup(optarg);
            break;
        case 'h':
        case '?':
            printf("Usage: %s [OPTIONS]\n", argv[0]);
            printf("\t -n MNO Server Address (required)\n");
            printf("\t -s SM-DP+ Address override (optional)\n");
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

    cancelled = 0;
    signal(SIGINT, sigint_handler);

    CANCELPOINT();
    jprint_progress("es12p_get_mno_challenge", mno_addr);
    if (es12p_get_mno_challenge(&euicc_ctx, mno_addr, &challenge) < 0) {
        error_function_name = "es12p_get_mno_challenge";
        goto err;
    }
    should_ack_mno = 1;

    CANCELPOINT();
    jprint_progress("es10b_zk_profile_request", NULL);
    if (es10b_zk_profile_request_r(&euicc_ctx, &b64_zk_resp, challenge.mnoChallenge,
                                   sizeof(challenge.mnoChallenge))
        < 0) {
        error_function_name = "es10b_zk_profile_request";
        goto err;
    }

    CANCELPOINT();
    jprint_progress("es12p_zk_request", mno_addr);
    if (es12p_zk_request(&euicc_ctx, mno_addr, challenge.requestId, b64_zk_resp, &zk_result) < 0) {
        error_function_name = "es12p_zk_request";
        goto err;
    }

    bf43_alloc_len = euicc_base64_decode_len(zk_result.setEligibilityDataB64);
    if (bf43_alloc_len <= 0) {
        error_function_name = "bf43_decode";
        goto err;
    }
    bf43_raw = malloc((size_t)bf43_alloc_len);
    if (bf43_raw == NULL) {
        error_function_name = "bf43_alloc";
        goto err;
    }
    if ((bf43_len = euicc_base64_decode(bf43_raw, zk_result.setEligibilityDataB64)) < 0) {
        error_function_name = "bf43_decode";
        goto err;
    }

    CANCELPOINT();
    jprint_progress("es10b_set_eligibility_data", NULL);
    if (es10b_set_eligibility_data_r(&euicc_ctx, bf43_raw, (uint32_t)bf43_len) < 0) {
        error_function_name = "es10b_set_eligibility_data";
        goto err;
    }

    CANCELPOINT();
    jprint_progress("es12p_ack", mno_addr);
    es12p_ack(&euicc_ctx, mno_addr, challenge.requestId, 1);
    should_ack_mno = 0;

    if (smdp_override) {
        free(zk_result.smdpAddress);
        zk_result.smdpAddress = strdup(smdp_override);
        if (!zk_result.smdpAddress) {
            error_function_name = "smdpAddress";
            goto err;
        }
    }

    jprint_success(build_order_result_json(&zk_result));
    fret = 0;
    goto exit;

err:
    fret = -1;
    if (should_ack_mno) {
        es12p_ack(&euicc_ctx, mno_addr, challenge.requestId, 0);
    }
    if (cancelled) {
        jprint_error("cancelled", NULL);
    } else {
        jprint_error(error_function_name, error_detail);
    }
exit:
    free(mno_addr);
    free(smdp_override);
    free(bf43_raw);
    es12p_challenge_result_free(&challenge);
    es12p_zk_request_result_free(&zk_result);
    euicc_http_cleanup(&euicc_ctx);
    return fret;
}

struct applet_entry applet_profile_zk_order = {
    .name = "zk-order",
    .main = applet_main,
};
