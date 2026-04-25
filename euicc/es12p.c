#include "es12p.h"
#include "logger.h"

#include <cjson-ext/cJSON_ex.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

static const char *mno_header[] = {
    "User-Agent: gsma-rsp-lpad",
    "Content-Type: application/json",
    NULL,
};

static char *build_url(const char *mno_url, const char *path) {
    char *out = NULL;
    const int has_scheme = strstr(mno_url, "://") != NULL;
    const char *prefix = has_scheme ? "" : "https://";
    out = malloc(strlen(prefix) + strlen(mno_url) + strlen(path) + 1);
    if (!out) {
        return NULL;
    }
    out[0] = '\0';
    strcat(out, prefix);
    strcat(out, mno_url);
    strcat(out, path);
    return out;
}

static int mno_trans_json(struct euicc_ctx *ctx, const char *mno_url, const char *path,
                          cJSON *tx, cJSON **rx) {
    int fret = 0;
    char *url = NULL;
    char *tx_str = NULL;
    uint8_t *rbuf = NULL;
    uint32_t rlen = 0;
    uint32_t rcode = 0;

    *rx = NULL;
    if (!ctx->http.interface) {
        goto err;
    }
    url = build_url(mno_url, path);
    if (!url) {
        goto err;
    }
    tx_str = cJSON_PrintUnformatted(tx);
    if (!tx_str) {
        goto err;
    }

    euicc_http_request_print(ctx->http.log_fp, url, tx_str);
    if (ctx->http.interface->transmit(ctx, url, &rcode, &rbuf, &rlen, (const uint8_t *)tx_str,
                                      strlen(tx_str), mno_header) < 0) {
        fprintf(stderr, "MNO HTTP transmit failed: %s\n", url);
        goto err;
    }
    euicc_http_response_print(ctx->http.log_fp, rcode, (char *)rbuf);
    if (rcode / 100 != 2) {
        fprintf(stderr, "MNO HTTP returned %u from %s: %.*s\n", rcode, url, (int)rlen, rbuf ? (char *)rbuf : "");
        goto err;
    }
    *rx = cJSON_ParseWithLength((const char *)rbuf, rlen);
    if (!*rx) {
        fprintf(stderr, "MNO HTTP returned invalid JSON from %s: %.*s\n", url, (int)rlen, rbuf ? (char *)rbuf : "");
        goto err;
    }
    goto exit;

err:
    fret = -1;
    cJSON_Delete(*rx);
    *rx = NULL;
exit:
    free(url);
    cJSON_free(tx_str);
    free(rbuf);
    return fret;
}

static int take_string(cJSON *root, const char *key, char **out) {
    cJSON *item = cJSON_GetObjectItem(root, key);
    if (!cJSON_IsString(item)) {
        fprintf(stderr, "MNO response missing string field: %s\n", key);
        return -1;
    }
    *out = strdup(item->valuestring);
    return *out ? 0 : -1;
}

int es12p_get_mno_challenge(struct euicc_ctx *ctx, const char *mno_url,
                            char **out_b64_mno_challenge, char **out_request_id) {
    int fret = 0;
    cJSON *tx = cJSON_CreateObject();
    cJSON *rx = NULL;

    *out_b64_mno_challenge = NULL;
    *out_request_id = NULL;
    if (!tx) {
        goto err;
    }
    if (mno_trans_json(ctx, mno_url, "/zk-esim/v1/getMNOChallenge", tx, &rx) < 0) {
        goto err;
    }
    if (take_string(rx, "mnoChallenge", out_b64_mno_challenge) < 0) {
        goto err;
    }
    if (take_string(rx, "requestId", out_request_id) < 0) {
        goto err;
    }
    goto exit;

err:
    fret = -1;
    free(*out_b64_mno_challenge);
    free(*out_request_id);
    *out_b64_mno_challenge = NULL;
    *out_request_id = NULL;
exit:
    cJSON_Delete(tx);
    cJSON_Delete(rx);
    return fret;
}

int es12p_zk_request(struct euicc_ctx *ctx, const char *mno_url, const char *request_id,
                     const char *b64_zk_profile_response, const char *matching_id,
                     char **out_b64_set_eligibility_req, char **out_iccid,
                     char **out_matching_id, char **out_smdp_address) {
    int fret = 0;
    cJSON *tx = cJSON_CreateObject();
    cJSON *rx = NULL;

    *out_b64_set_eligibility_req = NULL;
    *out_iccid = NULL;
    *out_matching_id = NULL;
    *out_smdp_address = NULL;
    if (!tx) {
        goto err;
    }
    cJSON_AddStringToObject(tx, "requestId", request_id);
    cJSON_AddStringToObject(tx, "zkProfileResponse_b64", b64_zk_profile_response);
    cJSON_AddStringOrNullToObject(tx, "matchingId", matching_id);
    if (mno_trans_json(ctx, mno_url, "/zk-esim/v1/zkRequest", tx, &rx) < 0) {
        goto err;
    }
    if (take_string(rx, "setEligibilityDataRequest", out_b64_set_eligibility_req) < 0) {
        goto err;
    }
    if (take_string(rx, "iccid", out_iccid) < 0) {
        goto err;
    }
    if (take_string(rx, "matchingId", out_matching_id) < 0) {
        goto err;
    }
    if (take_string(rx, "smdpAddress", out_smdp_address) < 0) {
        goto err;
    }
    goto exit;

err:
    fret = -1;
    free(*out_b64_set_eligibility_req);
    free(*out_iccid);
    free(*out_matching_id);
    free(*out_smdp_address);
    *out_b64_set_eligibility_req = NULL;
    *out_iccid = NULL;
    *out_matching_id = NULL;
    *out_smdp_address = NULL;
exit:
    cJSON_Delete(tx);
    cJSON_Delete(rx);
    return fret;
}

int es12p_ack(struct euicc_ctx *ctx, const char *mno_url, const char *request_id, bool ok) {
    int fret = 0;
    cJSON *tx = cJSON_CreateObject();
    cJSON *rx = NULL;
    if (!tx) {
        goto err;
    }
    cJSON_AddStringToObject(tx, "requestId", request_id);
    cJSON_AddBoolToObject(tx, "ok", ok);
    if (mno_trans_json(ctx, mno_url, "/zk-esim/v1/ack", tx, &rx) < 0) {
        goto err;
    }
    goto exit;

err:
    fret = -1;
exit:
    cJSON_Delete(tx);
    cJSON_Delete(rx);
    return fret;
}
