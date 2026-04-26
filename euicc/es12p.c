#include "es12p.h"
#include "base64.h"
#include "euicc.h"
#include "logger.h"

#include <stdlib.h>
#include <string.h>

#include <cjson/cJSON.h>
#include <cjson-ext/cJSON_ex.h>

static const char *mno_headers[] = {
    "User-Agent: gsma-rsp-lpad",
    "Content-Type: application/json",
    NULL,
};

static char *es12p_build_url(const char *mno_addr, const char *path) {
    char *url = NULL;
    const int has_scheme = strstr(mno_addr, "://") != NULL;
    const char *url_prefix = has_scheme ? "" : "https://";

    url = malloc(strlen(url_prefix) + strlen(mno_addr) + strlen(path) + 1);
    if (url == NULL) {
        return NULL;
    }
    url[0] = '\0';
    strcat(url, url_prefix);
    strcat(url, mno_addr);
    strcat(url, path);
    return url;
}

static int es12p_trans_ex(struct euicc_ctx *ctx, const char *mno_addr, const char *path, uint32_t *rcode, char **str_rx,
                          const char *str_tx) {
    int fret = 0;
    uint32_t rcode_local = 0;
    uint8_t *rbuf = NULL;
    uint32_t rlen;
    char *full_url = NULL;

    *str_rx = NULL;

    if (!ctx->http.interface) {
        goto err;
    }

    full_url = es12p_build_url(mno_addr, path);
    if (full_url == NULL) {
        goto err;
    }

    euicc_http_request_print(ctx->http.log_fp, full_url, str_tx);

    if (ctx->http.interface->transmit(ctx, full_url, &rcode_local, &rbuf, &rlen, (const uint8_t *)str_tx,
                                      (uint32_t)strlen(str_tx), mno_headers)
        < 0) {
        goto err;
    }

    euicc_http_response_print(ctx->http.log_fp, rcode_local, (char *)rbuf);

    free(full_url);
    full_url = NULL;

    *str_rx = malloc(rlen + 1);
    if (*str_rx == NULL) {
        goto err;
    }
    memcpy(*str_rx, rbuf, rlen);
    (*str_rx)[rlen] = '\0';

    free(rbuf);
    rbuf = NULL;

    *rcode = rcode_local;
    fret = 0;
    goto exit;

err:
    fret = -1;
exit:
    free(full_url);
    free(rbuf);
    return fret;
}

int es12p_get_mno_challenge(struct euicc_ctx *ctx, const char *mno_addr,
                            struct es12p_challenge_result *result) {
    int fret = 0;
    uint32_t rcode;
    char *rbuf = NULL;
    uint8_t *challenge = NULL;
    int challenge_len;
    cJSON *jroot = NULL;
    cJSON *j_request_id, *j_challenge;

    memset(result, 0, sizeof(*result));

    if (es12p_trans_ex(ctx, mno_addr, "/zk-esim/v1/getMNOChallenge", &rcode, &rbuf, "{}") < 0) {
        goto err;
    }
    if (rcode / 100 != 2) {
        goto err;
    }

    jroot = cJSON_Parse(rbuf);
    if (!jroot) {
        goto err;
    }

    j_request_id = cJSON_GetObjectItem(jroot, "requestId");
    j_challenge = cJSON_GetObjectItem(jroot, "mnoChallenge");

    if (!cJSON_IsString(j_request_id) || !cJSON_IsString(j_challenge)) {
        goto err;
    }

    result->requestId = strdup(j_request_id->valuestring);
    if (!result->requestId) {
        goto err;
    }

    challenge = malloc(euicc_base64_decode_len(j_challenge->valuestring));
    if (challenge == NULL) {
        goto err;
    }
    challenge_len = euicc_base64_decode(challenge, j_challenge->valuestring);
    if (challenge_len != (int)sizeof(result->mnoChallenge)) {
        goto err;
    }
    memcpy(result->mnoChallenge, challenge, sizeof(result->mnoChallenge));

    fret = 0;
    goto exit;

err:
    fret = -1;
    free(result->requestId);
    result->requestId = NULL;
exit:
    cJSON_Delete(jroot);
    free(challenge);
    free(rbuf);
    return fret;
}

int es12p_zk_request(struct euicc_ctx *ctx, const char *mno_addr, const char *request_id, const char *b64_zk_response,
                     struct es12p_zk_request_result *result) {
    int fret = 0;
    uint32_t rcode;
    char *rbuf = NULL;
    char *sbuf = NULL;
    cJSON *sjroot = NULL;
    cJSON *rjroot = NULL;
    cJSON *j_elig, *j_iccid, *j_mid, *j_smdp;

    memset(result, 0, sizeof(*result));

    sjroot = cJSON_CreateObject();
    if (!sjroot) {
        goto err;
    }
    cJSON_AddStringToObject(sjroot, "requestId", request_id);
    cJSON_AddStringToObject(sjroot, "zkProfileResponse", b64_zk_response);

    sbuf = cJSON_PrintUnformatted(sjroot);
    if (!sbuf) {
        goto err;
    }

    if (es12p_trans_ex(ctx, mno_addr, "/zk-esim/v1/zkRequest", &rcode, &rbuf, sbuf) < 0) {
        goto err;
    }
    if (rcode / 100 != 2) {
        goto err;
    }

    rjroot = cJSON_Parse(rbuf);
    if (!rjroot) {
        goto err;
    }

    j_elig = cJSON_GetObjectItem(rjroot, "setEligibilityDataRequest");
    j_iccid = cJSON_GetObjectItem(rjroot, "iccid");
    j_mid = cJSON_GetObjectItem(rjroot, "matchingId");
    j_smdp = cJSON_GetObjectItem(rjroot, "smdpAddress");

    if (!cJSON_IsString(j_elig) || !cJSON_IsString(j_iccid) || !cJSON_IsString(j_mid) || !cJSON_IsString(j_smdp)) {
        goto err;
    }

    result->setEligibilityDataB64 = strdup(j_elig->valuestring);
    result->iccid = strdup(j_iccid->valuestring);
    result->matchingId = strdup(j_mid->valuestring);
    result->smdpAddress = strdup(j_smdp->valuestring);

    if (!result->setEligibilityDataB64 || !result->iccid || !result->matchingId || !result->smdpAddress) {
        goto err;
    }

    fret = 0;
    goto exit;

err:
    fret = -1;
    es12p_zk_request_result_free(result);
exit:
    cJSON_Delete(sjroot);
    cJSON_Delete(rjroot);
    cJSON_free(sbuf);
    free(rbuf);
    return fret;
}

int es12p_ack(struct euicc_ctx *ctx, const char *mno_addr, const char *request_id, int ok) {
    int fret = 0;
    uint32_t rcode;
    char *rbuf = NULL;
    char *sbuf = NULL;
    cJSON *sjroot = NULL;

    sjroot = cJSON_CreateObject();
    if (!sjroot) {
        goto err;
    }
    cJSON_AddStringToObject(sjroot, "requestId", request_id);
    cJSON_AddBoolToObject(sjroot, "ok", ok);

    sbuf = cJSON_PrintUnformatted(sjroot);
    if (!sbuf) {
        goto err;
    }

    if (es12p_trans_ex(ctx, mno_addr, "/zk-esim/v1/ack", &rcode, &rbuf, sbuf) < 0) {
        goto err;
    }

    fret = 0;
    goto exit;

err:
    fret = -1;
exit:
    cJSON_Delete(sjroot);
    cJSON_free(sbuf);
    free(rbuf);
    return fret;
}

int es12p_register_challenge(struct euicc_ctx *ctx, const char *mno_addr,
                             struct es12p_register_challenge_result *result) {
    int fret = 0;
    uint32_t rcode;
    char *rbuf = NULL;
    cJSON *jroot = NULL;
    cJSON *j_request_id, *j_commitment;

    memset(result, 0, sizeof(*result));

    if (es12p_trans_ex(ctx, mno_addr, "/zk-esim/v1/registerChallenge", &rcode, &rbuf, "{}") < 0) {
        goto err;
    }
    if (rcode / 100 != 2) {
        goto err;
    }

    jroot = cJSON_Parse(rbuf);
    if (!jroot) {
        goto err;
    }
    j_request_id = cJSON_GetObjectItem(jroot, "requestId");
    j_commitment = cJSON_GetObjectItem(jroot, "mnoNonceCommitment");
    if (!cJSON_IsString(j_commitment)) {
        j_commitment = cJSON_GetObjectItem(jroot, "rMno");
    }
    if (!cJSON_IsString(j_request_id) || !cJSON_IsString(j_commitment)) {
        goto err;
    }

    result->requestId = strdup(j_request_id->valuestring);
    result->mnoNonceCommitment = strdup(j_commitment->valuestring);
    if (!result->requestId || !result->mnoNonceCommitment) {
        goto err;
    }

    goto exit;
err:
    fret = -1;
    es12p_register_challenge_result_free(result);
exit:
    cJSON_Delete(jroot);
    free(rbuf);
    return fret;
}

int es12p_register_credential(struct euicc_ctx *ctx, const char *mno_addr, const char *request_id,
                              const char *blinded_eligibility_challenge,
                              const char *device_auth_signature,
                              char **mno_partial_signature) {
    int fret = 0;
    uint32_t rcode;
    char *rbuf = NULL;
    char *sbuf = NULL;
    cJSON *sjroot = NULL;
    cJSON *rjroot = NULL;
    cJSON *j_sig;

    *mno_partial_signature = NULL;

    sjroot = cJSON_CreateObject();
    if (!sjroot) {
        goto err;
    }
    cJSON_AddStringToObject(sjroot, "requestId", request_id);
    cJSON_AddStringToObject(sjroot, "blindedEligibilityChallenge", blinded_eligibility_challenge);
    cJSON_AddStringToObject(sjroot, "deviceAuthSignature", device_auth_signature);

    sbuf = cJSON_PrintUnformatted(sjroot);
    if (!sbuf) {
        goto err;
    }
    if (es12p_trans_ex(ctx, mno_addr, "/zk-esim/v1/registerCredential", &rcode, &rbuf, sbuf) < 0) {
        goto err;
    }
    if (rcode / 100 != 2) {
        goto err;
    }

    rjroot = cJSON_Parse(rbuf);
    if (!rjroot) {
        goto err;
    }
    j_sig = cJSON_GetObjectItem(rjroot, "mnoPartialSignature");
    if (!cJSON_IsString(j_sig)) {
        j_sig = cJSON_GetObjectItem(rjroot, "s");
    }
    if (!cJSON_IsString(j_sig)) {
        goto err;
    }
    *mno_partial_signature = strdup(j_sig->valuestring);
    if (!*mno_partial_signature) {
        goto err;
    }

    goto exit;
err:
    fret = -1;
    free(*mno_partial_signature);
    *mno_partial_signature = NULL;
exit:
    cJSON_Delete(sjroot);
    cJSON_Delete(rjroot);
    cJSON_free(sbuf);
    free(rbuf);
    return fret;
}

int es12p_cert_init_request(struct euicc_ctx *ctx, const char *pca_addr,
                            const char *user_public_key,
                            const char *binding_signature,
                            const char *credential_binding_hash,
                            char **pseudonym_certificate) {
    int fret = 0;
    uint32_t rcode;
    char *rbuf = NULL;
    char *sbuf = NULL;
    cJSON *sjroot = NULL;
    cJSON *rjroot = NULL;
    cJSON *j_cert;

    *pseudonym_certificate = NULL;

    sjroot = cJSON_CreateObject();
    if (!sjroot) {
        goto err;
    }
    cJSON_AddStringToObject(sjroot, "userPublicKey", user_public_key);
    cJSON_AddStringToObject(sjroot, "bindingSignature", binding_signature);
    cJSON_AddStringToObject(sjroot, "credentialBindingHash", credential_binding_hash);

    sbuf = cJSON_PrintUnformatted(sjroot);
    if (!sbuf) {
        goto err;
    }
    if (es12p_trans_ex(ctx, pca_addr, "/zk-esim/v1/certInitRequest", &rcode, &rbuf, sbuf) < 0) {
        goto err;
    }
    if (rcode / 100 != 2) {
        goto err;
    }

    rjroot = cJSON_Parse(rbuf);
    if (!rjroot) {
        goto err;
    }
    j_cert = cJSON_GetObjectItem(rjroot, "pseudonymCertificate");
    if (!cJSON_IsString(j_cert)) {
        j_cert = cJSON_GetObjectItem(rjroot, "pCertU");
    }
    if (!cJSON_IsString(j_cert)) {
        goto err;
    }
    *pseudonym_certificate = strdup(j_cert->valuestring);
    if (!*pseudonym_certificate) {
        goto err;
    }

    goto exit;
err:
    fret = -1;
    free(*pseudonym_certificate);
    *pseudonym_certificate = NULL;
exit:
    cJSON_Delete(sjroot);
    cJSON_Delete(rjroot);
    cJSON_free(sbuf);
    free(rbuf);
    return fret;
}

void es12p_challenge_result_free(struct es12p_challenge_result *result) {
    if (!result) {
        return;
    }
    free(result->requestId);
    result->requestId = NULL;
}

void es12p_zk_request_result_free(struct es12p_zk_request_result *result) {
    if (!result) {
        return;
    }
    free(result->setEligibilityDataB64);
    free(result->iccid);
    free(result->matchingId);
    free(result->smdpAddress);
    result->setEligibilityDataB64 = NULL;
    result->iccid = NULL;
    result->matchingId = NULL;
    result->smdpAddress = NULL;
}

void es12p_register_challenge_result_free(struct es12p_register_challenge_result *result) {
    if (!result) {
        return;
    }
    free(result->requestId);
    free(result->mnoNonceCommitment);
    result->requestId = NULL;
    result->mnoNonceCommitment = NULL;
}
