#pragma once

#include <stdint.h>

struct euicc_ctx;

struct es12p_challenge_result {
    char *requestId;
    uint8_t mnoChallenge[16];
};

struct es12p_zk_request_result {
    char *setEligibilityDataB64;
    char *iccid;
    char *matchingId;
    char *smdpAddress;
};

struct es12p_register_challenge_result {
    char *requestId;
    char *mnoNonceCommitment;
};

int es12p_get_mno_challenge(struct euicc_ctx *ctx, const char *mno_addr, struct es12p_challenge_result *result);

int es12p_zk_request(struct euicc_ctx *ctx, const char *mno_addr, const char *request_id,
                     const char *b64_zk_response, struct es12p_zk_request_result *result);

int es12p_ack(struct euicc_ctx *ctx, const char *mno_addr, const char *request_id, int ok);

int es12p_register_challenge(struct euicc_ctx *ctx, const char *mno_addr,
                             struct es12p_register_challenge_result *result);
int es12p_register_credential(struct euicc_ctx *ctx, const char *mno_addr, const char *request_id,
                              const char *blinded_eligibility_challenge,
                              const char *device_auth_signature,
                              char **mno_partial_signature);
int es12p_cert_init_request(struct euicc_ctx *ctx, const char *pca_addr,
                            const char *user_public_key,
                            const char *binding_signature,
                            const char *credential_binding_hash,
                            char **pseudonym_certificate);

void es12p_challenge_result_free(struct es12p_challenge_result *result);
void es12p_zk_request_result_free(struct es12p_zk_request_result *result);
void es12p_register_challenge_result_free(struct es12p_register_challenge_result *result);
