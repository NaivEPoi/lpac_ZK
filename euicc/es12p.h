#pragma once

#include <stdbool.h>

#include "euicc.h"

int es12p_get_mno_challenge(struct euicc_ctx *ctx, const char *mno_url,
                            char **out_b64_mno_challenge, char **out_request_id);
int es12p_zk_request(struct euicc_ctx *ctx, const char *mno_url, const char *request_id,
                     const char *b64_zk_profile_response, const char *matching_id,
                     char **out_b64_set_eligibility_req, char **out_iccid,
                     char **out_matching_id, char **out_smdp_address);
int es12p_ack(struct euicc_ctx *ctx, const char *mno_url, const char *request_id, bool ok);
