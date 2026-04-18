#pragma once

#include "es10b.h"
#include "euicc.h"

#include <inttypes.h>


//* Added values for the updated authenticate client function - values for the eligibility bundle 
struct zk_eligibility_bundle {
    char *b64_transcript_nonce;
    char *b64_server_nonce;
    char *b64_pseudonym_cert;
    char *b64_auth_cred;
    char *b64_one_time_tok;
    char *b64_hashed_pseudonym;
    char *b64_inclusion_proof;
    char *b64_accum_root;
    char *b64_mno_root_sig;
    char *b64_session_binding;
};


int es9p_initiate_authentication_r(struct euicc_ctx *ctx, char **transaction_id,
                                   struct es10b_authenticate_server_param *resp, const char *server_address,
                                   const char *b64_euicc_challenge, const char *b64_euicc_info_1);

// int es9p_initiate_authentication_rzk(struct euicc_ctx *ctx, char **transaction_id,
//                                    struct es10b_authenticate_server_param *resp, const char *server_address,
//                                    const char *b64_euicc_challenge, const char *b64_euicc_info_1);

int es9p_get_bound_profile_package_r(struct euicc_ctx *ctx, char **b64_bound_profile_package,
                                     const char *server_address, const char *transaction_id,
                                     const char *b64_prepare_download_response);

int es9p_authenticate_client_r(struct euicc_ctx *ctx, struct es10b_prepare_download_param *resp,
                               const char *server_address, const char *transaction_id,
                               const char *b64_authenticate_server_response);

int es9p_authenticate_client_rzk(struct euicc_ctx *ctx, struct es10b_prepare_download_param *resp, 
                                const char *server_address, const char *transaction_id, 
                                const char *b64_authenticate_server_response);

int es9p_cancel_session_r(struct euicc_ctx *ctx, const char *server_address, const char *transaction_id,
                          const char *b64_cancel_session_response);

int es9p_initiate_authentication(struct euicc_ctx *ctx);
int es9p_get_bound_profile_package(struct euicc_ctx *ctx);
int es9p_authenticate_client(struct euicc_ctx *ctx);
int es9p_cancel_session(struct euicc_ctx *ctx);

int es11_authenticate_client_r(struct euicc_ctx *ctx, char ***smdp_list, const char *server_address,
                               const char *transaction_id, const char *b64_authenticate_server_response);
int es11_authenticate_client(struct euicc_ctx *ctx, char ***smdp_list);

int es9p_handle_notification(struct euicc_ctx *ctx, const char *b64_PendingNotification);
void es11_smdp_list_free_all(char **smdp_list);
