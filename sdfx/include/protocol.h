/*
 * Copyright (C) 2025 SDFX Project
 * SDFX is licensed under Mulan PSL v2.
 */

/**
 * @file protocol.h
 * @brief SDFX protocol definitions
 */

#ifndef SDFX_PROTOCOL_H
#define SDFX_PROTOCOL_H

#include "sdf_types.h"
#include "sdfx_defaults.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* protocol magic number */
#define SDFX_PROTOCOL_MAGIC     0x53444658  /* "SDFX" */
#define SDFX_MAGIC              SDFX_PROTOCOL_MAGIC

/* protocol version */
#define SDFX_PROTOCOL_VERSION   0x00020000  /* 2.0: fixed-width wire handles */

/* Network configuration - use unified default configuration */
/* SDFX_DEFAULT_PORT is now defined in common/include/sdfx_defaults.h */

/* Limit constants */
#define SDFX_MAX_RANDOM_LENGTH  65536

/* Message type definitions */
#define SDFX_CMD_OPEN_DEVICE            0x0001
#define SDFX_CMD_CLOSE_DEVICE           0x0002
#define SDFX_CMD_OPEN_SESSION           0x0003
#define SDFX_CMD_CLOSE_SESSION          0x0004
#define SDFX_CMD_GET_DEVICE_INFO        0x0005
#define SDFX_CMD_GENERATE_RANDOM        0x0006
#define SDFX_CMD_HASH_INIT              0x0010
#define SDFX_CMD_HASH_UPDATE            0x0011
#define SDFX_CMD_HASH_FINAL             0x0012
#define SDFX_CMD_ENCRYPT                0x0020
#define SDFX_CMD_DECRYPT                0x0021
#define SDFX_CMD_INTERNAL_SIGN_ECC      0x0030
#define SDFX_CMD_INTERNAL_VERIFY_ECC    0x0031
#define SDFX_CMD_EXTERNAL_ENCRYPT_ECC   0x0032
#define SDFX_CMD_EXTERNAL_DECRYPT_ECC   0x0033
#define SDFX_CMD_GENERATE_KEYPAIR_ECC   0x0034
#define SDFX_CMD_EXTERNAL_SIGN_ECC      0x0035
#define SDFX_CMD_EXTERNAL_VERIFY_ECC    0x0036
#define SDFX_CMD_GENERATE_KEY_KEK       0x0040
#define SDFX_CMD_IMPORT_KEY_KEK         0x0041
#define SDFX_CMD_DESTROY_KEY            0x0042
#define SDFX_CMD_CALCULATE_MAC          0x0043
#define SDFX_CMD_CREATE_FILE            0x0050
#define SDFX_CMD_READ_FILE              0x0051
#define SDFX_CMD_WRITE_FILE             0x0052
#define SDFX_CMD_DELETE_FILE            0x0053
#define SDFX_CMD_GET_PRIVATE_ACCESS     0x0054
#define SDFX_CMD_RELEASE_PRIVATE_ACCESS 0x0055
#define SDFX_CMD_EXPORT_SIGN_PUB_ECC    0x0056
#define SDFX_CMD_EXPORT_ENC_PUB_ECC     0x0057
#define SDFX_CMD_GENERATE_KEY_IPK_ECC   0x0058
#define SDFX_CMD_GENERATE_KEY_EPK_ECC   0x0059
#define SDFX_CMD_IMPORT_KEY_ISK_ECC     0x005A
#define SDFX_CMD_ADMIN_STATUS            0x0060
#define SDFX_CMD_ADMIN_KEY_LIST          0x0061
#define SDFX_CMD_ADMIN_KEY_CREATE        0x0062
#define SDFX_CMD_ADMIN_KEY_DELETE        0x0063
#define SDFX_CMD_ADMIN_KEY_ENABLE        0x0064
#define SDFX_CMD_ADMIN_KEY_DISABLE       0x0065
#define SDFX_CMD_ADMIN_KEY_PUBLIC        0x0066
#define SDFX_CMD_ADMIN_KEY_PASSWORD      0x0067
#define SDFX_CMD_ADMIN_DEVICE_CONFIG      0x0068
#define SDFX_CMD_ADMIN_SESSION_LIST        0x0069
#define SDFX_CMD_ADMIN_SESSION_CLOSE       0x006A
#define SDFX_CMD_ADMIN_KEK_LIST            0x006B
#define SDFX_CMD_ADMIN_KEK_CREATE          0x006C
#define SDFX_CMD_ADMIN_KEK_DELETE          0x006D
#define SDFX_CMD_ADMIN_KEK_ENABLE          0x006E
#define SDFX_CMD_ADMIN_KEK_DISABLE         0x006F
#define SDFX_CMD_ADMIN_BACKUP_LIST         0x0070
#define SDFX_CMD_ADMIN_BACKUP_CREATE       0x0071
#define SDFX_CMD_ADMIN_BACKUP_RESTORE      0x0072
#define SDFX_CMD_ADMIN_BACKUP_DELETE       0x0073
#define SDFX_CMD_ADMIN_DEVICE_RESET        0x0074
#define SDFX_CMD_ADMIN_SELFTEST            0x0075
#define SDFX_CMD_ADMIN_INTEGRITY_INIT      0x0076
#define SDFX_CMD_ADMIN_KEY_VERIFY          0x0077
#define SDFX_CMD_ADMIN_KEY_REINDEX         0x0078
#define SDFX_CMD_ADMIN_RSA_KEY_LIST        0x0079
#define SDFX_CMD_ADMIN_RSA_KEY_CREATE      0x007A
#define SDFX_CMD_ADMIN_RSA_KEY_DELETE      0x007B
#define SDFX_CMD_ADMIN_RSA_KEY_ENABLE      0x007C
#define SDFX_CMD_ADMIN_RSA_KEY_DISABLE     0x007D
#define SDFX_CMD_ADMIN_RSA_KEY_PUBLIC      0x007E
#define SDFX_CMD_ADMIN_RSA_KEY_PASSWORD    0x007F
#define SDFX_CMD_ADMIN_RSA_KEY_VERIFY      0x0080
#define SDFX_CMD_ADMIN_RSA_KEY_REINDEX     0x0081
#define SDFX_CMD_EXPORT_SIGN_PUB_RSA       0x0082
#define SDFX_CMD_EXPORT_ENC_PUB_RSA        0x0083
#define SDFX_CMD_GENERATE_KEY_IPK_RSA      0x0084
#define SDFX_CMD_GENERATE_KEY_EPK_RSA      0x0085
#define SDFX_CMD_IMPORT_KEY_ISK_RSA        0x0086
#define SDFX_CMD_EXTERNAL_PUBLIC_RSA       0x0087
#define SDFX_CMD_INTERNAL_PUBLIC_RSA       0x0088
#define SDFX_CMD_INTERNAL_PRIVATE_RSA      0x0089
#define SDFX_CMD_GENERATE_KEYPAIR_RSA      0x008A
#define SDFX_CMD_EXTERNAL_PRIVATE_RSA      0x008B
#define SDFX_CMD_ADMIN_KEK_VERIFY          0x008C
#define SDFX_CMD_EXTENDED_OPERATION         0x0090

/*
 * Wire structures are packed deliberately. All multi-byte scalar values are
 * fixed-width and converted to/from network byte order at the boundary.
 */
#pragma pack(push, 1)

/* Message header structure */
typedef struct sdfx_message_header {
    uint32_t magic;
    uint32_t version;
    uint32_t cmd;
    uint32_t length;
    uint32_t session_id;
    uint32_t status;
    uint32_t reserved[2];
} sdfx_message_header_t;

typedef uint64_t sdfx_remote_handle_t;

/* Complete message structure */
typedef struct sdfx_message {
    sdfx_message_header_t header;
    BYTE data[0];       /* variable length data */
} sdfx_message_t;

/* Message header size */
#define SDFX_MESSAGE_HEADER_SIZE    sizeof(sdfx_message_header_t)

/* Maximum message size */
#define SDFX_MAX_MESSAGE_SIZE       (64 * 1024)  /* 64KB */
/* SM2 ENTL is a 16-bit bit length, so the identity is at most 8191 bytes. */
#define SDFX_MAX_SM2_ID_LENGTH      8191U

/* Various request/response data structures */

/* Open device request */
typedef struct sdfx_open_device_req {
    ULONG device_type;      /* device type */
    BYTE reserved[16];      /* reserved */
} sdfx_open_device_req_t;

/* Open device response */
typedef struct sdfx_open_device_resp {
    sdfx_remote_handle_t device_handle;
} sdfx_open_device_resp_t;

/* Close device request */
typedef struct sdfx_close_device_req {
    sdfx_remote_handle_t device_handle;
} sdfx_close_device_req_t;

/* Close device response */
typedef struct sdfx_close_device_resp {
    BYTE reserved[4];       /* reserved field */
} sdfx_close_device_resp_t;

/* Open session request */
typedef struct sdfx_open_session_req {
    sdfx_remote_handle_t device_handle;
} sdfx_open_session_req_t;

/* Open session response */
typedef struct sdfx_open_session_resp {
    sdfx_remote_handle_t session_handle;
} sdfx_open_session_resp_t;

/* Close session request */
typedef struct sdfx_close_session_req {
    sdfx_remote_handle_t session_handle;
} sdfx_close_session_req_t;

/* Close session response */
typedef struct sdfx_close_session_resp {
    BYTE reserved[4];       /* reserved field */
} sdfx_close_session_resp_t;

/* Get device info request */
typedef struct sdfx_get_device_info_req {
    sdfx_remote_handle_t session_handle;
} sdfx_get_device_info_req_t;

/* Get device info response */
typedef struct sdfx_get_device_info_resp {
    DEVICEINFO device_info; /* device information */
} sdfx_get_device_info_resp_t;

/* Generate random number request */
typedef struct sdfx_generate_random_req {
    sdfx_remote_handle_t session_handle;
    ULONG length;          /* random number length */
} sdfx_generate_random_req_t;

/* Generate random number response */
typedef struct sdfx_generate_random_resp {
    ULONG length;          /* actual random number length */
    BYTE random_data[0];   /* random number data */
} sdfx_generate_random_resp_t;

/* Hash initialize request */
typedef struct sdfx_hash_init_req {
    sdfx_remote_handle_t session_handle;
    ULONG alg_id;             /* algorithm ID */
    ECCrefPublicKey public_key; /* SM2 public key (optional) */
    ULONG id_length;          /* ID length */
    BYTE id_data[0];          /* ID data */
} sdfx_hash_init_req_t;

/* Hash initialize response */
typedef struct sdfx_hash_init_resp {
    /* No response data */
} sdfx_hash_init_resp_t;

/* Hash update request */
typedef struct sdfx_hash_update_req {
    sdfx_remote_handle_t session_handle;
    ULONG data_length;     /* data length */
    BYTE data[0];          /* data to be hashed */
} sdfx_hash_update_req_t;

/* Hash update response */
typedef struct sdfx_hash_update_resp {
    /* No response data */
} sdfx_hash_update_resp_t;

/* Hash final request */
typedef struct sdfx_hash_final_req {
    sdfx_remote_handle_t session_handle;
} sdfx_hash_final_req_t;

/* Hash final response */
typedef struct sdfx_hash_final_resp {
    ULONG hash_length;     /* hash value length */
    BYTE hash_data[0];     /* hash value data */
} sdfx_hash_final_resp_t;

/* Encrypt request */
typedef struct sdfx_encrypt_req {
    sdfx_remote_handle_t session_handle;
    sdfx_remote_handle_t key_handle;
    ULONG alg_id;          /* algorithm ID */
    ULONG iv_length;       /* IV length */
    ULONG data_length;     /* data length */
    BYTE payload[0];       /* IV + data */
} sdfx_encrypt_req_t;

/* Encrypt response */
typedef struct sdfx_encrypt_resp {
    ULONG enc_data_length; /* ciphertext length */
    BYTE enc_data[0];      /* ciphertext data */
} sdfx_encrypt_resp_t;

/* Decrypt request */
typedef struct sdfx_decrypt_req {
    sdfx_remote_handle_t session_handle;
    sdfx_remote_handle_t key_handle;
    ULONG alg_id;          /* algorithm ID */
    ULONG iv_length;       /* IV length */
    ULONG enc_data_length; /* ciphertext length */
    BYTE payload[0];       /* IV + ciphertext */
} sdfx_decrypt_req_t;

/* Decrypt response */
typedef struct sdfx_decrypt_resp {
    ULONG data_length;     /* plaintext length */
    BYTE data[0];          /* plaintext data */
} sdfx_decrypt_resp_t;

/* ECC internal sign request */
typedef struct sdfx_internal_sign_ecc_req {
    sdfx_remote_handle_t session_handle;
    ULONG key_index;       /* private key index */
    ULONG data_length;     /* data length */
    BYTE data[0];          /* data to be signed */
} sdfx_internal_sign_ecc_req_t;

/* ECC internal sign response */
typedef struct sdfx_internal_sign_ecc_resp {
    ECCSignature signature; /* signature value */
} sdfx_internal_sign_ecc_resp_t;

/* ECC internal verify request */
typedef struct sdfx_internal_verify_ecc_req {
    sdfx_remote_handle_t session_handle;
    ULONG key_index;       /* public key index */
    ULONG data_length;     /* data length */
    ECCSignature signature; /* signature value */
    BYTE data[0];          /* data to be verified */
} sdfx_internal_verify_ecc_req_t;

/* ECC external encrypt request */
typedef struct sdfx_external_encrypt_ecc_req {
    sdfx_remote_handle_t session_handle;
    ULONG alg_id;             /* algorithm ID */
    ECCrefPublicKey public_key; /* public key */
    ULONG data_length;        /* data length */
    BYTE data[0];             /* data to be encrypted */
} sdfx_external_encrypt_ecc_req_t;

/* ECC external encrypt response */
typedef struct sdfx_external_encrypt_ecc_resp {
    ECCCipher cipher;         /* variable-length ciphertext, followed by cipher.L-1 bytes */
} sdfx_external_encrypt_ecc_resp_t;

/* ECC external decrypt request */
typedef struct sdfx_external_decrypt_ecc_req {
    sdfx_remote_handle_t session_handle;
    ULONG alg_id;               /* algorithm ID */
    ECCrefPrivateKey private_key; /* private key */
    ECCCipher cipher;           /* variable-length ciphertext, followed by cipher.L-1 bytes */
} sdfx_external_decrypt_ecc_req_t;

/* ECC external decrypt response */
typedef struct sdfx_external_decrypt_ecc_resp {
    ULONG data_length;         /* plaintext length */
    BYTE data[0];              /* plaintext data */
} sdfx_external_decrypt_ecc_resp_t;

/* ECC key pair generate request */
typedef struct sdfx_generate_keypair_ecc_req {
    sdfx_remote_handle_t session_handle;
    ULONG alg_id;             /* algorithm ID (SGD_SM2_1/2/3) */
} sdfx_generate_keypair_ecc_req_t;

/* ECC key pair generate response */
typedef struct sdfx_generate_keypair_ecc_resp {
    ECCrefPublicKey public_key;   /* Generated public key */
    ECCrefPrivateKey private_key; /* Generated private key */
} sdfx_generate_keypair_ecc_resp_t;

/* ECC external sign request */
typedef struct sdfx_external_sign_ecc_req {
    sdfx_remote_handle_t session_handle;
    ULONG alg_id;               /* algorithm ID */
    ECCrefPrivateKey private_key; /* private key */
    ULONG data_length;          /* data length */
    BYTE data[0];               /* data to be signed */
} sdfx_external_sign_ecc_req_t;

/* ECC external sign response */
typedef struct sdfx_external_sign_ecc_resp {
    ULONG signature_length;     /* signature length */
    BYTE signature[0];          /* signature data */
} sdfx_external_sign_ecc_resp_t;

/* ECC external verify request */
typedef struct sdfx_external_verify_ecc_req {
    sdfx_remote_handle_t session_handle;
    ULONG alg_id;              /* algorithm ID */
    ECCrefPublicKey public_key; /* public key */
    ULONG data_length;         /* data length */
    ULONG signature_length;    /* signature length */
    BYTE payload[0];           /* data + signature */
} sdfx_external_verify_ecc_req_t;

/* ECC external verify response */
typedef struct sdfx_external_verify_ecc_resp {
    ULONG result;              /* verify result (0=success) */
} sdfx_external_verify_ecc_resp_t;

#define SDFX_MAX_BLOB_LENGTH 32768U
#define SDFX_MAX_FILE_NAME   128U
#define SDFX_MAX_FILE_SIZE   (1024U * 1024U)

typedef struct sdfx_blob_req {
    sdfx_remote_handle_t session_handle;
    sdfx_remote_handle_t object_handle;
    uint32_t param[4];
    uint32_t data_length;
    BYTE data[0];
} sdfx_blob_req_t;

typedef struct sdfx_blob_resp {
    sdfx_remote_handle_t object_handle;
    uint32_t param[4];
    uint32_t data_length;
    BYTE data[0];
} sdfx_blob_resp_t;
/* GM/T 0018-2023 operations added after protocol v2. */
#define SDFX_EXT_SYM_INIT               1U
#define SDFX_EXT_SYM_UPDATE             2U
#define SDFX_EXT_SYM_FINAL              3U
#define SDFX_EXT_MAC_INIT               4U
#define SDFX_EXT_MAC_UPDATE             5U
#define SDFX_EXT_MAC_FINAL              6U
#define SDFX_EXT_HMAC_INIT              7U
#define SDFX_EXT_HMAC_UPDATE            8U
#define SDFX_EXT_HMAC_FINAL             9U
#define SDFX_EXT_AUTH_ONESHOT          10U
#define SDFX_EXT_AUTH_INIT             11U
#define SDFX_EXT_AUTH_UPDATE           12U
#define SDFX_EXT_AUTH_FINAL            13U
#define SDFX_EXT_EXTERNAL_CRYPT        14U
#define SDFX_EXT_EXTERNAL_SYM_INIT     15U
#define SDFX_EXT_EXTERNAL_HMAC_INIT    16U
#define SDFX_EXT_AGREEMENT_SPONSOR     20U
#define SDFX_EXT_AGREEMENT_KEY         21U
#define SDFX_EXT_AGREEMENT_RESPONSE    22U
#define SDFX_EXT_VPN_IKE               30U
#define SDFX_EXT_VPN_IKE_EPK           31U
#define SDFX_EXT_VPN_IPSEC             32U
#define SDFX_EXT_VPN_IPSEC_EPK         33U
#define SDFX_EXT_VPN_SSL               34U
#define SDFX_EXT_VPN_SSL_EPK           35U

typedef struct sdfx_extended_req {
    sdfx_remote_handle_t session_handle;
    sdfx_remote_handle_t object_handle;
    uint32_t operation;
    uint32_t alg_id;
    uint32_t param[8];
    uint32_t data_length;
    BYTE data[0];
} sdfx_extended_req_t;

typedef struct sdfx_extended_resp {
    sdfx_remote_handle_t object_handle;
    uint32_t param[8];
    uint32_t data_length;
    BYTE data[0];
} sdfx_extended_resp_t;

#pragma pack(pop)

SDFX_STATIC_ASSERT(sizeof(sdfx_message_header_t) == 32,
                   "unexpected SDFX header size");
SDFX_STATIC_ASSERT(sizeof(sdfx_blob_req_t) == 36,
                   "unexpected SDFX blob request size");
SDFX_STATIC_ASSERT(sizeof(sdfx_blob_resp_t) == 28,
                   "unexpected SDFX blob response size");
SDFX_STATIC_ASSERT(sizeof(sdfx_extended_req_t) == 60,
                   "unexpected SDFX extended request size");
SDFX_STATIC_ASSERT(sizeof(sdfx_extended_resp_t) == 44,
                   "unexpected SDFX extended response size");

/**
 * @brief Create message
 * @param cmd Command type
 * @param session_id Session ID
 * @param data Data pointer
 * @param data_len Data length
 * @param msg_len Returns the total message length
 * @return Message pointer, needs to be freed by the caller
 */
sdfx_message_t* sdfx_message_create(ULONG cmd, ULONG session_id, 
                                   const void *data, ULONG data_len, 
                                   ULONG *msg_len);

/**
 * @brief Destroy message
 * @param msg Message pointer
 */
void sdfx_message_destroy(sdfx_message_t *msg);

/**
 * @brief Validate message header
 * @param header Message header pointer
 * @return 0 for success, non-zero for failure
 */
int sdfx_message_validate_header(const sdfx_message_header_t *header);

/**
 * @brief Serialize message header to network byte order
 * @param header Message header pointer
 */
void sdfx_message_header_to_network(sdfx_message_header_t *header);

/**
 * @brief Deserialize message header from network byte order
 * @param header Message header pointer
 */
void sdfx_message_header_from_network(sdfx_message_header_t *header);

/**
 * @brief Byte order conversion functions
 */
static inline uint32_t sdfx_bswap32(uint32_t value)
{
    return ((value & 0x000000ffU) << 24) | ((value & 0x0000ff00U) << 8) |
           ((value & 0x00ff0000U) >> 8) | ((value & 0xff000000U) >> 24);
}

static inline ULONG sdfx_htonl(ULONG value)
{
    const uint16_t marker = 1;
    return (*(const uint8_t *)&marker == 0) ? value : sdfx_bswap32(value);
}

static inline ULONG sdfx_ntohl(ULONG value)
{
    return sdfx_htonl(value);
}

static inline sdfx_remote_handle_t sdfx_htonll(sdfx_remote_handle_t value)
{
    const uint16_t marker = 1;
    if (*(const uint8_t *)&marker == 0) {
        return value;
    }
    return ((uint64_t)sdfx_htonl((uint32_t)(value & 0xffffffffULL)) << 32) |
           sdfx_htonl((uint32_t)(value >> 32));
}

static inline sdfx_remote_handle_t sdfx_ntohll(sdfx_remote_handle_t value)
{
    return sdfx_htonll(value);
}

/**
 * @brief Map a protocol command code to the external SDF API function name.
 * Used by DEBUG logging so call traces show the SDF function being invoked.
 */
static inline const char *sdfx_cmd_name(uint32_t cmd)
{
    switch (cmd) {
        case SDFX_CMD_OPEN_DEVICE:           return "SDF_OpenDevice";
        case SDFX_CMD_CLOSE_DEVICE:          return "SDF_CloseDevice";
        case SDFX_CMD_OPEN_SESSION:          return "SDF_OpenSession";
        case SDFX_CMD_CLOSE_SESSION:         return "SDF_CloseSession";
        case SDFX_CMD_GET_DEVICE_INFO:       return "SDF_GetDeviceInfo";
        case SDFX_CMD_GENERATE_RANDOM:       return "SDF_GenerateRandom";
        case SDFX_CMD_HASH_INIT:             return "SDF_HashInit";
        case SDFX_CMD_HASH_UPDATE:           return "SDF_HashUpdate";
        case SDFX_CMD_HASH_FINAL:            return "SDF_HashFinal";
        case SDFX_CMD_ENCRYPT:               return "SDF_Encrypt";
        case SDFX_CMD_DECRYPT:               return "SDF_Decrypt";
        case SDFX_CMD_INTERNAL_SIGN_ECC:     return "SDF_InternalSign_ECC";
        case SDFX_CMD_INTERNAL_VERIFY_ECC:   return "SDF_InternalVerify_ECC";
        case SDFX_CMD_EXTERNAL_ENCRYPT_ECC:  return "SDF_ExternalEncrypt_ECC";
        case SDFX_CMD_EXTERNAL_DECRYPT_ECC:  return "SDF_ExternalDecrypt_ECC";
        case SDFX_CMD_GENERATE_KEYPAIR_ECC:  return "SDF_GenerateKeyPair_ECC";
        case SDFX_CMD_EXTERNAL_SIGN_ECC:     return "SDF_ExternalSign_ECC";
        case SDFX_CMD_EXTERNAL_VERIFY_ECC:   return "SDF_ExternalVerify_ECC";
        case SDFX_CMD_GENERATE_KEY_KEK:      return "SDF_GenerateKeyWithKEK";
        case SDFX_CMD_IMPORT_KEY_KEK:        return "SDF_ImportKeyWithKEK";
        case SDFX_CMD_DESTROY_KEY:           return "SDF_DestroyKey";
        case SDFX_CMD_CALCULATE_MAC:         return "SDF_CalculateMAC";
        case SDFX_CMD_CREATE_FILE:           return "SDF_CreateFile";
        case SDFX_CMD_READ_FILE:             return "SDF_ReadFile";
        case SDFX_CMD_WRITE_FILE:            return "SDF_WriteFile";
        case SDFX_CMD_DELETE_FILE:           return "SDF_DeleteFile";
        case SDFX_CMD_GET_PRIVATE_ACCESS:    return "SDF_GetPrivateKeyAccessRight";
        case SDFX_CMD_RELEASE_PRIVATE_ACCESS:return "SDF_ReleasePrivateKeyAccessRight";
        case SDFX_CMD_EXPORT_SIGN_PUB_ECC:   return "SDF_ExportSignPublicKey_ECC";
        case SDFX_CMD_EXPORT_ENC_PUB_ECC:    return "SDF_ExportEncPublicKey_ECC";
        case SDFX_CMD_GENERATE_KEY_IPK_ECC:  return "SDF_GenerateKeyWithIPK_ECC";
        case SDFX_CMD_GENERATE_KEY_EPK_ECC:  return "SDF_GenerateKeyWithEPK_ECC";
        case SDFX_CMD_IMPORT_KEY_ISK_ECC:    return "SDF_ImportKeyWithISK_ECC";
        case SDFX_CMD_ADMIN_STATUS:          return "AdminStatus";
        case SDFX_CMD_ADMIN_KEY_LIST:        return "AdminKeyList";
        case SDFX_CMD_ADMIN_KEY_CREATE:      return "AdminKeyCreate";
        case SDFX_CMD_ADMIN_KEY_DELETE:      return "AdminKeyDelete";
        case SDFX_CMD_ADMIN_KEY_ENABLE:      return "AdminKeyEnable";
        case SDFX_CMD_ADMIN_KEY_DISABLE:     return "AdminKeyDisable";
        case SDFX_CMD_ADMIN_KEY_PUBLIC:      return "AdminKeyPublic";
        case SDFX_CMD_ADMIN_KEY_PASSWORD:    return "AdminKeyPassword";
        case SDFX_CMD_ADMIN_DEVICE_CONFIG:   return "AdminDeviceConfig";
        case SDFX_CMD_ADMIN_SESSION_LIST:    return "AdminSessionList";
        case SDFX_CMD_ADMIN_SESSION_CLOSE:   return "AdminSessionClose";
        case SDFX_CMD_ADMIN_KEK_LIST:        return "AdminKekList";
        case SDFX_CMD_ADMIN_KEK_CREATE:      return "AdminKekCreate";
        case SDFX_CMD_ADMIN_KEK_DELETE:      return "AdminKekDelete";
        case SDFX_CMD_ADMIN_KEK_ENABLE:      return "AdminKekEnable";
        case SDFX_CMD_ADMIN_KEK_DISABLE:     return "AdminKekDisable";
        case SDFX_CMD_ADMIN_BACKUP_LIST:     return "AdminBackupList";
        case SDFX_CMD_ADMIN_BACKUP_CREATE:   return "AdminBackupCreate";
        case SDFX_CMD_ADMIN_BACKUP_RESTORE:  return "AdminBackupRestore";
        case SDFX_CMD_ADMIN_BACKUP_DELETE:   return "AdminBackupDelete";
        case SDFX_CMD_ADMIN_DEVICE_RESET:    return "AdminDeviceReset";
        case SDFX_CMD_ADMIN_SELFTEST:        return "AdminSelfTest";
        case SDFX_CMD_ADMIN_INTEGRITY_INIT:  return "AdminIntegrityInit";
        case SDFX_CMD_ADMIN_KEY_VERIFY:      return "AdminKeyVerify";
        case SDFX_CMD_ADMIN_KEY_REINDEX:     return "AdminKeyReindex";
        case SDFX_CMD_ADMIN_RSA_KEY_LIST:    return "AdminRsaKeyList";
        case SDFX_CMD_ADMIN_RSA_KEY_CREATE:  return "AdminRsaKeyCreate";
        case SDFX_CMD_ADMIN_RSA_KEY_DELETE:  return "AdminRsaKeyDelete";
        case SDFX_CMD_ADMIN_RSA_KEY_ENABLE:  return "AdminRsaKeyEnable";
        case SDFX_CMD_ADMIN_RSA_KEY_DISABLE: return "AdminRsaKeyDisable";
        case SDFX_CMD_ADMIN_RSA_KEY_PUBLIC:  return "AdminRsaKeyPublic";
        case SDFX_CMD_ADMIN_RSA_KEY_PASSWORD:return "AdminRsaKeyPassword";
        case SDFX_CMD_ADMIN_RSA_KEY_VERIFY:  return "AdminRsaKeyVerify";
        case SDFX_CMD_ADMIN_RSA_KEY_REINDEX: return "AdminRsaKeyReindex";
        case SDFX_CMD_EXPORT_SIGN_PUB_RSA:   return "SDF_ExportSignPublicKey_RSA";
        case SDFX_CMD_EXPORT_ENC_PUB_RSA:    return "SDF_ExportEncPublicKey_RSA";
        case SDFX_CMD_GENERATE_KEY_IPK_RSA:  return "SDF_GenerateKeyWithIPK_RSA";
        case SDFX_CMD_GENERATE_KEY_EPK_RSA:  return "SDF_GenerateKeyWithEPK_RSA";
        case SDFX_CMD_IMPORT_KEY_ISK_RSA:    return "SDF_ImportKeyWithISK_RSA";
        case SDFX_CMD_EXTERNAL_PUBLIC_RSA:   return "SDF_ExternalPublicKeyOperation_RSA";
        case SDFX_CMD_INTERNAL_PUBLIC_RSA:   return "SDF_InternalPublicKeyOperation_RSA";
        case SDFX_CMD_INTERNAL_PRIVATE_RSA:  return "SDF_InternalPrivateKeyOperation_RSA";
        case SDFX_CMD_GENERATE_KEYPAIR_RSA:  return "SDF_GenerateKeyPair_RSA";
        case SDFX_CMD_EXTERNAL_PRIVATE_RSA:  return "SDF_ExternalPrivateKeyOperation_RSA";
        case SDFX_CMD_ADMIN_KEK_VERIFY:      return "AdminKekVerify";
        case SDFX_CMD_EXTENDED_OPERATION:    return "SDF_ExtendedOperation";
        default:                             return "Unknown";
    }
}

#ifdef __cplusplus
}
#endif

#endif /* SDFX_PROTOCOL_H */
