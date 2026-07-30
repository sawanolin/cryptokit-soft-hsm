/* GM/T 0018 RSA client interfaces. */
#include "sdf_internal.h"

static LONG send_rsa_blob(ULONG command, sdfx_remote_handle_t session_id,
                          const uint32_t params[4], const BYTE *data,
                          uint32_t data_len, BYTE *response,
                          size_t response_capacity, size_t *response_len)
{
    if ((data_len && data == NULL) || data_len > SDFX_MAX_BLOB_LENGTH ||
        response == NULL || response_len == NULL) return SDR_INARGERR;
    size_t size = sizeof(sdfx_blob_req_t) + data_len;
    sdfx_blob_req_t *request = calloc(1, size);
    if (request == NULL) return SDR_NOBUFFER;
    request->session_handle = sdfx_htonll(session_id);
    for (size_t i = 0; i < 4; ++i) request->param[i] = sdfx_htonl(params ? params[i] : 0);
    request->data_length = sdfx_htonl(data_len);
    if (data_len) memcpy(request->data, data, data_len);
    LONG ret = sdf_send_request(command, request, size, response,
                                response_capacity, response_len);
    memset(request, 0, size); free(request); return ret;
}

static LONG rsa_blob_payload(BYTE *buffer, size_t response_len,
                             const BYTE **data, uint32_t *data_len,
                             sdfx_remote_handle_t *object_id)
{
    if (response_len < sizeof(sdfx_message_header_t) + sizeof(sdfx_blob_resp_t))
        return SDR_PROTOCOL_ERROR;
    sdfx_message_t *message = (sdfx_message_t *)buffer;
    sdfx_blob_resp_t *response = (sdfx_blob_resp_t *)message->data;
    uint32_t length = sdfx_ntohl(response->data_length);
    if (message->header.length < sizeof(*response) + length ||
        response_len < sizeof(sdfx_message_header_t) + sizeof(*response) + length)
        return SDR_PROTOCOL_ERROR;
    *data = response->data; *data_len = length;
    if (object_id) *object_id = sdfx_ntohll(response->object_handle);
    return SDR_OK;
}

static LONG rsa_create_local(sdfx_remote_handle_t remote_id, HANDLE *handle)
{
    if (remote_id == 0 || handle == NULL) return SDR_PROTOCOL_ERROR;
    sdfx_remote_handle_t *stored = malloc(sizeof(*stored));
    if (stored == NULL) return SDR_NOBUFFER;
    *stored = remote_id; *handle = handle_manager_create_key_with_data(stored);
    if (*handle == NULL) { free(stored); return SDR_NOBUFFER; }
    return SDR_OK;
}

static LONG rsa_export_public(HANDLE session, ULONG index, ULONG command,
                              RSArefPublicKey *public_key)
{
    if (session == NULL || index == 0 || public_key == NULL) return SDR_INARGERR;
    sdfx_remote_handle_t sid; SDF_CHECK_SESSION(session, sid);
    uint32_t params[4] = {index,0,0,0};
    BYTE response[sizeof(sdfx_message_header_t)+sizeof(sdfx_blob_resp_t)+sizeof(RSArefPublicKey)];
    size_t response_len=0; LONG ret=send_rsa_blob(command,sid,params,NULL,0,response,sizeof(response),&response_len);
    const BYTE *data;uint32_t length;if(ret==SDR_OK)ret=rsa_blob_payload(response,response_len,&data,&length,NULL);
    if(ret==SDR_OK&&length!=sizeof(*public_key))ret=SDR_PROTOCOL_ERROR;
    if(ret==SDR_OK)memcpy(public_key,data,sizeof(*public_key));return ret;
}

LONG SDF_ExportSignPublicKey_RSA(HANDLE hSessionHandle, ULONG uiKeyIndex,
                                 RSArefPublicKey *pucPublicKey)
{return rsa_export_public(hSessionHandle,uiKeyIndex,SDFX_CMD_EXPORT_SIGN_PUB_RSA,pucPublicKey);}
LONG SDF_ExportEncPublicKey_RSA(HANDLE hSessionHandle, ULONG uiKeyIndex,
                                RSArefPublicKey *pucPublicKey)
{return rsa_export_public(hSessionHandle,uiKeyIndex,SDFX_CMD_EXPORT_ENC_PUB_RSA,pucPublicKey);}

static LONG rsa_parse_wrapped(BYTE *response,size_t response_len,BYTE *wrapped,
                              ULONG *wrapped_len,HANDLE *handle)
{
    const BYTE *data;uint32_t length;sdfx_remote_handle_t object_id;
    LONG ret=rsa_blob_payload(response,response_len,&data,&length,&object_id);
    if(ret!=SDR_OK)return ret;if(length==0||length>RSAref_MAX_LEN)return SDR_PROTOCOL_ERROR;
    if(*wrapped_len<length){*wrapped_len=length;return SDR_NOBUFFER;}
    memcpy(wrapped,data,length);*wrapped_len=length;return rsa_create_local(object_id,handle);
}

LONG SDF_GenerateKeyWithIPK_RSA(HANDLE hSessionHandle,ULONG uiIPKIndex,
    ULONG uiKeyBits,BYTE *pucKey,ULONG *puiKeyLength,HANDLE *phKeyHandle)
{
    if(hSessionHandle==NULL||uiIPKIndex==0||(uiKeyBits!=128&&uiKeyBits!=256)||pucKey==NULL||puiKeyLength==NULL||phKeyHandle==NULL)return SDR_INARGERR;
    sdfx_remote_handle_t sid;SDF_CHECK_SESSION(hSessionHandle,sid);uint32_t params[4]={uiIPKIndex,uiKeyBits,0,0};
    BYTE response[sizeof(sdfx_message_header_t)+sizeof(sdfx_blob_resp_t)+RSAref_MAX_LEN];size_t response_len=0;
    LONG ret=send_rsa_blob(SDFX_CMD_GENERATE_KEY_IPK_RSA,sid,params,NULL,0,response,sizeof(response),&response_len);
    return ret==SDR_OK?rsa_parse_wrapped(response,response_len,pucKey,puiKeyLength,phKeyHandle):ret;
}

LONG SDF_GenerateKeyWithEPK_RSA(HANDLE hSessionHandle,ULONG uiKeyBits,
    RSArefPublicKey *pucPublicKey,BYTE *pucKey,ULONG *puiKeyLength,HANDLE *phKeyHandle)
{
    if(hSessionHandle==NULL||(uiKeyBits!=128&&uiKeyBits!=256)||pucPublicKey==NULL||pucKey==NULL||puiKeyLength==NULL||phKeyHandle==NULL)return SDR_INARGERR;
    sdfx_remote_handle_t sid;SDF_CHECK_SESSION(hSessionHandle,sid);uint32_t params[4]={uiKeyBits,0,0,0};
    BYTE response[sizeof(sdfx_message_header_t)+sizeof(sdfx_blob_resp_t)+RSAref_MAX_LEN];size_t response_len=0;
    LONG ret=send_rsa_blob(SDFX_CMD_GENERATE_KEY_EPK_RSA,sid,params,(BYTE *)pucPublicKey,sizeof(*pucPublicKey),response,sizeof(response),&response_len);
    return ret==SDR_OK?rsa_parse_wrapped(response,response_len,pucKey,puiKeyLength,phKeyHandle):ret;
}

LONG SDF_ImportKeyWithISK_RSA(HANDLE hSessionHandle,ULONG uiISKIndex,
    BYTE *pucKey,ULONG uiKeyLength,HANDLE *phKeyHandle)
{
    if(hSessionHandle==NULL||uiISKIndex==0||pucKey==NULL||uiKeyLength==0||uiKeyLength>RSAref_MAX_LEN||phKeyHandle==NULL)return SDR_INARGERR;
    sdfx_remote_handle_t sid;SDF_CHECK_SESSION(hSessionHandle,sid);uint32_t params[4]={uiISKIndex,0,0,0};
    BYTE response[sizeof(sdfx_message_header_t)+sizeof(sdfx_blob_resp_t)];size_t response_len=0;
    LONG ret=send_rsa_blob(SDFX_CMD_IMPORT_KEY_ISK_RSA,sid,params,pucKey,uiKeyLength,response,sizeof(response),&response_len);
    if(ret!=SDR_OK)return ret;const BYTE *data;uint32_t length;sdfx_remote_handle_t object_id;
    ret=rsa_blob_payload(response,response_len,&data,&length,&object_id);return ret==SDR_OK&&length==0?rsa_create_local(object_id,phKeyHandle):(ret==SDR_OK?SDR_PROTOCOL_ERROR:ret);
}

static LONG rsa_operation(HANDLE session,ULONG command,ULONG index,
    const BYTE *key,uint32_t key_len,BYTE *input,ULONG input_len,
    BYTE *output,ULONG *output_len)
{
    if(session==NULL||input==NULL||input_len==0||output==NULL||output_len==NULL||
       (key_len&&key==NULL))return SDR_INARGERR;
    sdfx_remote_handle_t sid;SDF_CHECK_SESSION(session,sid);size_t payload_len=key_len+input_len;
    BYTE *payload=malloc(payload_len);if(payload==NULL)return SDR_NOBUFFER;
    if(key_len)memcpy(payload,key,key_len);memcpy(payload+key_len,input,input_len);
    uint32_t params[4]={index,0,0,0};BYTE response[sizeof(sdfx_message_header_t)+sizeof(sdfx_blob_resp_t)+RSAref_MAX_LEN];size_t response_len=0;
    LONG ret=send_rsa_blob(command,sid,params,payload,(uint32_t)payload_len,response,sizeof(response),&response_len);memset(payload,0,payload_len);free(payload);
    const BYTE *data;uint32_t length;if(ret==SDR_OK)ret=rsa_blob_payload(response,response_len,&data,&length,NULL);
    if(ret==SDR_OK&&*output_len<length){*output_len=length;return SDR_NOBUFFER;}if(ret==SDR_OK){memcpy(output,data,length);*output_len=length;}return ret;
}

LONG SDF_ExternalPublicKeyOperation_RSA(HANDLE s,RSArefPublicKey *k,BYTE *in,ULONG in_len,BYTE *out,ULONG *out_len)
{return k==NULL?SDR_INARGERR:rsa_operation(s,SDFX_CMD_EXTERNAL_PUBLIC_RSA,0,(BYTE *)k,sizeof(*k),in,in_len,out,out_len);}
LONG SDF_InternalPublicKeyOperation_RSA(HANDLE s,ULONG index,BYTE *in,ULONG in_len,BYTE *out,ULONG *out_len)
{return index==0?SDR_INARGERR:rsa_operation(s,SDFX_CMD_INTERNAL_PUBLIC_RSA,index,NULL,0,in,in_len,out,out_len);}
LONG SDF_InternalPrivateKeyOperation_RSA(HANDLE s,ULONG index,BYTE *in,ULONG in_len,BYTE *out,ULONG *out_len)
{return index==0?SDR_INARGERR:rsa_operation(s,SDFX_CMD_INTERNAL_PRIVATE_RSA,index,NULL,0,in,in_len,out,out_len);}
LONG SDF_ExternalPrivateKeyOperation_RSA(HANDLE s,RSArefPrivateKey *k,BYTE *in,ULONG in_len,BYTE *out,ULONG *out_len)
{return k==NULL?SDR_INARGERR:rsa_operation(s,SDFX_CMD_EXTERNAL_PRIVATE_RSA,0,(BYTE *)k,sizeof(*k),in,in_len,out,out_len);}

LONG SDF_GenerateKeyPair_RSA(HANDLE hSessionHandle,ULONG uiKeyBits,
    RSArefPublicKey *pucPublicKey,RSArefPrivateKey *pucPrivateKey)
{
    if(hSessionHandle==NULL||uiKeyBits<1024||uiKeyBits>RSAref_MAX_BITS||(uiKeyBits%256)!=0||pucPublicKey==NULL||pucPrivateKey==NULL)return SDR_INARGERR;
    sdfx_remote_handle_t sid;SDF_CHECK_SESSION(hSessionHandle,sid);uint32_t params[4]={uiKeyBits,0,0,0};
    BYTE response[sizeof(sdfx_message_header_t)+sizeof(sdfx_blob_resp_t)+sizeof(RSArefPublicKey)+sizeof(RSArefPrivateKey)];size_t response_len=0;
    LONG ret=send_rsa_blob(SDFX_CMD_GENERATE_KEYPAIR_RSA,sid,params,NULL,0,response,sizeof(response),&response_len);
    const BYTE *data;uint32_t length;if(ret==SDR_OK)ret=rsa_blob_payload(response,response_len,&data,&length,NULL);
    if(ret==SDR_OK&&length!=sizeof(*pucPublicKey)+sizeof(*pucPrivateKey))ret=SDR_PROTOCOL_ERROR;
    if(ret==SDR_OK){memcpy(pucPublicKey,data,sizeof(*pucPublicKey));memcpy(pucPrivateKey,data+sizeof(*pucPublicKey),sizeof(*pucPrivateKey));}return ret;
}
