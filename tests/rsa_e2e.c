#include <stdio.h>
#include <string.h>
#include "sdf.h"

#define CHECK(call) do { LONG value=(call); if(value!=SDR_OK){fprintf(stderr,"%s failed: 0x%08x\n",#call,(unsigned)value);result=value;goto cleanup;} } while(0)

int main(void)
{
    HANDLE device=NULL,session=NULL,key_a=NULL,key_b=NULL;LONG result=SDR_OK;
    RSArefPublicKey public_key,internal_sign,internal_enc;RSArefPrivateKey private_key;
    BYTE representative[RSAref_MAX_LEN]={0},signature[RSAref_MAX_LEN],recovered[RSAref_MAX_LEN];
    BYTE wrapped[RSAref_MAX_LEN],plain[32]="RSA wrapped SM4 key test",cipher[32],decoded[32];
    ULONG length,cipher_len=sizeof(cipher),decoded_len=sizeof(decoded);
    representative[sizeof(representative)-1]=0x2a;
    CHECK(SDF_OpenDevice(&device));CHECK(SDF_OpenSession(device,&session));
    CHECK(SDF_GenerateKeyPair_RSA(session,2048,&public_key,&private_key));
    length=sizeof(signature);CHECK(SDF_ExternalPrivateKeyOperation_RSA(session,&private_key,representative,sizeof(representative),signature,&length));
    if(length!=sizeof(signature)){result=SDR_KEYERR;goto cleanup;}
    length=sizeof(recovered);CHECK(SDF_ExternalPublicKeyOperation_RSA(session,&public_key,signature,sizeof(signature),recovered,&length));
    if(length!=sizeof(representative)||memcmp(representative,recovered,sizeof(representative))!=0){fprintf(stderr,"external RSA round-trip mismatch\n");result=SDR_VERIFYERR;goto cleanup;}

    CHECK(SDF_ExportSignPublicKey_RSA(session,8,&internal_sign));
    length=sizeof(signature);CHECK(SDF_InternalPrivateKeyOperation_RSA(session,8,representative,sizeof(representative),signature,&length));
    length=sizeof(recovered);CHECK(SDF_ExternalPublicKeyOperation_RSA(session,&internal_sign,signature,sizeof(signature),recovered,&length));
    if(length!=sizeof(representative)||memcmp(representative,recovered,sizeof(representative))!=0){fprintf(stderr,"internal RSA operation mismatch\n");result=SDR_VERIFYERR;goto cleanup;}

    CHECK(SDF_ExportEncPublicKey_RSA(session,4,&internal_enc));
    length=sizeof(wrapped);CHECK(SDF_GenerateKeyWithIPK_RSA(session,4,128,wrapped,&length,&key_a));
    if(length!=internal_enc.bits/8){fprintf(stderr,"wrapped RSA length mismatch\n");result=SDR_KEYERR;goto cleanup;}
    CHECK(SDF_Encrypt(session,key_a,SGD_SM4_ECB,NULL,plain,sizeof(plain),cipher,&cipher_len));
    CHECK(SDF_DestroyKey(session,key_a));key_a=NULL;
    CHECK(SDF_ImportKeyWithISK_RSA(session,4,wrapped,length,&key_b));
    CHECK(SDF_Decrypt(session,key_b,SGD_SM4_ECB,NULL,cipher,cipher_len,decoded,&decoded_len));
    if(decoded_len!=sizeof(plain)||memcmp(plain,decoded,sizeof(plain))!=0){fprintf(stderr,"RSA-wrapped SM4 round-trip mismatch\n");result=SDR_VERIFYERR;goto cleanup;}
    puts("RSA external/internal operations and wrapped session-key round-trip passed.");
cleanup:
    if(key_a)SDF_DestroyKey(session,key_a);if(key_b)SDF_DestroyKey(session,key_b);
    if(session)SDF_CloseSession(session);if(device)SDF_CloseDevice(device);
    return result==SDR_OK?0:1;
}

