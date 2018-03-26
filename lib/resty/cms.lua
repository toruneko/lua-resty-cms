-- Copyright (C) by Jianhao Dai (Toruneko)

local bit = require "bit"
local ffi = require "ffi"
local ffi_new = ffi.new
local ffi_cast = ffi.cast
local ffi_gc = ffi.gc
local ffi_str = ffi.string
local ffi_null = ffi.null
local C = ffi.C
local bor = bit.bor
local band = bit.band
local setmetatable = setmetatable
local tonumber = tonumber
local type = type
local ipairs = ipairs

local BIO_TYPE_MEM = bor(1, 0x0400)
local BIO_CTRL_INFO = 3
local BIO_CTRL_PENDING = 10
local BIO_CTRL_FLUSH = 11

local NID_pkcs7_enveloped = 23
local CMS_TEXT = 0x1
local CMS_NO_CONTENT_VERIFY = 0x4
local CMS_NO_ATTR_VERIFY = 0x8
local CMS_NO_SIGNER_CERT_VERIFY = 0x20
local CMS_DETACHED = 0x40
local CMS_NOATTR = 0x100
local CMS_STREAM = 0x1000
local CMS_NOCRL = 0x2000
local CMS_PARTIAL = 0x4000
local CMS_DEBUG_DECRYPT = 0x20000

local CMS_RECIPINFO_NONE = -1
local CMS_RECIPINFO_TRANS = 0
local CMS_RECIPINFO_AGREE = 1
local CMS_RECIPINFO_KEK = 2
local CMS_RECIPINFO_PASS = 3
local CMS_RECIPINFO_OTHER = 4

local _M = { _VERSION = '0.01' }
local mt = { __index = _M }

ffi.cdef [[
//ERR函数
unsigned long ERR_get_error(void);
const char *ERR_reason_error_string(unsigned long e);
void ERR_clear_error(void);

// BIO系列函数
typedef struct bio_st BIO;
typedef struct bio_method_st BIO_METHOD;
BIO_METHOD *BIO_s_mem(void);
BIO_METHOD *BIO_s_null(void);
BIO * BIO_new(BIO_METHOD *type);
void BIO_vfree(BIO *a);
void BIO_free_all(BIO *bio);
BIO *BIO_pop(BIO *a);
int	BIO_puts(BIO *bp,const char *buf);
int BIO_read(BIO *b, void *data, int len);
int BIO_method_type(const BIO *b);
BIO *BIO_new_mem_buf(const void *buf, int len);
int SMIME_crlf_copy(BIO *in, BIO *out, int flags);
long BIO_ctrl(BIO *bp, int cmd, long larg, void *parg);

//stack函数
typedef struct stack_st _STACK;
int sk_num(const _STACK *st);
void *sk_value(const _STACK *st, int i);
_STACK *sk_new_null(void);
void sk_free(_STACK *st);
int sk_push(_STACK *st, void *data);
void sk_pop_free(_STACK *st, void (*func) (void *));

//ASN1系列函数
typedef struct asn1_string_st ASN1_STRING;
typedef struct asn1_object_st ASN1_OBJECT;
int OBJ_obj2nid(const ASN1_OBJECT *o);
int ASN1_STRING_length(ASN1_STRING *x);

//digests函数
typedef struct env_md_st EVP_MD;
void OpenSSL_add_all_digests(void);
const EVP_MD *EVP_get_digestbyname(const char *name);

//cipher系列函数
typedef struct evp_cipher_st EVP_CIPHER;
const EVP_CIPHER *EVP_des_ede(void);
const EVP_CIPHER *EVP_des_cbc(void);
const EVP_CIPHER *EVP_des_ede3_cbc(void);

//RSA函数
typedef int pem_password_cb(char *buf, int size, int rwflag, void *userdata);
typedef struct rsa_st RSA;
void RSA_free(RSA *rsa);
RSA * PEM_read_bio_RSAPrivateKey(BIO *bp, RSA **rsa, pem_password_cb *cb, void *u);

//X509函数
typedef struct x509_st X509;
typedef struct X509_crl_st X509_CRL;
typedef struct X509_algor_st X509_ALGOR;
typedef struct x509_store_st X509_STORE;
typedef struct x509_store_ctx_st X509_STORE_CTX;
X509 *PEM_read_bio_X509(BIO *bp, X509 **x, pem_password_cb *cb, void *u);
void X509_free(X509 *x509);
void X509_CRL_free(X509_CRL *x509_CRL);
X509_STORE *X509_STORE_new(void);
void X509_STORE_free(X509_STORE *v);
int X509_STORE_add_cert(X509_STORE *ctx, X509 *x);
int X509_STORE_CTX_init(X509_STORE_CTX *ctx, X509_STORE *store,
                        X509 *x509, struct stack_st_X509 *chain);
int X509_STORE_CTX_set_default(X509_STORE_CTX *ctx, const char *name);
void X509_STORE_CTX_set0_crls(X509_STORE_CTX *c, struct stack_st_X509_CRL *sk);
int X509_verify_cert(X509_STORE_CTX *ctx);
int X509_STORE_CTX_get_error(X509_STORE_CTX *ctx);
const char *X509_verify_cert_error_string(long n);
X509_STORE_CTX *X509_STORE_CTX_new(void);
void X509_STORE_CTX_free(X509_STORE_CTX *ctx);

//PKEY函数
typedef struct evp_pkey_st EVP_PKEY;
EVP_PKEY *EVP_PKEY_new(void);
void EVP_PKEY_free(EVP_PKEY *key);
int EVP_PKEY_set1_RSA(EVP_PKEY *pkey,RSA *key);

//CMS系列函数
typedef struct CMS_ContentInfo_st CMS_ContentInfo;
CMS_ContentInfo *CMS_ContentInfo_new();
void *CMS_ContentInfo_free(CMS_ContentInfo *cms);
int i2d_CMS_ContentInfo(CMS_ContentInfo *a, unsigned char **pp);
CMS_ContentInfo *d2i_CMS_ContentInfo(CMS_ContentInfo **a, unsigned char **pp,
                                     long length);
int CMS_set_detached(CMS_ContentInfo *cms, int detached);
ASN1_STRING **CMS_get0_content(CMS_ContentInfo *cms);
const ASN1_OBJECT *CMS_get0_type(CMS_ContentInfo *cms);

//签名相关函数
typedef struct CMS_SignerInfo_st CMS_SignerInfo;
int CMS_SignedData_init(CMS_ContentInfo *cms);
CMS_SignerInfo *CMS_add1_signer(CMS_ContentInfo *cms,
                                X509 *signer, EVP_PKEY *pk, const EVP_MD *md,
                                unsigned int flags);
BIO *CMS_dataInit(CMS_ContentInfo *cms, BIO *icont);
int CMS_dataFinal(CMS_ContentInfo *cms, BIO *cmsbio);

//加密相关函数
typedef struct CMS_RecipienCMS_EnvelopedData_createtInfo_st CMS_RecipientInfo;
CMS_ContentInfo *CMS_EnvelopedData_create(const EVP_CIPHER *cipher);
CMS_RecipientInfo *CMS_add1_recipient_cert(CMS_ContentInfo *cms,
                                           X509 *recip, unsigned int flags);

//解密相关函数
typedef struct CMS_RecipientEncryptedKey_st CMS_RecipientEncryptedKey;
struct stack_st_CMS_RecipientInfo *CMS_get0_RecipientInfos(CMS_ContentInfo *cms);
int CMS_RecipientInfo_type(CMS_RecipientInfo *ri);
int cms_pkey_get_ri_type(EVP_PKEY *pk);
struct stack_st_CMS_RecipientEncryptedKey
*CMS_RecipientInfo_kari_get0_reks(CMS_RecipientInfo *ri);
int CMS_RecipientEncryptedKey_cert_cmp(CMS_RecipientEncryptedKey *rek,
                                       X509 *cert);
int CMS_RecipientInfo_kari_set0_pkey(CMS_RecipientInfo *ri, EVP_PKEY *pk);
int CMS_RecipientInfo_kari_decrypt(CMS_ContentInfo *cms,
                                   CMS_RecipientInfo *ri,
                                   CMS_RecipientEncryptedKey *rek);
int CMS_RecipientInfo_ktri_cert_cmp(CMS_RecipientInfo *ri, X509 *cert);
int CMS_RecipientInfo_set0_pkey(CMS_RecipientInfo *ri, EVP_PKEY *pkey);
int CMS_RecipientInfo_decrypt(CMS_ContentInfo *cms, CMS_RecipientInfo *ri);

//验签相关函数
struct stack_st_CMS_SignerInfo *CMS_get0_SignerInfos(CMS_ContentInfo *cms);
void CMS_SignerInfo_get0_algs(CMS_SignerInfo *si, EVP_PKEY **pk,
                              X509 **signer, X509_ALGOR **pdig,
                              X509_ALGOR **psig);
int CMS_set1_signers_certs(CMS_ContentInfo *cms, struct stack_st_X509 *scerts,
                           unsigned int flags);
struct stack_st_X509 *CMS_get1_certs(CMS_ContentInfo *cms);
struct stack_st_X509_CRL *CMS_get1_crls(CMS_ContentInfo *cms);
int CMS_signed_get_attr_count(const CMS_SignerInfo *si);
int CMS_SignerInfo_verify(CMS_SignerInfo *si);
int CMS_SignerInfo_verify_content(CMS_SignerInfo *si, BIO *chain);
]]
C.OpenSSL_add_all_digests()

local function err()
    local code = C.ERR_get_error()

    if code == 0 then
        return nil
    end

    local err = C.ERR_reason_error_string(code)

    return ffi_str(err)
end

local function SKM_sk_new(typeof, data)
    if not data and type(data) ~= "table" then
        return nil
    end

    local stack = C.sk_new_null()
    if stack ~= ffi_null then
        ffi_gc(stack, C.sk_free)
    end

    for _, item in ipairs(data) do
        C.sk_push(stack, item)
    end

    if typeof then
        return ffi_cast(typeof, ffi_cast("intptr_t", stack))
    end
    return stack
end

local function SKM_sk_num(st)
    local stack = ffi_cast("_STACK*", ffi_cast("intptr_t", st))
    return tonumber(C.sk_num(stack))
end

local function SKM_sk_value(st, i)
    local stack = ffi_cast("_STACK*", ffi_cast("intptr_t", st))
    return C.sk_value(stack, i)
end

local function SKM_sk_pop_free(st, free_func)
    local stack = ffi_cast("_STACK*", ffi_cast("intptr_t", st))
    C.sk_pop_free(stack, free_func)
end

local function sk_X509_pop_free(st)
    SKM_sk_pop_free(st, C.X509_free)
end

local function sk_X509_CRL_pop_free(st)
    SKM_sk_pop_free(st, C.X509_CRL_free)
end

local function BIO_new(data, method)
    if not method then
        method = C.BIO_s_mem()
    end

    local bio = C.BIO_new(method)
    if bio == ffi_null then
        return nil, err()
    end
    ffi_gc(bio, C.BIO_vfree)

    if data then
        local len = C.BIO_puts(bio, data)
        if len < 0 then
            return nil, err()
        end
    end
    return bio
end

local function BIO_read(bio)
    local len = C.BIO_ctrl(bio, BIO_CTRL_PENDING, 0, nil)
    if len <= 0 then
        return nil, err()
    end

    local str = ffi_new("char[?]", len + 1)
    if C.BIO_read(bio, str, len) <= 0 then
        return nil, err()
    end
    str[len] = 0

    return ffi_str(str)
end

local function do_free_upto(f, upto)
    if upto then
        repeat
            local tbio = C.BIO_pop(f)
            ffi_gc(f, C.BIO_vfree)
            f = tbio
        until (f ~= ffi_null and f ~= upto)
    else
        ffi_gc(f, C.BIO_free_all)
    end
end

local function PEM_read_bio_RSAPrivateKey(pkey, pass)
    local bio, msg = BIO_new(pkey)
    if not bio then
        return nil, msg
    end

    local rsa = C.PEM_read_bio_RSAPrivateKey(bio, nil, nil, pass)
    if rsa == ffi_null then
        return nil, err()
    end
    ffi_gc(rsa, C.RSA_free)

    return rsa
end

local function EVP_PKEY_new(rsa)
    local pkey = C.EVP_PKEY_new()
    ffi_gc(pkey, C.EVP_PKEY_free)
    if C.EVP_PKEY_set1_RSA(pkey, rsa) == 0 then
        return nil, err()
    end
    return pkey
end

local function PEM_read_bio_X509(cert, pass)
    local bio, msg = BIO_new(cert)
    if not bio then
        return nil, msg
    end

    local x509 = C.PEM_read_bio_X509(bio, nil, nil, pass)
    if x509 == ffi_null then
        return nil, err()
    end
    ffi_gc(x509, C.X509_free)

    return x509
end

local function X509_STORE_new(cert)
    if not cert then
        return nil, "no cert"
    end

    local ctx = C.X509_STORE_new()
    if ctx == ffi_null then
        return nil, err()
    end
    ffi_gc(ctx, C.X509_STORE_free)

    if type(cert) ~= "table" then
        cert = { cert }
    end
    for _, x509 in ipairs(cert) do
        if C.X509_STORE_add_cert(ctx, x509) == 0 then
            return nil, err()
        end
    end

    return ctx
end

local function EVP_get_digestbyname(algorithm)
    local md = C.EVP_get_digestbyname(algorithm)
    if md == ffi_null then
        return nil, "Unknown message digest"
    end

    return md
end

local function i2d_CMS_ContentInfo(cms)
    local str = ffi_new("unsigned char*[1]")
    local str_len = C.i2d_CMS_ContentInfo(cms, str)
    if str_len == 0 then
        return nil, err()
    end

    return ffi_str(str[0], str_len)
end

local function d2i_CMS_ContentInfo(data)
    local enc_data = ffi_new("unsigned char*[1]")
    enc_data[0] = ffi_cast("unsigned char*", data)
    local cms = C.d2i_CMS_ContentInfo(nil, enc_data, #data)
    if cms == ffi_null then
        return nil, err()
    end
    ffi_gc(cms, C.CMS_ContentInfo_free)

    return cms
end

local function check_content(cms)
    local asn1_str = C.CMS_get0_content(cms)
    if asn1_str == ffi_null then
        return false, err()
    end
    if C.ASN1_STRING_length(asn1_str[0]) == 0 then
        return false, "no content"
    end

    return true
end

local function CMS_final(cms, data, dcont, flags)
    local cmsbio = C.CMS_dataInit(cms, dcont)
    if cmsbio == ffi_null then
        return nil, err()
    end
    do_free_upto(cmsbio, dcont)

    C.SMIME_crlf_copy(data, cmsbio, flags)
    -- BIO_flush
    C.BIO_ctrl(cmsbio, BIO_CTRL_FLUSH, 0, nil)

    if C.CMS_dataFinal(cms, cmsbio) == ffi_null then
        return nil, err()
    end

    return cms
end

local function CMS_sign(signcert, pkey, data, flags)
    local cms = C.CMS_ContentInfo_new()
    if cms == ffi_null then
        return nil, err()
    end
    ffi_gc(cms, C.CMS_ContentInfo_free)

    if C.CMS_SignedData_init(cms) == 0 then
        return nil, err()
    end

    if pkey and C.CMS_add1_signer(cms, signcert, pkey, nil, flags) == ffi_null then
        return nil, err()
    end

    if band(flags, CMS_DETACHED) == 0 then
        C.CMS_set_detached(cms, 0)
    end

    if band(flags, bor(CMS_STREAM, CMS_PARTIAL)) ~= 0 then
        return cms
    end

    return CMS_final(cms, data, nil, flags)
end

local function CMS_encrypt(certs, data, cipher, flags)
    local cms = C.CMS_EnvelopedData_create(cipher)
    if cms == ffi_null then
        return nil, err()
    end
    ffi_gc(cms, C.CMS_ContentInfo_free)

    if type(certs) ~= "table" then
        certs = { certs }
    end
    for _, recip in ipairs(certs) do
        if C.CMS_add1_recipient_cert(cms, recip, flags) == ffi_null then
            return nil, err()
        end
    end

    if band(flags, CMS_DETACHED) == 0 then
        C.CMS_set_detached(cms, 0)
    end

    if band(flags, bor(CMS_STREAM, CMS_PARTIAL)) ~= 0 then
        return cms
    end

    return CMS_final(cms, data, nil, flags)
end

local function cms_kari_set1_pkey(cms, ri, pk, cert)
    local reks = C.CMS_RecipientInfo_kari_get0_reks(ri)
    if not cert then
        return 0
    end
    local num = SKM_sk_num(reks)
    for i = 0, num - 1 do
        local rek = SKM_sk_value(reks, i)
        if C.CMS_RecipientEncryptedKey_cert_cmp(rek, cert) == 0 then
            C.CMS_RecipientInfo_kari_set0_pkey(ri, pk)
            local rv = C.CMS_RecipientInfo_kari_decrypt(cms, ri, rek)
            C.CMS_RecipientInfo_kari_set0_pkey(ri, nil)
            if rv > 0 then
                return 1
            else
                return -1
            end
        end
    end
    return 0
end

local function CMS_decrypt_set1_pkey(cms, pk, cert, debug)
    local ris = C.CMS_get0_RecipientInfos(cms)
    if ris == ffi.null then
        debug = false
    end

    local ri_type = C.cms_pkey_get_ri_type(pk)
    if ri_type == CMS_RECIPINFO_NONE then
        return false, err()
    end

    local match_ri = false
    local num = SKM_sk_num(ris)
    for i = 0, num - 1 do
        local ri = SKM_sk_value(ris, i)
        if C.CMS_RecipientInfo_type(ri) == ri_type then
            match_ri = true
            if ri_type == CMS_RECIPINFO_AGREE then
                local r = cms_kari_set1_pkey(cms, ri, pk, cert)
                if r > 0 then return true end
                if r < 0 then return false, err() end
                -- If we have a cert try matching RecipientInfo otherwise try them all.
            elseif not cert or C.CMS_RecipientInfo_ktri_cert_cmp(ri, cert) == 0 then
                C.CMS_RecipientInfo_set0_pkey(ri, pk)
                local r = C.CMS_RecipientInfo_decrypt(cms, ri)
                C.CMS_RecipientInfo_set0_pkey(ri, nil)
                if cert then
                    -- If not debugging clear any error and return success to
                    -- avoid leaking of information useful to MMA
                    if not debug then
                        C.ERR_clear_error()
                        return true
                    end
                    if r > 0 then
                        return true
                    end
                    return false, err()
                    -- If no cert and not debugging don't leave loop after first
                    -- successful decrypt. Always attempt to decrypt all recipients
                    -- to avoid leaking timing of a successful decrypt.
                elseif r > 0 and debug then
                    return true
                end
            end
        end
    end

    -- If no cert and not debugging always return success
    if match_ri and not cert and not debug then
        C.ERR_clear_error()
        return true
    end

    return false, "no recipieninfo matched"
end

local function CMS_decrypt(cms, pk, cert, dcont, flags)
    if C.OBJ_obj2nid(C.CMS_get0_type(cms)) ~= NID_pkcs7_enveloped then
        return nil, "no enveloped data"
    end

    if not dcont then
        local succ, err = check_content(cms)
        if not succ then
            return nil, err
        end
    end

    local debug
    if band(flags, CMS_DEBUG_DECRYPT) == 0 then
        debug = false
    else
        debug = true
    end

    if pk then
        local succ, err = CMS_decrypt_set1_pkey(cms, pk, cert, debug)
        if not succ then
            return nil, err
        end
    end

    local cont = C.CMS_dataInit(cms, dcont)
    if cont == ffi_null then
        return nil, err()
    end
    do_free_upto(cont, dcont)

    return cont
end

local function cms_signerinfo_verify_cert(si, store, certs, crls, flags)
    local signer = ffi_new("X509 *[1]")
    C.CMS_SignerInfo_get0_algs(si, nil, signer, nil, nil)

    local ctx = C.X509_STORE_CTX_new()
    if ctx == ffi_null then
        return nil, err()
    end
    ffi_gc(ctx, C.X509_STORE_CTX_free)

    if C.X509_STORE_CTX_init(ctx, store, signer[0], certs) == 0 then
        return false, err()
    end

    C.X509_STORE_CTX_set_default(ctx, "smime_sign")
    if crls ~= ffi_null then
        C.X509_STORE_CTX_set0_crls(ctx, crls)
    end

    if C.X509_verify_cert(ctx) <= 0 then
        local j = C.X509_STORE_CTX_get_error(ctx)
        return false, ffi_str(C.X509_verify_cert_error_string(j))
    end

    return true
end

local function CMS_verify(cms, certs, store, dcont, flags)
    if not dcont then
        local succ, err = check_content(cms)
        if not succ then
            return nil, err
        end
    end

    -- Attempt to find all signer certificates
    local sinfos = C.CMS_get0_SignerInfos(cms)
    if SKM_sk_num(sinfos) <= 0 then
        return nil, err()
    end

    local scount = 0
    local signer = ffi_new("X509 *[1]")
    for i = 0, SKM_sk_num(sinfos) - 1 do
        local si = SKM_sk_value(sinfos, i)
        C.CMS_SignerInfo_get0_algs(si, nil, signer, nil, nil)
        if signer[0] ~= ffi_null then
            scount = scount + 1
        end
    end

    if scount ~= SKM_sk_num(sinfos) then
        scount = scount + C.CMS_set1_signers_certs(cms, SKM_sk_new("struct stack_st_X509 *", certs), flags)
    end

    if scount ~= SKM_sk_num(sinfos) then
        return nil, "signer certificate not found"
    end

    -- Attempt to verify all signers certs
    if band(flags, CMS_NO_SIGNER_CERT_VERIFY) == 0 then
        local crls
        local cms_certs = C.CMS_get1_certs(cms)
        if cms_certs ~= ffi_null then
            ffi_gc(cms_certs, sk_X509_pop_free)
        end
        if band(flags, CMS_NOCRL) == 0 then
            crls = C.CMS_get1_crls(cms)
            if crls ~= ffi_null then
                ffi_gc(crls, sk_X509_CRL_pop_free)
            end
        end
        for i = 0, SKM_sk_num(sinfos) - 1 do
            local si = SKM_sk_value(sinfos, i)
            local succ, err = cms_signerinfo_verify_cert(si, store, cms_certs, crls, flags)
            if not succ then
                return nil, err
            end
        end
    end

    -- Attempt to verify all SignerInfo signed attribute signatures
    if band(flags, CMS_NO_ATTR_VERIFY) == 0 then
        for i = 0, SKM_sk_num(sinfos) do
            local si = SKM_sk_value(sinfos, i)
            if C.CMS_signed_get_attr_count(si) >= 0 then
                if C.CMS_SignerInfo_verify(si) <= 0 then
                    return nil, err()
                end
            end
        end
    end

    local tmpin
    if dcont and C.BIO_method_type(dcont) == BIO_TYPE_MEM then
        local ptr = ffi_new("char*[1]")
        -- BIO_get_mem_data(bio, ptr)
        local len = C.BIO_ctrl(dcont, BIO_CTRL_INFO, 0, ptr)
        tmpin = C.BIO_new_mem_buf(ptr[0], len)
        if tmpin == ffi_null then
            return nil, "malloc failure"
        end
    else
        tmpin = dcont
    end

    local cmsbio = C.CMS_dataInit(cms, tmpin)
    if cmsbio == ffi_null then
        return nil, err()
    end
    if dcont and C.BIO_method_type(dcont) == BIO_TYPE_MEM then
        do_free_upto(cmsbio, dcont)
    else
        ffi_gc(cmsbio, C.BIO_free_all)
    end

    if band(flags, CMS_NO_CONTENT_VERIFY) == 0 then
        for i = 0, SKM_sk_num(sinfos) do
            local si = SKM_sk_value(sinfos, i)
            if C.CMS_SignerInfo_verify_content(si, cmsbio) <= 0 then
                return nil, err()
            end
        end
    end

    return cmsbio
end

function _M:new(opts)
    local tab = {}

    if opts.private_key then
        local rsa, err = PEM_read_bio_RSAPrivateKey(opts.private_key)
        if not rsa then
            return nil, err
        end
        local pkey, err = EVP_PKEY_new(rsa)
        if not pkey then
            return nil, err
        end
        tab.pkey = pkey
    end

    if opts.private_cert then
        local pcert, err = PEM_read_bio_X509(opts.private_cert)
        if not pcert then
            return nil, err
        end
        tab.pcert = pcert
    end

    if opts.public_cert then
        local cert, err = PEM_read_bio_X509(opts.public_cert)
        if not cert then
            return nil, err
        end
        tab.cert = cert
    end

    if opts.root_cert then
        if type(opts.root_cert) ~= "table" then
            opts.root_cert = { opts.root_cert }
        end
        local rcert = {}
        for _, cert in ipairs(opts.root_cert) do
            local x509, err = PEM_read_bio_X509(cert)
            if not x509 then
                return nil, err
            end
            rcert[#rcert + 1] = x509
        end
        local store, err = X509_STORE_new(rcert)
        if not store then
            return nil, err
        end
        tab.store = store
    end

    if opts.cipher and opts.method then
        local func = "EVP_" .. opts.cipher .. "_" .. opts.method
        if not C[func] then
            return nil, "no cipher on method"
        end
        tab.cipher = C[func]()
    else
        tab.cipher = C.EVP_des_ede3_cbc()
    end

    return setmetatable(tab, mt)
end

function _M:sign(data)
    if not data then
        return nil, "no plain data"
    end

    local bio, err = BIO_new(data)
    if not bio then
        return nil, err
    end

    local cms, err = CMS_sign(self.pcert, self.pkey, bio, CMS_NOATTR)
    if not cms then
        return nil, err
    end

    local signed, err = i2d_CMS_ContentInfo(cms)
    if not signed then
        return nil, err
    end

    return signed
end

function _M:verify(data)
    if not data then
        return nil, "no cihper data"
    end

    local cms, err = d2i_CMS_ContentInfo(data)
    if not cms then
        return nil, err
    end

    local bio, err = CMS_verify(cms, { self.pcert }, self.store, nil, bor(CMS_NO_ATTR_VERIFY, CMS_NO_CONTENT_VERIFY))
    if not bio then
        return nil, err
    end

    local verified, err = BIO_read(bio)
    if not verified then
        return nil, err
    end

    return verified
end

function _M:encrypt(data)
    if not data then
        return nil, "no plain data"
    end

    local bio, err = BIO_new(data)
    if not bio then
        return nil, err
    end

    local cms, err = CMS_encrypt(self.cert, bio, self.cipher, 0)
    if not cms then
        return nil, err
    end

    local encryped, err = i2d_CMS_ContentInfo(cms)
    if not encryped then
        return nil, err
    end

    return encryped
end

function _M:decrypt(data)
    if not data then
        return nil, "no chiper data"
    end

    local cms, err = d2i_CMS_ContentInfo(data)
    if not cms then
        return nil, err
    end

    local bio, err = CMS_decrypt(cms, self.pkey, self.pcert, nil, CMS_DEBUG_DECRYPT)
    if not bio then
        return nil, err
    end

    local decryped, err = BIO_read(bio)
    if not decryped then
        return nil, err
    end

    return decryped
end

return _M