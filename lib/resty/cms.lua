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
local setmetatable = setmetatable
local type = type
local ipairs = ipairs

local BIO_CTRL_PENDING = 10
local CMS_NO_CONTENT_VERIFY = 0x4
local CMS_NO_ATTR_VERIFY = 0x8
local CMS_NOATTR = 0x100
local CMS_DEBUG_DECRYPT = 0x20000

local _M = { _VERSION = '0.0.2' }
local mt = { __index = _M }

ffi.cdef [[
//ERR Functions
unsigned long ERR_get_error(void);
const char *ERR_reason_error_string(unsigned long e);
void ERR_clear_error(void);

// BIO Functions
typedef struct bio_st BIO;
typedef struct bio_method_st BIO_METHOD;
BIO_METHOD *BIO_s_mem(void);
BIO * BIO_new(BIO_METHOD *type);
void BIO_vfree(BIO *a);
int	BIO_puts(BIO *bp,const char *buf);
int BIO_read(BIO *b, void *data, int len);
long BIO_ctrl(BIO *bp, int cmd, long larg, void *parg);

//stack Functions
typedef struct stack_st OPENSSL_STACK;
OPENSSL_STACK *OPENSSL_sk_new_null(void);
void OPENSSL_sk_free(OPENSSL_STACK *st);
int OPENSSL_sk_push(OPENSSL_STACK *st, void *data);

//cipher Functions
typedef struct evp_cipher_st EVP_CIPHER;
const EVP_CIPHER *EVP_des_ede(void);
const EVP_CIPHER *EVP_des_cbc(void);
const EVP_CIPHER *EVP_des_ede3_cbc(void);

//RSA Functions
typedef int pem_password_cb(char *buf, int size, int rwflag, void *userdata);
typedef struct rsa_st RSA;
void RSA_free(RSA *rsa);
RSA * PEM_read_bio_RSAPrivateKey(BIO *bp, RSA **rsa, pem_password_cb *cb, void *u);

//X509 Functions
typedef struct x509_st X509;
typedef struct x509_store_st X509_STORE;
X509 *PEM_read_bio_X509(BIO *bp, X509 **x, pem_password_cb *cb, void *u);
void X509_free(X509 *x509);
X509_STORE *X509_STORE_new(void);
void X509_STORE_free(X509_STORE *v);
int X509_STORE_add_cert(X509_STORE *ctx, X509 *x);

//PKEY Functions
typedef struct evp_pkey_st EVP_PKEY;
EVP_PKEY *EVP_PKEY_new(void);
void EVP_PKEY_free(EVP_PKEY *key);
int EVP_PKEY_set1_RSA(EVP_PKEY *pkey,RSA *key);

//CMS Functions
typedef struct CMS_ContentInfo_st CMS_ContentInfo;
CMS_ContentInfo *CMS_ContentInfo_new();
void *CMS_ContentInfo_free(CMS_ContentInfo *cms);
int i2d_CMS_ContentInfo(CMS_ContentInfo *a, unsigned char **pp);
CMS_ContentInfo *d2i_CMS_ContentInfo(CMS_ContentInfo **a, unsigned char **pp,
                                     long length);
CMS_ContentInfo *PEM_read_bio_CMS(BIO *bp, CMS_ContentInfo **a, pem_password_cb *cb, void *u);

CMS_ContentInfo *CMS_sign(X509 *signcert, EVP_PKEY *pkey,
                          struct stack_st_X509 *certs, BIO *data,
                          unsigned int flags);
CMS_ContentInfo *CMS_encrypt(struct stack_st_X509 *certs, BIO *in,
                             const EVP_CIPHER *cipher, unsigned int flags);
int CMS_verify(CMS_ContentInfo *cms, struct stack_st_X509 *certs,
               X509_STORE *store, BIO *dcont, BIO *out, unsigned int flags);
int CMS_decrypt(CMS_ContentInfo *cms, EVP_PKEY *pkey, X509 *cert,
                BIO *dcont, BIO *out, unsigned int flags);
]]

local function get_error()
    local code = C.ERR_get_error()

    if code == 0 then
        return nil
    end

    local err = C.ERR_reason_error_string(code)

    return ffi_str(err)
end

local function sk_X509_new(certs)
    if not certs and type(certs) ~= "table" then
        return nil
    end

    local stack = C.OPENSSL_sk_new_null()
    if stack == ffi_null then
        return nil, get_error()
    end
    ffi_gc(stack, C.OPENSSL_sk_free)

    for _, cert in ipairs(certs) do
        C.OPENSSL_sk_push(stack, cert)
    end

    return ffi_cast("struct stack_st_X509 *", ffi_cast("intptr_t", stack))
end

local function BIO_new(data, method)
    if not method then
        method = C.BIO_s_mem()
    end

    local bio = C.BIO_new(method)
    if bio == ffi_null then
        return nil, get_error()
    end
    ffi_gc(bio, C.BIO_vfree)

    if data then
        local len = C.BIO_puts(bio, data)
        if len < 0 then
            return nil, get_error()
        end
    end
    return bio
end

local function BIO_read(bio)
    local len = C.BIO_ctrl(bio, BIO_CTRL_PENDING, 0, ffi_null)
    if len <= 0 then
        return nil, get_error()
    end

    local str = ffi_new("char[?]", len + 1)
    if C.BIO_read(bio, str, len) <= 0 then
        return nil, get_error()
    end
    str[len] = 0

    return ffi_str(str)
end

local function PEM_read_bio_RSAPrivateKey(pkey, pass)
    local bio, msg = BIO_new(pkey)
    if not bio then
        return nil, msg
    end

    local rsa = C.PEM_read_bio_RSAPrivateKey(bio, ffi_null, ffi_null, pass)
    if rsa == ffi_null then
        return nil, get_error()
    end
    ffi_gc(rsa, C.RSA_free)

    return rsa
end

local function EVP_PKEY_new(rsa)
    local pkey = C.EVP_PKEY_new()
    ffi_gc(pkey, C.EVP_PKEY_free)
    if C.EVP_PKEY_set1_RSA(pkey, rsa) == 0 then
        return nil, get_error()
    end
    return pkey
end

local function PEM_read_bio_X509(cert, pass)
    local bio, msg = BIO_new(cert)
    if not bio then
        return nil, msg
    end

    local x509 = C.PEM_read_bio_X509(bio, ffi_null, ffi_null, pass)
    if x509 == ffi_null then
        return nil, get_error()
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
        return nil, get_error()
    end
    ffi_gc(ctx, C.X509_STORE_free)

    if type(cert) ~= "table" then
        cert = { cert }
    end
    for _, x509 in ipairs(cert) do
        if C.X509_STORE_add_cert(ctx, x509) == 0 then
            return nil, get_error()
        end
    end

    return ctx
end

function _M.new(opts)
    local cms = {}

    if opts.private_key then
        local rsa, err = PEM_read_bio_RSAPrivateKey(opts.private_key)
        if not rsa then
            return nil, err
        end
        local pkey, err = EVP_PKEY_new(rsa)
        if not pkey then
            return nil, err
        end
        cms.pkey = pkey
    end

    if opts.sign_cert then
        local pcert, err = PEM_read_bio_X509(opts.sign_cert)
        if not pcert then
            return nil, err
        end
        cms.signcert = pcert
    end

    if opts.cert then
        local cert, err = PEM_read_bio_X509(opts.cert)
        if not cert then
            return nil, err
        end
        cms.cert = cert
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
        cms.store = store
    end

    if opts.cipher and opts.method then
        local func = "EVP_" .. opts.cipher .. "_" .. opts.method
        if not C[func] then
            return nil, "no cipher on method"
        end
        cms.cipher = C[func]()
    else
        cms.cipher = C.EVP_des_ede3_cbc()
    end

    return setmetatable(cms, mt)
end

function _M.BIO_new(self, data, method)
    local bio, err = BIO_new(data, method)
    if not bio then
        return nil, err
    end
    return bio
end

function _M.BIO_read(self, bio)
    local data, err = BIO_read(bio)
    if not data then
        return nil, err
    end
    return data
end

function _M.i2d_CMS_ContentInfo(self, cms)
    local str = ffi_new("unsigned char*[1]")
    local str_len = C.i2d_CMS_ContentInfo(cms, str)
    if str_len == 0 then
        return nil, get_error()
    end

    return ffi_str(str[0], str_len)
end

function _M.d2i_CMS_ContentInfo(self, data)
    local enc_data = ffi_new("unsigned char*[1]")
    enc_data[0] = ffi_cast("unsigned char*", data)
    local cms = C.d2i_CMS_ContentInfo(ffi_null, enc_data, #data)
    if cms == ffi_null then
        return nil, get_error()
    end
    ffi_gc(cms, C.CMS_ContentInfo_free)

    return cms
end

function _M.PEM_read_bio_CMS(self, data, pass)
    local data_in, err = self:BIO_new(data)
    if not data_in then
        return nil, err
    end

    local cms = C.PEM_read_bio_CMS(data_in, ffi_null, ffi_null, pass)
    if cms == ffi_null then
        return nil, get_error()
    end
    ffi_gc(cms, C.CMS_ContentInfo_free)

    return cms
end

function _M.CMS_sign(self, data_in, flags)
    local cms = C.CMS_sign(self.signcert, self.pkey, ffi_null, data_in, flags)
    if cms == ffi_null then
        return nil, get_error()
    end
    return cms
end

function _M.CMS_encrypt(self, data_in, flags)
    local certs = sk_X509_new({ self.cert })
    local cms = C.CMS_encrypt(certs, data_in, self.cipher, flags)
    if cms == ffi_null then
        return nil, get_error()
    end
    return cms
end

function _M.CMS_verify(self, cms, flags)
    local out = self:BIO_new()
    local certs = sk_X509_new({ self.cert })
    if C.CMS_verify(cms, certs, self.store, ffi_null, out, flags) == 0 then
        return nil, get_error()
    end
    return out
end

function _M.CMS_decrypt(self, cms, flags)
    local out = self:BIO_new()
    if C.CMS_decrypt(cms, self.pkey, self.signcert, ffi_null, out, flags) == 0 then
        return nil, get_error()
    end
    return out
end

function _M.sign(self, data)
    if not data then
        return nil, "no plain data"
    end

    local data_in, err = self:BIO_new(data)
    if not data_in then
        return nil, err
    end

    local cms, err = self:CMS_sign(data_in, CMS_NOATTR)
    if not cms then
        return nil, err
    end

    local signed, err = self:i2d_CMS_ContentInfo(cms)
    if not signed then
        return nil, err
    end

    return signed
end

function _M.encrypt(self, data)
    if not data then
        return nil, "no plain data"
    end

    local data_in, err = self:BIO_new(data)
    if not data_in then
        return nil, err
    end

    local cms, err = self:CMS_encrypt(data_in, 0)
    if not cms then
        return nil, err
    end

    local encryped, err = self:i2d_CMS_ContentInfo(cms)
    if not encryped then
        return nil, err
    end

    return encryped
end

function _M.verify(self, data)
    if not data then
        return nil, "no cihper data"
    end

    local cms, err = self:d2i_CMS_ContentInfo(data)
    if not cms then
        return nil, err
    end

    local out, err = self:CMS_verify(cms, bor(CMS_NO_ATTR_VERIFY, CMS_NO_CONTENT_VERIFY))
    if not out then
        return nil, err
    end

    local verified, err = self:BIO_read(out)
    if not verified then
        return nil, err
    end

    return verified
end

function _M.decrypt(self, data)
    if not data then
        return nil, "no chiper data"
    end

    local cms, err = self:d2i_CMS_ContentInfo(data)
    if not cms then
        return nil, err
    end

    local out, err = self:CMS_decrypt(cms, CMS_DEBUG_DECRYPT)
    if not out then
        return nil, err
    end

    local decryped, err = self:BIO_read(out)
    if not decryped then
        return nil, err
    end

    return decryped
end

return _M