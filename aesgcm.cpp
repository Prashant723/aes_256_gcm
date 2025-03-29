#include "aesgcm.hpp"

# define BSWAP8(x) ({ u64 ret_=(x); \
                        asm ("bswapq %0" \
                        : "+r"(ret_)); ret_; })

# define BSWAP4(x) ({ u32 ret_=(x); \
                        asm ("bswapl %0" \
                        : "+r"(ret_)); ret_; })

# define U64(C) C##ULL

# define GETU32(pt) (((u32)(pt)[0] << 24) ^ ((u32)(pt)[1] << 16) ^ ((u32)(pt)[2] << 8) ^ ((u32)(pt)[3]))
# define PUTU32(ct, st) { (ct)[0] = (u8)((st) >> 24); (ct)[1] = (u8)((st) >> 16); (ct)[2] = (u8)((st) >> 8); (ct)[3] = (u8)(st); }


aesGcm::aesGcm(const unsigned char *key,const unsigned char *iv)
{
    mkey = new AES_KEY;
    mctx = new GCM128_CONTEXT;
    memset(mkey , 0 , sizeof(AES_KEY));
    AES_set_encrypt_key(key, 256);
    CRYPTO_gcm128_init(mctx , mkey);
    CRYPTO_gcm128_setiv(mctx, iv , (size_t)12);
}

aesGcm::~aesGcm()
{
    delete[] array;
}

void aesGcm::CRYPTO_gcm128_init(GCM128_CONTEXT *ctx, AES_KEY *key)
{

    memset(ctx, 0, sizeof(*ctx));
    // ctx->block = block;
    ctx->key = (void *)key;

    AES_encrypt(ctx->H.c, ctx->H.c, key);

    ctx->H.u[0] = BSWAP8(ctx->H.u[0]);
    ctx->H.u[1] = BSWAP8(ctx->H.u[1]);

}

void aesGcm::CRYPTO_gcm128_setiv(GCM128_CONTEXT *ctx, const unsigned char *iv,size_t len)
{
    unsigned int ctr;

    ctx->len.u[0] = 0; /* AAD length */
    ctx->len.u[1] = 0; /* message length */
    ctx->ares = 0;
    ctx->mres = 0;

    if (len == 12) {
        memcpy(ctx->Yi.c, iv, 12);
        ctx->Yi.c[12] = 0;
        ctx->Yi.c[13] = 0;
        ctx->Yi.c[14] = 0;
        ctx->Yi.c[15] = 1;
        ctr = 1;
    }

    ctx->Xi.u[0] = 0;
    ctx->Xi.u[1] = 0;

    AES_encrypt(ctx->Yi.c, ctx->EK0.c, mkey);
    // ++ctr;
    // ctx->Yi.d[3] = BSWAP4(ctr);
    // AES_encrypt(ctx->Yi.c, ctx->EK0.c, mkey);
    initialiseMemoryPool();

}

void aesGcm::initialiseMemoryPool(){

    const size_t rows = 1000000;
    const size_t cols = 16;
    array = new unsigned char[rows * cols];
    memset(array, 0, rows * cols);
    unsigned char c[16];
    auto start = std::chrono::high_resolution_clock::now();
    for(int i = 0; i < rows ; i++)
    {
        IncrementCounter(mctx->Yi.c);
        AES_encrypt(mctx->Yi.c, c, mkey);
        memcpy(array + (i*cols) , c , 16);
    }
    auto end = std::chrono::high_resolution_clock::now();
    std::cout<<"total time for 1000000 : "<<std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count()<<std::endl;
}

void aesGcm::getIvCounter(unsigned char * arr)
{
    // memcpy(arr , array[iv_counter_index++] , 16);
}

void aesGcm::AES_encrypt(const unsigned char *in, unsigned char *out,const AES_KEY *key) {

    const u32 *rk;
    u32 s0, s1, s2, s3, t0, t1, t2, t3;
    int r;

    assert(in && out && key);
    rk = key->rd_key;

    /*
     * map byte array block to cipher state
     * and add initial round key:
     */
    s0 = GETU32(in ) ^ rk[0];
    s1 = GETU32(in + 4) ^ rk[1];
    s2 = GETU32(in + 8) ^ rk[2];
    s3 = GETU32(in + 12) ^ rk[3];
// #ifdef FULL_UNROLL
    /* round 1: */
    t0 = Te0[s0 >> 24] ^ Te1[(s1 >> 16) & 0xff] ^ Te2[(s2 >> 8) & 0xff] ^ Te3[s3 & 0xff] ^ rk[ 4];
    t1 = Te0[s1 >> 24] ^ Te1[(s2 >> 16) & 0xff] ^ Te2[(s3 >> 8) & 0xff] ^ Te3[s0 & 0xff] ^ rk[ 5];
    t2 = Te0[s2 >> 24] ^ Te1[(s3 >> 16) & 0xff] ^ Te2[(s0 >> 8) & 0xff] ^ Te3[s1 & 0xff] ^ rk[ 6];
    t3 = Te0[s3 >> 24] ^ Te1[(s0 >> 16) & 0xff] ^ Te2[(s1 >> 8) & 0xff] ^ Te3[s2 & 0xff] ^ rk[ 7];
    /* round 2: */
    s0 = Te0[t0 >> 24] ^ Te1[(t1 >> 16) & 0xff] ^ Te2[(t2 >> 8) & 0xff] ^ Te3[t3 & 0xff] ^ rk[ 8];
    s1 = Te0[t1 >> 24] ^ Te1[(t2 >> 16) & 0xff] ^ Te2[(t3 >> 8) & 0xff] ^ Te3[t0 & 0xff] ^ rk[ 9];
    s2 = Te0[t2 >> 24] ^ Te1[(t3 >> 16) & 0xff] ^ Te2[(t0 >> 8) & 0xff] ^ Te3[t1 & 0xff] ^ rk[10];
    s3 = Te0[t3 >> 24] ^ Te1[(t0 >> 16) & 0xff] ^ Te2[(t1 >> 8) & 0xff] ^ Te3[t2 & 0xff] ^ rk[11];
    /* round 3: */
    t0 = Te0[s0 >> 24] ^ Te1[(s1 >> 16) & 0xff] ^ Te2[(s2 >> 8) & 0xff] ^ Te3[s3 & 0xff] ^ rk[12];
    t1 = Te0[s1 >> 24] ^ Te1[(s2 >> 16) & 0xff] ^ Te2[(s3 >> 8) & 0xff] ^ Te3[s0 & 0xff] ^ rk[13];
    t2 = Te0[s2 >> 24] ^ Te1[(s3 >> 16) & 0xff] ^ Te2[(s0 >> 8) & 0xff] ^ Te3[s1 & 0xff] ^ rk[14];
    t3 = Te0[s3 >> 24] ^ Te1[(s0 >> 16) & 0xff] ^ Te2[(s1 >> 8) & 0xff] ^ Te3[s2 & 0xff] ^ rk[15];
    /* round 4: */
    s0 = Te0[t0 >> 24] ^ Te1[(t1 >> 16) & 0xff] ^ Te2[(t2 >> 8) & 0xff] ^ Te3[t3 & 0xff] ^ rk[16];
    s1 = Te0[t1 >> 24] ^ Te1[(t2 >> 16) & 0xff] ^ Te2[(t3 >> 8) & 0xff] ^ Te3[t0 & 0xff] ^ rk[17];
    s2 = Te0[t2 >> 24] ^ Te1[(t3 >> 16) & 0xff] ^ Te2[(t0 >> 8) & 0xff] ^ Te3[t1 & 0xff] ^ rk[18];
    s3 = Te0[t3 >> 24] ^ Te1[(t0 >> 16) & 0xff] ^ Te2[(t1 >> 8) & 0xff] ^ Te3[t2 & 0xff] ^ rk[19];
    /* round 5: */
    t0 = Te0[s0 >> 24] ^ Te1[(s1 >> 16) & 0xff] ^ Te2[(s2 >> 8) & 0xff] ^ Te3[s3 & 0xff] ^ rk[20];
    t1 = Te0[s1 >> 24] ^ Te1[(s2 >> 16) & 0xff] ^ Te2[(s3 >> 8) & 0xff] ^ Te3[s0 & 0xff] ^ rk[21];
    t2 = Te0[s2 >> 24] ^ Te1[(s3 >> 16) & 0xff] ^ Te2[(s0 >> 8) & 0xff] ^ Te3[s1 & 0xff] ^ rk[22];
    t3 = Te0[s3 >> 24] ^ Te1[(s0 >> 16) & 0xff] ^ Te2[(s1 >> 8) & 0xff] ^ Te3[s2 & 0xff] ^ rk[23];
    /* round 6: */
    s0 = Te0[t0 >> 24] ^ Te1[(t1 >> 16) & 0xff] ^ Te2[(t2 >> 8) & 0xff] ^ Te3[t3 & 0xff] ^ rk[24];
    s1 = Te0[t1 >> 24] ^ Te1[(t2 >> 16) & 0xff] ^ Te2[(t3 >> 8) & 0xff] ^ Te3[t0 & 0xff] ^ rk[25];
    s2 = Te0[t2 >> 24] ^ Te1[(t3 >> 16) & 0xff] ^ Te2[(t0 >> 8) & 0xff] ^ Te3[t1 & 0xff] ^ rk[26];
    s3 = Te0[t3 >> 24] ^ Te1[(t0 >> 16) & 0xff] ^ Te2[(t1 >> 8) & 0xff] ^ Te3[t2 & 0xff] ^ rk[27];
    /* round 7: */
    t0 = Te0[s0 >> 24] ^ Te1[(s1 >> 16) & 0xff] ^ Te2[(s2 >> 8) & 0xff] ^ Te3[s3 & 0xff] ^ rk[28];
    t1 = Te0[s1 >> 24] ^ Te1[(s2 >> 16) & 0xff] ^ Te2[(s3 >> 8) & 0xff] ^ Te3[s0 & 0xff] ^ rk[29];
    t2 = Te0[s2 >> 24] ^ Te1[(s3 >> 16) & 0xff] ^ Te2[(s0 >> 8) & 0xff] ^ Te3[s1 & 0xff] ^ rk[30];
    t3 = Te0[s3 >> 24] ^ Te1[(s0 >> 16) & 0xff] ^ Te2[(s1 >> 8) & 0xff] ^ Te3[s2 & 0xff] ^ rk[31];
    /* round 8: */
    s0 = Te0[t0 >> 24] ^ Te1[(t1 >> 16) & 0xff] ^ Te2[(t2 >> 8) & 0xff] ^ Te3[t3 & 0xff] ^ rk[32];
    s1 = Te0[t1 >> 24] ^ Te1[(t2 >> 16) & 0xff] ^ Te2[(t3 >> 8) & 0xff] ^ Te3[t0 & 0xff] ^ rk[33];
    s2 = Te0[t2 >> 24] ^ Te1[(t3 >> 16) & 0xff] ^ Te2[(t0 >> 8) & 0xff] ^ Te3[t1 & 0xff] ^ rk[34];
    s3 = Te0[t3 >> 24] ^ Te1[(t0 >> 16) & 0xff] ^ Te2[(t1 >> 8) & 0xff] ^ Te3[t2 & 0xff] ^ rk[35];
    /* round 9: */
    t0 = Te0[s0 >> 24] ^ Te1[(s1 >> 16) & 0xff] ^ Te2[(s2 >> 8) & 0xff] ^ Te3[s3 & 0xff] ^ rk[36];
    t1 = Te0[s1 >> 24] ^ Te1[(s2 >> 16) & 0xff] ^ Te2[(s3 >> 8) & 0xff] ^ Te3[s0 & 0xff] ^ rk[37];
    t2 = Te0[s2 >> 24] ^ Te1[(s3 >> 16) & 0xff] ^ Te2[(s0 >> 8) & 0xff] ^ Te3[s1 & 0xff] ^ rk[38];
    t3 = Te0[s3 >> 24] ^ Te1[(s0 >> 16) & 0xff] ^ Te2[(s1 >> 8) & 0xff] ^ Te3[s2 & 0xff] ^ rk[39];
    if (key->rounds > 10) {
        /* round 10: */
        s0 = Te0[t0 >> 24] ^ Te1[(t1 >> 16) & 0xff] ^ Te2[(t2 >> 8) & 0xff] ^ Te3[t3 & 0xff] ^ rk[40];
        s1 = Te0[t1 >> 24] ^ Te1[(t2 >> 16) & 0xff] ^ Te2[(t3 >> 8) & 0xff] ^ Te3[t0 & 0xff] ^ rk[41];
        s2 = Te0[t2 >> 24] ^ Te1[(t3 >> 16) & 0xff] ^ Te2[(t0 >> 8) & 0xff] ^ Te3[t1 & 0xff] ^ rk[42];
        s3 = Te0[t3 >> 24] ^ Te1[(t0 >> 16) & 0xff] ^ Te2[(t1 >> 8) & 0xff] ^ Te3[t2 & 0xff] ^ rk[43];
        /* round 11: */
        t0 = Te0[s0 >> 24] ^ Te1[(s1 >> 16) & 0xff] ^ Te2[(s2 >> 8) & 0xff] ^ Te3[s3 & 0xff] ^ rk[44];
        t1 = Te0[s1 >> 24] ^ Te1[(s2 >> 16) & 0xff] ^ Te2[(s3 >> 8) & 0xff] ^ Te3[s0 & 0xff] ^ rk[45];
        t2 = Te0[s2 >> 24] ^ Te1[(s3 >> 16) & 0xff] ^ Te2[(s0 >> 8) & 0xff] ^ Te3[s1 & 0xff] ^ rk[46];
        t3 = Te0[s3 >> 24] ^ Te1[(s0 >> 16) & 0xff] ^ Te2[(s1 >> 8) & 0xff] ^ Te3[s2 & 0xff] ^ rk[47];
        if (key->rounds > 12) {
            /* round 12: */
            s0 = Te0[t0 >> 24] ^ Te1[(t1 >> 16) & 0xff] ^ Te2[(t2 >> 8) & 0xff] ^ Te3[t3 & 0xff] ^ rk[48];
            s1 = Te0[t1 >> 24] ^ Te1[(t2 >> 16) & 0xff] ^ Te2[(t3 >> 8) & 0xff] ^ Te3[t0 & 0xff] ^ rk[49];
            s2 = Te0[t2 >> 24] ^ Te1[(t3 >> 16) & 0xff] ^ Te2[(t0 >> 8) & 0xff] ^ Te3[t1 & 0xff] ^ rk[50];
            s3 = Te0[t3 >> 24] ^ Te1[(t0 >> 16) & 0xff] ^ Te2[(t1 >> 8) & 0xff] ^ Te3[t2 & 0xff] ^ rk[51];
            /* round 13: */
            t0 = Te0[s0 >> 24] ^ Te1[(s1 >> 16) & 0xff] ^ Te2[(s2 >> 8) & 0xff] ^ Te3[s3 & 0xff] ^ rk[52];
            t1 = Te0[s1 >> 24] ^ Te1[(s2 >> 16) & 0xff] ^ Te2[(s3 >> 8) & 0xff] ^ Te3[s0 & 0xff] ^ rk[53];
            t2 = Te0[s2 >> 24] ^ Te1[(s3 >> 16) & 0xff] ^ Te2[(s0 >> 8) & 0xff] ^ Te3[s1 & 0xff] ^ rk[54];
            t3 = Te0[s3 >> 24] ^ Te1[(s0 >> 16) & 0xff] ^ Te2[(s1 >> 8) & 0xff] ^ Te3[s2 & 0xff] ^ rk[55];
        }
    }
    rk += key->rounds << 2;

    s0 =
        (Te2[(t0 >> 24) ] & 0xff000000) ^
        (Te3[(t1 >> 16) & 0xff] & 0x00ff0000) ^
        (Te0[(t2 >> 8) & 0xff] & 0x0000ff00) ^
        (Te1[(t3 ) & 0xff] & 0x000000ff) ^
        rk[0];
    PUTU32(out , s0);
    s1 =
        (Te2[(t1 >> 24) ] & 0xff000000) ^
        (Te3[(t2 >> 16) & 0xff] & 0x00ff0000) ^
        (Te0[(t3 >> 8) & 0xff] & 0x0000ff00) ^
        (Te1[(t0 ) & 0xff] & 0x000000ff) ^
        rk[1];
    PUTU32(out + 4, s1);
    s2 =
        (Te2[(t2 >> 24) ] & 0xff000000) ^
        (Te3[(t3 >> 16) & 0xff] & 0x00ff0000) ^
        (Te0[(t0 >> 8) & 0xff] & 0x0000ff00) ^
        (Te1[(t1 ) & 0xff] & 0x000000ff) ^
        rk[2];
    PUTU32(out + 8, s2);
    s3 =
        (Te2[(t3 >> 24) ] & 0xff000000) ^
        (Te3[(t0 >> 16) & 0xff] & 0x00ff0000) ^
        (Te0[(t1 >> 8) & 0xff] & 0x0000ff00) ^
        (Te1[(t2 ) & 0xff] & 0x000000ff) ^
        rk[3];
    PUTU32(out + 12, s3);
}

int aesGcm::AES_set_encrypt_key(const unsigned char *userKey, const int bits)
{
    u32 *rk;
    int i = 0;
    u32 temp;

    if (!userKey || !mkey)
        return -1;
    if (bits != 128 && bits != 192 && bits != 256)
        return -2;

    rk = mkey->rd_key;
    mkey->rounds = 14;

    rk[0] = GETU32(userKey );
    rk[1] = GETU32(userKey + 4);
    rk[2] = GETU32(userKey + 8);
    rk[3] = GETU32(userKey + 12);
    rk[4] = GETU32(userKey + 16);
    rk[5] = GETU32(userKey + 20);
    rk[6] = GETU32(userKey + 24);
    rk[7] = GETU32(userKey + 28);
    if (bits == 256) {
        while (1) {
            temp = rk[ 7];
            rk[ 8] = rk[ 0] ^
                (Te2[(temp >> 16) & 0xff] & 0xff000000) ^
                (Te3[(temp >> 8) & 0xff] & 0x00ff0000) ^
                (Te0[(temp ) & 0xff] & 0x0000ff00) ^
                (Te1[(temp >> 24) ] & 0x000000ff) ^
                rcon[i];
            rk[ 9] = rk[ 1] ^ rk[ 8];
            rk[10] = rk[ 2] ^ rk[ 9];
            rk[11] = rk[ 3] ^ rk[10];
            if (++i == 7) {
                return 0;
            }
            temp = rk[11];
            rk[12] = rk[ 4] ^
                (Te2[(temp >> 24) ] & 0xff000000) ^
                (Te3[(temp >> 16) & 0xff] & 0x00ff0000) ^
                (Te0[(temp >> 8) & 0xff] & 0x0000ff00) ^
                (Te1[(temp ) & 0xff] & 0x000000ff);
            rk[13] = rk[ 5] ^ rk[12];
            rk[14] = rk[ 6] ^ rk[13];
            rk[15] = rk[ 7] ^ rk[14];
            rk += 8;
            }
    }
    return 0;
}


void aesGcm::encrypt(const unsigned char * plainText , unsigned char * cipherText , int len)
{
    if(ivCounter > 0)
    {
        encryptChunkAVX(plainText, cipherText, 16 - ivCounter);
        lenAdder = 16 - ivCounter;
    }
    else
    {
        lenAdder = 0;
    }
    // int blockSize = 64;
    // int chunks = (len - lenAdder)/blockSize;
    // if(chunks > 0)
    // {
    // for(int i = 0 ; i < chunks ; i++)
    // {
    // encryptChunkAVX512(plainText + lenAdder + (i * blockSize) , cipherText + lenAdder + (i * blockSize));

    // }
    // lenAdder += (chunks * blockSize);
    // }
    blockSize = 32;
    chunks = (len - lenAdder)/blockSize;
    if(chunks > 0)
    {
        for(int i = 0 ; i < chunks ; i++)
        {
            encryptChunkAVX256(plainText + lenAdder + (i * blockSize) , cipherText + lenAdder + (i * blockSize));
        }
        lenAdder += (chunks * blockSize);
    }
    blockSize = 16;
    chunks = (len - lenAdder)/blockSize;
    if(chunks > 0)
    {
        for(int i = 0; i < chunks ; i++)
        {
            encryptChunkAVX128(plainText + lenAdder + (i * blockSize) , cipherText + lenAdder + (i * blockSize) );
        }
        lenAdder += (chunks * blockSize);
    }
    int remainingBytes = (len - lenAdder);
    if(remainingBytes > 0)
    {
        encryptChunkAVX(plainText + lenAdder , cipherText + lenAdder , remainingBytes );
        ivCounter = remainingBytes;
    }
    else
    {
        ivCounter = 0;
    }
    // return 0;
}

void aesGcm::encryptChunk(const unsigned char * plainText , unsigned char * cipherText , int len)
{
    for(int i = 0; i < len ; i++)
    {
        cipherText[i] = plainText[i] ^ mctx->EK0.c[i];
    }
}

//void aesGcm::encryptChunkAVX512(const unsigned char *plainText, unsigned char *cipherText)
//{
// __m512i plainVec = _mm512_loadu_si512(reinterpret_cast<const __m512i*>(plainText));
// __m512i keyVec = _mm512_loadu_si512(reinterpret_cast<const __m512i*>(array + iv_counter_index));
// __m512i resultVec = _mm512_xor_si512(plainVec, keyVec);
// _mm512_storeu_si512(reinterpret_cast<__m512i*>(cipherText), resultVec);
// iv_counter_index += 64;
//}

void aesGcm::encryptChunkAVX256(const unsigned char *plainText, unsigned char *cipherText)
{
    __m256i plainVec = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(plainText));
    __m256i keyVec = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(array + iv_counter_index));
    __m256i resultVec = _mm256_xor_si256(plainVec, keyVec);
    _mm256_storeu_si256(reinterpret_cast<__m256i*>(cipherText), resultVec);
    iv_counter_index += 32;
}

void aesGcm::encryptChunkAVX128(const unsigned char *plainText, unsigned char *cipherText)
{
    __m128i plainVec = _mm_loadu_si128(reinterpret_cast<const __m128i*>(plainText));
    __m128i keyVec = _mm_loadu_si128(reinterpret_cast<const __m128i*>(array + iv_counter_index));
    __m128i resultVec = _mm_xor_si128(plainVec, keyVec);
    _mm_storeu_si128(reinterpret_cast<__m128i*>(cipherText), resultVec);
    iv_counter_index += 16;
}

void aesGcm::encryptChunkAVX(const unsigned char *plainText, unsigned char *cipherText, int len)
{
    __m128i plainVec = _mm_loadu_si128(reinterpret_cast<const __m128i*>(plainText));
    __m128i keyVec = _mm_loadu_si128(reinterpret_cast<const __m128i*>(array + iv_counter_index));
    __m128i resultVec = _mm_xor_si128(plainVec, keyVec);
    _mm_storeu_si128(reinterpret_cast<__m128i*>(cipherText), resultVec);
    iv_counter_index += len;
}

void aesGcm::encryptChunkAVX_IVOffset(const unsigned char *plainText, unsigned char *cipherText, int len , unsigned char *ivCounterEK)
{
    __m128i plainVec = _mm_loadu_si128(reinterpret_cast<const __m128i*>(plainText));
    __m128i keyVec = _mm_loadu_si128(reinterpret_cast<const __m128i*>(ivCounterEK));
    __m128i resultVec = _mm_xor_si128(plainVec, keyVec);
    _mm_storeu_si128(reinterpret_cast<__m128i*>(cipherText), resultVec);
}

void aesGcm::IncrementCounter(unsigned char *counter) {
    for(int i = 15; i >= 0; --i) {
        if(++counter[i] != 0) break;
    }
}
