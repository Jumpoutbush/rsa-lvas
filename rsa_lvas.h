#pragma once 

#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace rsa_lvas
{

// -------------------- lightweight byte view (C++17) --------------------
struct BytesView {
    const uint8_t* data = nullptr;
    size_t size = 0;
};

inline BytesView View(const std::vector<uint8_t>& v) {return {v.data(), v.size()}; }
inline BytesView View(const std::string& s) { return {reinterpret_cast<const uint8_t*>(s.data()), s.size()}; }


// -------------------- params --------------------
struct Params {
    int rsa_bits = 2048;        // RSA modulus size
    int prime_bits = 256;       // hash-to-prime output size
    int mr_checks = 64;         // Miller-Rabin rounds for primality test
    size_t seed_bytes = 32;     // public "samp_seed" length
};

// -------------------- opaque RAII big integer wrapper --------------------
class BigNum {
public:
    BigNum();
    ~BigNum();
    BigNum(const BigNum& other);
    BigNum& operator=(const BigNum& other);
    BigNum(BigNum&&) noexcept;
    BigNum& operator=(BigNum&&) noexcept;

    // Expose raw pointer for advanced users (read-only or controlled use).
    // This is still "library-style" but keeps OpenSSL interop possible.
    void* raw();               // returns BIGNUM*
    const void* raw() const;   // returns const BIGNUM*

    std::vector<uint8_t> to_bytes() const;               // big-endian
    static BigNum from_bytes(const std::vector<uint8_t>& be);

    std::string to_hex() const;

private:
    void* bn_; // BIGNUM*
};

// -------------------- key types --------------------
struct PublicKey {
    BigNum N;                       // RSA modulus
    BigNum g;                       // generator in Z*_N
    std::vector<uint8_t> samp_seed; // public seed for PrimeSamp (deterministic hash-to-prime)
};

struct SecretKey {
    // Keep pk embedded for convenience
    PublicKey pk;

    BigNum p;
    BigNum q;
    BigNum phi; // (p-1)(q-1)
};

// -------------------- signatures --------------------
using Signature = BigNum;

// -------------------- API --------------------
std::pair<PublicKey, SecretKey> KeyGen(const Params& params);

// Deterministic prime derived from (pk.samp_seed, msg). Exposed mainly for testing/debug.
BigNum PrimeSamp(const PublicKey& pk, BytesView msg, const Params& params);

// Sign / Verify
Signature Sign(const SecretKey& sk, BytesView msg, const Params& params);
bool Verify(const PublicKey& pk, BytesView msg, const Signature& sig, const Params& params);

// Aggregate: multiply individual signatures mod N (expects each signature is valid).
Signature Aggregate(const PublicKey& pk,
                    const std::vector<std::pair<std::vector<uint8_t>, Signature>>& msg_sigs,
                    const Params& params);

// AggVerify: verifies aggregate signature over message list.
bool AggVerify(const PublicKey& pk,
                const std::vector<std::vector<uint8_t>>& messages,
                const Signature& agg_sig,
                const Params& params);

// LocalOpen: for index j in messages, produce aux (opening). In RSA-LVAS, aux acts as the individual signature.
Signature LocalOpen(const PublicKey& pk,
                    const std::vector<std::vector<uint8_t>>& messages,
                    const Signature& agg_sig,
                    size_t j,
                    const Params& params);

// LocalAggVerify (RSA-LVAS): simply Verify(pk, m_j, aux).
bool LocalAggVerify(const PublicKey& pk, BytesView msg, const Signature& aux, const Params& params);

// -------------------- simple serialization --------------------
// These are minimal length-prefixed encodings for demo/library usage.
// For production, define canonical encoding and versioning.
std::vector<uint8_t> SerializePublicKey(const PublicKey& pk);
PublicKey DeserializePublicKey(const std::vector<uint8_t>& blob);

std::vector<uint8_t> SerializeSignature(const Signature& sig);
Signature DeserializeSignature(const std::vector<uint8_t>& blob);

} // namespace rsa-lvas