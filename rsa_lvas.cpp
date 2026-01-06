#include "rsa_lvas.h"

#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include <algorithm>
#include <cstring>
#include <stdexcept>

namespace rsa_lvas {

// -------------------- OpenSSL error helper --------------------
static void throw_openssl(const char* where) {
  unsigned long e = ERR_get_error();
  std::string msg = where;
  msg += " failed: ";
  msg += ERR_error_string(e, nullptr);
  throw std::runtime_error(msg);
}

// -------------------- BN_CTX RAII --------------------
struct Ctx {
  BN_CTX* ctx = nullptr;
  Ctx() : ctx(BN_CTX_new()) { if (!ctx) throw std::runtime_error("BN_CTX_new failed"); }
  ~Ctx() { BN_CTX_free(ctx); }
};

// -------------------- BigNum --------------------
BigNum::BigNum() : bn_(BN_new()) {
  if (!bn_) throw std::runtime_error("BN_new failed");
}
BigNum::~BigNum() { 
    if(bn_) BN_free(reinterpret_cast<BIGNUM*>(bn_)); 
}

BigNum::BigNum(BigNum&& o) noexcept : bn_(o.bn_) { o.bn_ = nullptr; }
BigNum& BigNum::operator=(BigNum&& o) noexcept {
  if (this == &o) return *this;
  BN_free(reinterpret_cast<BIGNUM*>(bn_));
  bn_ = o.bn_;
  o.bn_ = nullptr;
  return *this;
}
BigNum::BigNum(const BigNum& other) : bn_(BN_dup(reinterpret_cast<const BIGNUM*>(other.bn_))) {
    if (!bn_) throw std::runtime_error("BN_dup failed");
}

BigNum& BigNum::operator=(const BigNum& other) {
    if (this == &other) return *this;
    if (!bn_) {
        bn_ = BN_dup(reinterpret_cast<const BIGNUM*>(other.bn_));
        if (!bn_) throw std::runtime_error("BN_dup failed");
        return *this;
    }
    if (!BN_copy(reinterpret_cast<BIGNUM*>(bn_), reinterpret_cast<const BIGNUM*>(other.bn_))) {
        throw_openssl("BN_copy");
    }
    return *this;
}
  
void* BigNum::raw() { return bn_; }
const void* BigNum::raw() const { return bn_; }

std::vector<uint8_t> BigNum::to_bytes() const {
  const BIGNUM* bn = reinterpret_cast<const BIGNUM*>(bn_);
  int len = BN_num_bytes(bn);
  std::vector<uint8_t> out(static_cast<size_t>(len));
  BN_bn2bin(bn, out.data());
  return out;
}

BigNum BigNum::from_bytes(const std::vector<uint8_t>& be) {
  BigNum x;
  BIGNUM* bn = reinterpret_cast<BIGNUM*>(x.raw());
  if (!BN_bin2bn(be.data(), static_cast<int>(be.size()), bn)) throw_openssl("BN_bin2bn");
  return x;
}

std::string BigNum::to_hex() const {
  const BIGNUM* bn = reinterpret_cast<const BIGNUM*>(bn_);
  char* s = BN_bn2hex(bn);
  if (!s) return "(null)";
  std::string out(s);
  OPENSSL_free(s);
  return out;
}

// -------------------- helpers --------------------
static void bn_set_one(BigNum& x) {
  if (!BN_set_word(reinterpret_cast<BIGNUM*>(x.raw()), 1)) throw_openssl("BN_set_word(1)");
}
static void bn_set_zero(BigNum& x) {
  if (!BN_set_word(reinterpret_cast<BIGNUM*>(x.raw()), 0)) throw_openssl("BN_set_word(0)");
}

static BigNum bn_gcd(const BigNum& a, const BigNum& b) {
  Ctx c;
  BigNum g;
  if (!BN_gcd(reinterpret_cast<BIGNUM*>(g.raw()),
              reinterpret_cast<const BIGNUM*>(a.raw()),
              reinterpret_cast<const BIGNUM*>(b.raw()),
              c.ctx)) {
    throw_openssl("BN_gcd");
  }
  return g;
}

static bool bn_is_one(const BigNum& x) {
  return BN_is_one(reinterpret_cast<const BIGNUM*>(x.raw())) == 1;
}

static bool bn_is_zero(const BigNum& x) {
  return BN_is_zero(reinterpret_cast<const BIGNUM*>(x.raw())) == 1;
}

static bool bn_is_negative(const BigNum& x) {
  return BN_is_negative(reinterpret_cast<const BIGNUM*>(x.raw())) == 1;
}

static void bn_set_negative(BigNum& x, bool neg) {
  BN_set_negative(reinterpret_cast<BIGNUM*>(x.raw()), neg ? 1 : 0);
}

static BigNum bn_copy(const BigNum& a) {
  BigNum x;
  if (!BN_copy(reinterpret_cast<BIGNUM*>(x.raw()),
               reinterpret_cast<const BIGNUM*>(a.raw()))) {
    throw_openssl("BN_copy");
  }
  return x;
}

static BigNum bn_add_word(const BigNum& a, BN_ULONG w) {
  BigNum x = bn_copy(a);
  if (!BN_add_word(reinterpret_cast<BIGNUM*>(x.raw()), w)) throw_openssl("BN_add_word");
  return x;
}

static BigNum bn_mul(const BigNum& a, const BigNum& b) {
  Ctx c;
  BigNum r;
  if (!BN_mul(reinterpret_cast<BIGNUM*>(r.raw()),
              reinterpret_cast<const BIGNUM*>(a.raw()),
              reinterpret_cast<const BIGNUM*>(b.raw()),
              c.ctx)) {
    throw_openssl("BN_mul");
  }
  return r;
}

static BigNum bn_mod_mul(const BigNum& a, const BigNum& b, const BigNum& mod) {
  Ctx c;
  BigNum r;
  if (!BN_mod_mul(reinterpret_cast<BIGNUM*>(r.raw()),
                  reinterpret_cast<const BIGNUM*>(a.raw()),
                  reinterpret_cast<const BIGNUM*>(b.raw()),
                  reinterpret_cast<const BIGNUM*>(mod.raw()),
                  c.ctx)) {
    throw_openssl("BN_mod_mul");
  }
  return r;
}

static BigNum bn_mod_exp(const BigNum& base, const BigNum& exp, const BigNum& mod) {
  Ctx c;
  BigNum r;
  if (!BN_mod_exp(reinterpret_cast<BIGNUM*>(r.raw()),
                  reinterpret_cast<const BIGNUM*>(base.raw()),
                  reinterpret_cast<const BIGNUM*>(exp.raw()),
                  reinterpret_cast<const BIGNUM*>(mod.raw()),
                  c.ctx)) {
    throw_openssl("BN_mod_exp");
  }
  return r;
}

static BigNum bn_mod_inverse(const BigNum& a, const BigNum& mod) {
  Ctx c;
  BigNum inv;
  BIGNUM* r = BN_mod_inverse(reinterpret_cast<BIGNUM*>(inv.raw()),
                             reinterpret_cast<const BIGNUM*>(a.raw()),
                             reinterpret_cast<const BIGNUM*>(mod.raw()),
                             c.ctx);
  if (!r) throw_openssl("BN_mod_inverse");
  return inv;
}

// base^(signed exp) mod N
static BigNum bn_mod_exp_signed(const BigNum& base, const BigNum& exp_signed, const BigNum& mod) {
  if (!bn_is_negative(exp_signed)) {
    return bn_mod_exp(base, exp_signed, mod);
  }
  BigNum e = bn_copy(exp_signed);
  bn_set_negative(e, false);
  BigNum inv = bn_mod_inverse(base, mod);
  return bn_mod_exp(inv, e, mod);
}

// Extended GCD on BIGNUM: returns (g,u,v) s.t. u*a + v*b = g
struct Egcd {
  BigNum g;
  BigNum u;
  BigNum v;
};

static Egcd extended_gcd(const BigNum& a, const BigNum& b) {
  Ctx c;
  BN_CTX_start(c.ctx);

  BIGNUM* old_r = BN_CTX_get(c.ctx);
  BIGNUM* r     = BN_CTX_get(c.ctx);
  BIGNUM* old_s = BN_CTX_get(c.ctx);
  BIGNUM* s     = BN_CTX_get(c.ctx);
  BIGNUM* old_t = BN_CTX_get(c.ctx);
  BIGNUM* t     = BN_CTX_get(c.ctx);
  BIGNUM* q     = BN_CTX_get(c.ctx);
  BIGNUM* rem   = BN_CTX_get(c.ctx);
  BIGNUM* tmp   = BN_CTX_get(c.ctx);
  if (!tmp) throw std::runtime_error("BN_CTX_get failed");

  BN_copy(old_r, reinterpret_cast<const BIGNUM*>(a.raw()));
  BN_copy(r,     reinterpret_cast<const BIGNUM*>(b.raw()));
  BN_one(old_s); BN_zero(s);
  BN_zero(old_t); BN_one(t);

  while (!BN_is_zero(r)) {
    if (!BN_div(q, rem, old_r, r, c.ctx)) throw_openssl("BN_div");

    BN_copy(old_r, r);
    BN_copy(r, rem);

    // old_s, s = s, old_s - q*s
    BN_copy(tmp, s);
    if (!BN_mul(rem, q, s, c.ctx)) throw_openssl("BN_mul");
    if (!BN_sub(rem, old_s, rem)) throw_openssl("BN_sub");
    BN_copy(old_s, tmp);
    BN_copy(s, rem);

    // old_t, t = t, old_t - q*t
    BN_copy(tmp, t);
    if (!BN_mul(rem, q, t, c.ctx)) throw_openssl("BN_mul");
    if (!BN_sub(rem, old_t, rem)) throw_openssl("BN_sub");
    BN_copy(old_t, tmp);
    BN_copy(t, rem);
  }

  Egcd out;
  if (!BN_copy(reinterpret_cast<BIGNUM*>(out.g.raw()), old_r)) throw_openssl("BN_copy(g)");
  if (!BN_copy(reinterpret_cast<BIGNUM*>(out.u.raw()), old_s)) throw_openssl("BN_copy(u)");
  if (!BN_copy(reinterpret_cast<BIGNUM*>(out.v.raw()), old_t)) throw_openssl("BN_copy(v)");

  BN_CTX_end(c.ctx);
  return out;
}

// Shamir recovery: given x=z^b, y=z^a, gcd(a,b)=1 => z = y^u * x^v
static BigNum shamir_recover(const BigNum& x, const BigNum& y,
                             const BigNum& a, const BigNum& b,
                             const BigNum& modN) {
  Egcd eg = extended_gcd(a, b);
  if (!bn_is_one(eg.g)) {
    throw std::runtime_error("shamir_recover: gcd(a,b)!=1");
  }
  BigNum yu = bn_mod_exp_signed(y, eg.u, modN);
  BigNum xv = bn_mod_exp_signed(x, eg.v, modN);
  return bn_mod_mul(yu, xv, modN);
}

// -------------------- deterministic hash-to-prime (demo) --------------------
static BigNum hash_to_prime_hmac_sha256(const std::vector<uint8_t>& seed,
                                       BytesView msg,
                                       const Params& params) {
  const int bits = params.prime_bits;
  if (bits < 64 || (bits % 8) != 0) throw std::runtime_error("prime_bits must be multiple of 8 and >=64");
  const size_t out_len = static_cast<size_t>(bits / 8);

  std::vector<uint8_t> buf;
  buf.reserve(msg.size + 8);

  Ctx c;

  for (uint64_t ctr = 0;; ++ctr) {
    buf.assign(msg.data, msg.data + msg.size);
    for (int i = 0; i < 8; i++) buf.push_back(static_cast<uint8_t>((ctr >> (8*i)) & 0xFF));

    unsigned int mac_len = 0;
    unsigned char mac[SHA256_DIGEST_LENGTH];
    if (!HMAC(EVP_sha256(),
              seed.data(), static_cast<int>(seed.size()),
              buf.data(), buf.size(),
              mac, &mac_len)) {
      throw_openssl("HMAC");
    }

    // Expand to out_len
    std::vector<uint8_t> cand(out_len, 0);
    if (out_len <= SHA256_DIGEST_LENGTH) {
      std::memcpy(cand.data(), mac, out_len);
    } else {
      // SHA256(mac || i) expander
      size_t filled = 0;
      uint32_t i = 0;
      while (filled < out_len) {
        SHA256_CTX sctx;
        SHA256_Init(&sctx);
        SHA256_Update(&sctx, mac, SHA256_DIGEST_LENGTH);
        SHA256_Update(&sctx, &i, sizeof(i));
        unsigned char dig[SHA256_DIGEST_LENGTH];
        SHA256_Final(dig, &sctx);
        size_t take = std::min(out_len - filled, (size_t)SHA256_DIGEST_LENGTH);
        std::memcpy(cand.data() + filled, dig, take);
        filled += take;
        i++;
      }
    }

    // force exact bit-length and odd
    cand[0] |= 0x80;
    cand.back() |= 0x01;

    BigNum e;
    if (!BN_bin2bn(cand.data(), static_cast<int>(cand.size()),
                   reinterpret_cast<BIGNUM*>(e.raw()))) {
      throw_openssl("BN_bin2bn");
    }

    // primality test; if not prime, bump by 2 a few times (still deterministic)
    for (int step = 0; step < 1'000'000; step++) {
      int is_prime = BN_is_prime_ex(reinterpret_cast<const BIGNUM*>(e.raw()),
                                    params.mr_checks, c.ctx, nullptr);
      if (is_prime == 1) return e;
      if (is_prime < 0) throw_openssl("BN_is_prime_ex");
      if (!BN_add_word(reinterpret_cast<BIGNUM*>(e.raw()), 2)) throw_openssl("BN_add_word");
    }
  }
}

// -------------------- API impl --------------------
std::pair<PublicKey, SecretKey> KeyGen(const Params& params) {
  if (params.rsa_bits < 1024 || (params.rsa_bits % 2) != 0)
    throw std::runtime_error("rsa_bits must be even and >=1024");

  Ctx c;

  SecretKey sk;
  PublicKey pk;

  // p,q
  if (!BN_generate_prime_ex(reinterpret_cast<BIGNUM*>(sk.p.raw()), params.rsa_bits/2, 0, nullptr, nullptr, nullptr))
    throw_openssl("BN_generate_prime_ex(p)");
  if (!BN_generate_prime_ex(reinterpret_cast<BIGNUM*>(sk.q.raw()), params.rsa_bits/2, 0, nullptr, nullptr, nullptr))
    throw_openssl("BN_generate_prime_ex(q)");

  // N=pq
  if (!BN_mul(reinterpret_cast<BIGNUM*>(pk.N.raw()),
              reinterpret_cast<const BIGNUM*>(sk.p.raw()),
              reinterpret_cast<const BIGNUM*>(sk.q.raw()),
              c.ctx)) throw_openssl("BN_mul(N)");

  // phi=(p-1)(q-1)
  BigNum p1 = bn_copy(sk.p);
  BigNum q1 = bn_copy(sk.q);
  if (!BN_sub_word(reinterpret_cast<BIGNUM*>(p1.raw()), 1)) throw_openssl("BN_sub_word");
  if (!BN_sub_word(reinterpret_cast<BIGNUM*>(q1.raw()), 1)) throw_openssl("BN_sub_word");
  if (!BN_mul(reinterpret_cast<BIGNUM*>(sk.phi.raw()),
              reinterpret_cast<const BIGNUM*>(p1.raw()),
              reinterpret_cast<const BIGNUM*>(q1.raw()),
              c.ctx)) throw_openssl("BN_mul(phi)");

  // samp_seed
  pk.samp_seed.resize(params.seed_bytes);
  if (RAND_bytes(pk.samp_seed.data(), (int)pk.samp_seed.size()) != 1) throw_openssl("RAND_bytes");

  // choose random g in Z*_N
  BigNum gcd;
  for (;;) {
    if (!BN_rand_range(reinterpret_cast<BIGNUM*>(pk.g.raw()),
                       reinterpret_cast<const BIGNUM*>(pk.N.raw())))
      throw_openssl("BN_rand_range");
    if (BN_is_zero(reinterpret_cast<const BIGNUM*>(pk.g.raw())) ||
        BN_is_one(reinterpret_cast<const BIGNUM*>(pk.g.raw())))
      continue;

    gcd = bn_gcd(pk.g, pk.N);
    if (bn_is_one(gcd)) break;
  }

  sk.pk = pk;
  return {std::move(pk), std::move(sk)};
}

BigNum PrimeSamp(const PublicKey& pk, BytesView msg, const Params& params) {
  return hash_to_prime_hmac_sha256(pk.samp_seed, msg, params);
}

Signature Sign(const SecretKey& sk, BytesView msg, const Params& params) {
  Ctx c;
  BigNum e = PrimeSamp(sk.pk, msg, params);

  // d = e^{-1} mod phi
  BigNum d;
  BIGNUM* r = BN_mod_inverse(reinterpret_cast<BIGNUM*>(d.raw()),
                             reinterpret_cast<const BIGNUM*>(e.raw()),
                             reinterpret_cast<const BIGNUM*>(sk.phi.raw()),
                             c.ctx);
  if (!r) {
    // extremely unlikely (e divides phi)
    throw std::runtime_error("Sign: e not invertible mod phi(N). Regenerate key (negligible probability).");
  }

  // sigma = g^d mod N
  return bn_mod_exp(sk.pk.g, d, sk.pk.N);
}

bool Verify(const PublicKey& pk, BytesView msg, const Signature& sig, const Params& params) {
  BigNum e = PrimeSamp(pk, msg, params);
  BigNum lhs = bn_mod_exp(sig, e, pk.N);
  return BN_cmp(reinterpret_cast<const BIGNUM*>(lhs.raw()),
                reinterpret_cast<const BIGNUM*>(pk.g.raw())) == 0;
}

Signature Aggregate(const PublicKey& pk,
                    const std::vector<std::pair<std::vector<uint8_t>, Signature>>& msg_sigs,
                    const Params& params) {
  Signature agg;
  bn_set_one(agg);

  for (const auto& ms : msg_sigs) {
    BytesView m{ms.first.data(), ms.first.size()};
    if (!Verify(pk, m, ms.second, params)) {
      throw std::runtime_error("Aggregate: input signature verification failed");
    }
    agg = bn_mod_mul(agg, ms.second, pk.N);
  }
  return agg;
}

bool AggVerify(const PublicKey& pk,
               const std::vector<std::vector<uint8_t>>& messages,
               const Signature& agg_sig,
               const Params& params) {
  if (messages.empty()) return false;
  Ctx c;

  const size_t n = messages.size();
  std::vector<BigNum> e; e.reserve(n);
  for (const auto& m : messages) e.push_back(PrimeSamp(pk, View(m), params));

  // Eprod = ∏ e_i
  BigNum Eprod; bn_set_one(Eprod);
  for (size_t i = 0; i < n; i++) {
    BigNum tmp = bn_mul(Eprod, e[i]);
    Eprod = std::move(tmp);
  }

  // F = Σ (Eprod / e_i)
  BigNum F; bn_set_zero(F);
  BigNum quo, rem;

  for (size_t i = 0; i < n; i++) {
    // quo = Eprod / e_i
    if (!BN_div(reinterpret_cast<BIGNUM*>(quo.raw()),
                reinterpret_cast<BIGNUM*>(rem.raw()),
                reinterpret_cast<const BIGNUM*>(Eprod.raw()),
                reinterpret_cast<const BIGNUM*>(e[i].raw()),
                c.ctx)) throw_openssl("BN_div");
    if (!BN_is_zero(reinterpret_cast<const BIGNUM*>(rem.raw())))
      throw std::runtime_error("AggVerify: non-exact division (prime collision?)");

    if (!BN_add(reinterpret_cast<BIGNUM*>(F.raw()),
                reinterpret_cast<const BIGNUM*>(F.raw()),
                reinterpret_cast<const BIGNUM*>(quo.raw())))
      throw_openssl("BN_add(F)");
  }

  BigNum lhs = bn_mod_exp(agg_sig, Eprod, pk.N);
  BigNum rhs = bn_mod_exp(pk.g, F, pk.N);

  return BN_cmp(reinterpret_cast<const BIGNUM*>(lhs.raw()),
                reinterpret_cast<const BIGNUM*>(rhs.raw())) == 0;
}

Signature LocalOpen(const PublicKey& pk,
                    const std::vector<std::vector<uint8_t>>& messages,
                    const Signature& agg_sig,
                    size_t j,
                    const Params& params) {
  if (messages.empty() || j >= messages.size())
    throw std::runtime_error("LocalOpen: bad index");

  Ctx c;
  const size_t n = messages.size();

  std::vector<BigNum> e; e.reserve(n);
  for (const auto& m : messages) e.push_back(PrimeSamp(pk, View(m), params));

  // Eprod = ∏ e_i
  BigNum Eprod; bn_set_one(Eprod);
  for (size_t i = 0; i < n; i++) Eprod = bn_mul(Eprod, e[i]);

  // b = ∏_{i≠j} e_i = Eprod / e_j
  BigNum b, rem;
  if (!BN_div(reinterpret_cast<BIGNUM*>(b.raw()),
              reinterpret_cast<BIGNUM*>(rem.raw()),
              reinterpret_cast<const BIGNUM*>(Eprod.raw()),
              reinterpret_cast<const BIGNUM*>(e[j].raw()),
              c.ctx)) throw_openssl("BN_div(b)");
  if (!BN_is_zero(reinterpret_cast<const BIGNUM*>(rem.raw())))
    throw std::runtime_error("LocalOpen: non-exact division for b");

  // f_j = Σ_{i≠j} ∏_{k≠i,j} e_k = Σ_{i≠j} (Eprod/e_i)/e_j
  BigNum f; bn_set_zero(f);
  BigNum term_i, term_ij;

  for (size_t i = 0; i < n; i++) {
    if (i == j) continue;

    if (!BN_div(reinterpret_cast<BIGNUM*>(term_i.raw()),
                reinterpret_cast<BIGNUM*>(rem.raw()),
                reinterpret_cast<const BIGNUM*>(Eprod.raw()),
                reinterpret_cast<const BIGNUM*>(e[i].raw()),
                c.ctx)) throw_openssl("BN_div(term_i)");
    if (!BN_is_zero(reinterpret_cast<const BIGNUM*>(rem.raw())))
      throw std::runtime_error("LocalOpen: non-exact division for term_i");

    if (!BN_div(reinterpret_cast<BIGNUM*>(term_ij.raw()),
                reinterpret_cast<BIGNUM*>(rem.raw()),
                reinterpret_cast<const BIGNUM*>(term_i.raw()),
                reinterpret_cast<const BIGNUM*>(e[j].raw()),
                c.ctx)) throw_openssl("BN_div(term_ij)");
    if (!BN_is_zero(reinterpret_cast<const BIGNUM*>(rem.raw())))
      throw std::runtime_error("LocalOpen: non-exact division for term_ij (prime collision?)");

    if (!BN_add(reinterpret_cast<BIGNUM*>(f.raw()),
                reinterpret_cast<const BIGNUM*>(f.raw()),
                reinterpret_cast<const BIGNUM*>(term_ij.raw())))
      throw_openssl("BN_add(f)");
  }

  // x = agg_sig^b / g^f mod N
  BigNum t1 = bn_mod_exp(agg_sig, b, pk.N);
  BigNum t2 = bn_mod_exp(pk.g, f, pk.N);
  BigNum inv_t2 = bn_mod_inverse(t2, pk.N);
  BigNum x = bn_mod_mul(t1, inv_t2, pk.N);

  // require gcd(e_j, b)=1 (should hold if primes distinct)
  BigNum gg = bn_gcd(e[j], b);
  if (!bn_is_one(gg)) throw std::runtime_error("LocalOpen: gcd(e_j, prod_others) != 1 (prime collision?)");

  // aux = ShamirRecover(x=z^b, y=g=z^{e_j}, a=e_j, b=prod_others)
  Signature aux = shamir_recover(x, pk.g, e[j], b, pk.N);
  return aux;
}

bool LocalAggVerify(const PublicKey& pk, BytesView msg, const Signature& aux, const Params& params) {
  return Verify(pk, msg, aux, params);
}

// -------------------- serialization helpers --------------------
static void put_u32(std::vector<uint8_t>& out, uint32_t x) {
  out.push_back((x >> 24) & 0xFF);
  out.push_back((x >> 16) & 0xFF);
  out.push_back((x >> 8) & 0xFF);
  out.push_back(x & 0xFF);
}
static uint32_t get_u32(const std::vector<uint8_t>& in, size_t& off) {
  if (off + 4 > in.size()) throw std::runtime_error("deserialize: overflow");
  uint32_t x = (uint32_t(in[off]) << 24) | (uint32_t(in[off+1]) << 16) |
               (uint32_t(in[off+2]) << 8) | uint32_t(in[off+3]);
  off += 4;
  return x;
}
static void put_blob(std::vector<uint8_t>& out, const std::vector<uint8_t>& b) {
  if (b.size() > 0xFFFFFFFFu) throw std::runtime_error("blob too large");
  put_u32(out, (uint32_t)b.size());
  out.insert(out.end(), b.begin(), b.end());
}
static std::vector<uint8_t> get_blob(const std::vector<uint8_t>& in, size_t& off) {
  uint32_t len = get_u32(in, off);
  if (off + len > in.size()) throw std::runtime_error("deserialize: overflow");
  std::vector<uint8_t> b(in.begin() + off, in.begin() + off + len);
  off += len;
  return b;
}

std::vector<uint8_t> SerializePublicKey(const PublicKey& pk) {
  std::vector<uint8_t> out;
  // magic + version
  out.insert(out.end(), {'R','L','V','A','S', 0x01});

  put_blob(out, pk.N.to_bytes());
  put_blob(out, pk.g.to_bytes());
  put_blob(out, pk.samp_seed);
  return out;
}

PublicKey DeserializePublicKey(const std::vector<uint8_t>& blob) {
  size_t off = 0;
  if (blob.size() < 6) throw std::runtime_error("bad pk blob");
  if (!(blob[0]=='R' && blob[1]=='L' && blob[2]=='V' && blob[3]=='A' && blob[4]=='S'))
    throw std::runtime_error("bad pk magic");
  if (blob[5] != 0x01) throw std::runtime_error("bad pk version");
  off = 6;

  PublicKey pk;
  pk.N = BigNum::from_bytes(get_blob(blob, off));
  pk.g = BigNum::from_bytes(get_blob(blob, off));
  pk.samp_seed = get_blob(blob, off);
  if (off != blob.size()) throw std::runtime_error("trailing bytes in pk blob");
  return pk;
}

std::vector<uint8_t> SerializeSignature(const Signature& sig) {
  std::vector<uint8_t> out;
  out.insert(out.end(), {'S','I','G', 0x01});
  put_blob(out, sig.to_bytes());
  return out;
}

Signature DeserializeSignature(const std::vector<uint8_t>& blob) {
  size_t off = 0;
  if (blob.size() < 4) throw std::runtime_error("bad sig blob");
  if (!(blob[0]=='S' && blob[1]=='I' && blob[2]=='G')) throw std::runtime_error("bad sig magic");
  if (blob[3] != 0x01) throw std::runtime_error("bad sig version");
  off = 4;
  Signature sig = BigNum::from_bytes(get_blob(blob, off));
  if (off != blob.size()) throw std::runtime_error("trailing bytes in sig blob");
  return sig;
}

} // namespace rsa_lvas
