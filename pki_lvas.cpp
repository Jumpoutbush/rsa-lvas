#include "pki_lvas.h"

#include <openssl/evp.h>

#include <cstring>
#include <iomanip>
#include <sstream>
#include <stdexcept>

namespace pki_lvas {

// ---------- helpers ----------
static void put_u32(std::vector<uint8_t>& out, uint32_t x) {
  out.push_back((x >> 24) & 0xFF);
  out.push_back((x >> 16) & 0xFF);
  out.push_back((x >> 8) & 0xFF);
  out.push_back(x & 0xFF);
}
static uint32_t get_u32(const std::vector<uint8_t>& in, size_t& off) {
  if (off + 4 > in.size()) throw std::runtime_error("decode overflow(u32)");
  uint32_t x = (uint32_t(in[off]) << 24) | (uint32_t(in[off+1]) << 16) |
               (uint32_t(in[off+2]) << 8) | uint32_t(in[off+3]);
  off += 4;
  return x;
}
static void put_u64(std::vector<uint8_t>& out, uint64_t x) {
  for (int i = 7; i >= 0; --i) out.push_back(uint8_t((x >> (8*i)) & 0xFF));
}
static uint64_t get_u64(const std::vector<uint8_t>& in, size_t& off) {
  if (off + 8 > in.size()) throw std::runtime_error("decode overflow(u64)");
  uint64_t x = 0;
  for (int i = 0; i < 8; i++) x = (x << 8) | in[off + i];
  off += 8;
  return x;
}
static void put_blob(std::vector<uint8_t>& out, const std::vector<uint8_t>& b) {
  if (b.size() > 0xFFFFFFFFu) throw std::runtime_error("blob too large");
  put_u32(out, (uint32_t)b.size());
  out.insert(out.end(), b.begin(), b.end());
}
static std::vector<uint8_t> get_blob(const std::vector<uint8_t>& in, size_t& off) {
  uint32_t len = get_u32(in, off);
  if (off + len > in.size()) throw std::runtime_error("decode overflow(blob)");
  std::vector<uint8_t> b(in.begin() + off, in.begin() + off + len);
  off += len;
  return b;
}
static void put_str(std::vector<uint8_t>& out, const std::string& s) {
  std::vector<uint8_t> b(s.begin(), s.end());
  put_blob(out, b);
}
static std::string get_str(const std::vector<uint8_t>& in, size_t& off) {
  auto b = get_blob(in, off);
  return std::string(b.begin(), b.end());
}

std::vector<uint8_t> Sha256(const std::vector<uint8_t>& data) {
  std::vector<uint8_t> out(32);

  EVP_MD_CTX* ctx = EVP_MD_CTX_new();
  if (!ctx) throw std::runtime_error("EVP_MD_CTX_new failed");

  if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1) {
    EVP_MD_CTX_free(ctx);
    throw std::runtime_error("EVP_DigestInit_ex failed");
  }
  if (!data.empty()) {
    if (EVP_DigestUpdate(ctx, data.data(), data.size()) != 1) {
      EVP_MD_CTX_free(ctx);
      throw std::runtime_error("EVP_DigestUpdate failed");
    }
  }
  unsigned int len = 0;
  if (EVP_DigestFinal_ex(ctx, out.data(), &len) != 1 || len != 32) {
    EVP_MD_CTX_free(ctx);
    throw std::runtime_error("EVP_DigestFinal_ex failed");
  }
  EVP_MD_CTX_free(ctx);
  return out;
}

std::string Hex(const std::vector<uint8_t>& bytes) {
  std::ostringstream oss;
  for (auto c : bytes) oss << std::hex << std::setw(2) << std::setfill('0') << int(c);
  return oss.str();
}

// ---------- record encoding ----------
std::vector<uint8_t> EncodeLeafRecord(const LeafRecord& r) {
  // magic + version
  std::vector<uint8_t> out;
  out.insert(out.end(), {'L','E','A','F', 0x01});
  put_str(out, r.dns);
  put_str(out, r.issuer_ca_id);
  put_u64(out, r.not_before);
  put_u64(out, r.not_after);
  put_blob(out, r.ee_pubkey);
  return out;
}

LeafRecord DecodeLeafRecord(const std::vector<uint8_t>& bytes) {
  size_t off = 0;
  if (bytes.size() < 5) throw std::runtime_error("leaf too short");
  if (!(bytes[0]=='L' && bytes[1]=='E' && bytes[2]=='A' && bytes[3]=='F')) {
    throw std::runtime_error("leaf magic mismatch");
  }
  if (bytes[4] != 0x01) throw std::runtime_error("leaf version mismatch");
  off = 5;

  LeafRecord r;
  r.dns = get_str(bytes, off);
  r.issuer_ca_id = get_str(bytes, off);
  r.not_before = get_u64(bytes, off);
  r.not_after = get_u64(bytes, off);
  r.ee_pubkey = get_blob(bytes, off);

  if (off != bytes.size()) throw std::runtime_error("leaf trailing bytes");
  return r;
}

// ---------- IssuerCA ----------
IssuerCA::IssuerCA(std::string ca_id, const rsa_lvas::Params& params)
  : ca_id_(std::move(ca_id)), params_(params) {
  auto kp = rsa_lvas::KeyGen(params_);
  pk_ = std::move(kp.first);
  sk_ = std::move(kp.second);
}

IssuerCA::Issued IssuerCA::IssueLeaf(const std::string& dns,
                                     const std::vector<uint8_t>& ee_pubkey,
                                     uint64_t not_before,
                                     uint64_t not_after) const {
  Issued out;
  out.record.dns = dns;
  out.record.issuer_ca_id = ca_id_;
  out.record.not_before = not_before;
  out.record.not_after = not_after;
  out.record.ee_pubkey = ee_pubkey;

  out.record_bytes = EncodeLeafRecord(out.record);
  out.m = Sha256(out.record_bytes);

  out.sig = rsa_lvas::Sign(sk_, rsa_lvas::BytesView{out.m.data(), out.m.size()}, params_);
  return out;
}

// ---------- DirectoryLog ----------
DirectoryLog::DirectoryLog(rsa_lvas::Params params) : params_(params) {}

void DirectoryLog::RegisterCA(const std::string& ca_id, const rsa_lvas::PublicKey& pk) {
  ca_pk_[ca_id] = pk; // requires BigNum deep-copy (you already fixed)
}

void DirectoryLog::SubmitRecord(const std::string& ca_id,
                                const std::vector<uint8_t>& m,
                                const rsa_lvas::Signature& sig) {
  auto it = ca_pk_.find(ca_id);
  if (it == ca_pk_.end()) throw std::runtime_error("SubmitRecord: unknown CA id");

  // optional: reject if signature invalid
  if (!rsa_lvas::Verify(it->second, rsa_lvas::BytesView{m.data(), m.size()}, sig, params_)) {
    throw std::runtime_error("SubmitRecord: invalid signature");
  }

  Pending& p = pending_[ca_id];
  p.messages.push_back(m);
  p.sigs.push_back(sig);
}

void DirectoryLog::CloseEpoch() {
  epoch_++;

  for (auto& kv : pending_) {
    const std::string& ca_id = kv.first;
    Pending& p = kv.second;

    if (p.messages.empty()) continue;

    const auto& pk = ca_pk_.at(ca_id);

    std::vector<std::pair<std::vector<uint8_t>, rsa_lvas::Signature>> pairs;
    pairs.reserve(p.messages.size());
    for (size_t i = 0; i < p.messages.size(); i++) {
      pairs.push_back({p.messages[i], p.sigs[i]});
    }

    EpochState st;
    st.epoch = epoch_;
    st.messages = p.messages;
    st.agg_sig = rsa_lvas::Aggregate(pk, pairs, params_);

    st.idx.reserve(st.messages.size());
    for (size_t i = 0; i < st.messages.size(); i++) {
      st.idx.emplace(Hex(st.messages[i]), i);
    }

    latest_[ca_id] = std::move(st);

    // forget individual signatures / pending
    p.messages.clear();
    p.sigs.clear();
  }
}

rsa_lvas::Signature DirectoryLog::GetAuxLatest(const std::string& ca_id,
                                               const std::vector<uint8_t>& m) const {
  auto it = latest_.find(ca_id);
  if (it == latest_.end()) throw std::runtime_error("GetAuxLatest: no epoch state for this CA");
  const EpochState& st = it->second;

  std::string key = Hex(m);
  auto cit = st.aux_cache.find(key);
  if (cit != st.aux_cache.end()) return cit->second;

  auto idx_it = st.idx.find(key);
  if (idx_it == st.idx.end()) throw std::runtime_error("GetAuxLatest: message not in latest epoch");

  size_t j = idx_it->second;
  const auto& pk = ca_pk_.at(ca_id);

  rsa_lvas::Signature aux = rsa_lvas::LocalOpen(pk, st.messages, st.agg_sig, j, params_);
  st.aux_cache.emplace(key, aux);
  return aux;
}

const rsa_lvas::Signature& DirectoryLog::LatestAggSig(const std::string& ca_id) const {
  auto it = latest_.find(ca_id);
  if (it == latest_.end()) throw std::runtime_error("LatestAggSig: no epoch state");
  return it->second.agg_sig;
}

const rsa_lvas::PublicKey& DirectoryLog::GetCAPublicKey(const std::string& ca_id) const {
  return ca_pk_.at(ca_id);
}

// ---------- WebServer ----------
WebServer::WebServer(std::string ca_id, LeafRecord record, std::vector<uint8_t> record_bytes)
  : ca_id_(std::move(ca_id)), record_(std::move(record)), record_bytes_(std::move(record_bytes)) {
  m_ = Sha256(record_bytes_);
}

void WebServer::RefreshStaple(const DirectoryLog& log) {
  aux_ = log.GetAuxLatest(ca_id_, m_);
  epoch_ = log.current_epoch();
}

WebServer::HandshakePayload WebServer::MakeHandshakePayload() const {
  HandshakePayload hs;
  hs.ca_id = ca_id_;
  hs.record_bytes = record_bytes_;
  hs.aux_sig_bytes = rsa_lvas::SerializeSignature(aux_);
  hs.epoch = epoch_;
  return hs;
}

// ---------- Browser ----------
void Browser::AddTrustedCA(const std::string& ca_id, const rsa_lvas::PublicKey& pk) {
  trusted_ca_[ca_id] = pk;
}

bool Browser::VerifyHandshake(const WebServer::HandshakePayload& hs,
                              const rsa_lvas::Params& params,
                              std::string expected_dns) const {
  // 1) parse record
  LeafRecord r = DecodeLeafRecord(hs.record_bytes);

  if (r.dns != expected_dns) return false;

  // 2) find trusted CA pk
  auto it = trusted_ca_.find(hs.ca_id);
  if (it == trusted_ca_.end()) return false;

  // 3) compute message m = SHA256(record_bytes)
  std::vector<uint8_t> m = Sha256(hs.record_bytes);

  // 4) decode aux and verify (RSA-LVAS: aux is treated as normal signature)
  rsa_lvas::Signature aux = rsa_lvas::DeserializeSignature(hs.aux_sig_bytes);

  return rsa_lvas::Verify(it->second, rsa_lvas::BytesView{m.data(), m.size()}, aux, params);
}

} // namespace pki_lvas
