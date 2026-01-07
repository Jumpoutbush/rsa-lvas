#include "rsa_lvas.h"
#include "pki_lvas.h"

#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

// ---------------- CARecord: "CA certificate" analogue ----------------
struct CARecord {
  std::string issuer_ca_id;                  // who signs this record (parent CA)
  std::string subject_ca_id;                 // child CA id
  std::vector<uint8_t> subject_pk_blob;      // SerializePublicKey(child_pk)
  uint64_t not_before = 0;
  uint64_t not_after  = 0;
  uint32_t path_len   = 0;                   // simplified constraint
};

// minimal TLV helpers (self-contained)
static void put_u32(std::vector<uint8_t>& out, uint32_t x) {
  out.push_back((x >> 24) & 0xFF);
  out.push_back((x >> 16) & 0xFF);
  out.push_back((x >> 8) & 0xFF);
  out.push_back(x & 0xFF);
}
static uint32_t get_u32(const std::vector<uint8_t>& in, size_t& off) {
  if (off + 4 > in.size()) throw std::runtime_error("decode overflow(u32)");
  uint32_t x = (uint32_t(in[off]) << 24) | (uint32_t(in[off + 1]) << 16) |
               (uint32_t(in[off + 2]) << 8) | uint32_t(in[off + 3]);
  off += 4;
  return x;
}
static void put_u64(std::vector<uint8_t>& out, uint64_t x) {
  for (int i = 7; i >= 0; --i) out.push_back(uint8_t((x >> (8 * i)) & 0xFF));
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
  put_u32(out, (uint32_t)s.size());
  out.insert(out.end(), s.begin(), s.end());
}
static std::string get_str(const std::vector<uint8_t>& in, size_t& off) {
  uint32_t len = get_u32(in, off);
  if (off + len > in.size()) throw std::runtime_error("decode overflow(str)");
  std::string s(in.begin() + off, in.begin() + off + len);
  off += len;
  return s;
}

static std::vector<uint8_t> EncodeCARecord(const CARecord& r) {
  std::vector<uint8_t> out;
  out.insert(out.end(), {'C','A','R','E', 0x01});
  put_str(out, r.issuer_ca_id);
  put_str(out, r.subject_ca_id);
  put_blob(out, r.subject_pk_blob);
  put_u64(out, r.not_before);
  put_u64(out, r.not_after);
  put_u32(out, r.path_len);
  return out;
}

static CARecord DecodeCARecord(const std::vector<uint8_t>& bytes) {
  if (bytes.size() < 5) throw std::runtime_error("CARecord too short");
  if (!(bytes[0]=='C' && bytes[1]=='A' && bytes[2]=='R' && bytes[3]=='E'))
    throw std::runtime_error("CARecord magic mismatch");
  if (bytes[4] != 0x01) throw std::runtime_error("CARecord version mismatch");

  size_t off = 5;
  CARecord r;
  r.issuer_ca_id = get_str(bytes, off);
  r.subject_ca_id = get_str(bytes, off);
  r.subject_pk_blob = get_blob(bytes, off);
  r.not_before = get_u64(bytes, off);
  r.not_after = get_u64(bytes, off);
  r.path_len = get_u32(bytes, off);
  if (off != bytes.size()) throw std::runtime_error("CARecord trailing bytes");
  return r;
}

// ---------------- Simple CA wrapper ----------------
struct CA {
  std::string id;
  rsa_lvas::PublicKey pk;
  rsa_lvas::SecretKey sk;
};

static CA MakeCA(const std::string& id, const rsa_lvas::Params& params) {
  CA ca;
  ca.id = id;
  auto kp = rsa_lvas::KeyGen(params);
  ca.pk = std::move(kp.first);
  ca.sk = std::move(kp.second);
  return ca;
}

// CA signs arbitrary record bytes by signing m=SHA256(record_bytes)
static rsa_lvas::Signature SignRecord(const CA& issuer,
                                      const std::vector<uint8_t>& record_bytes,
                                      const rsa_lvas::Params& params) {
  auto m = pki_lvas::Sha256(record_bytes);
  return rsa_lvas::Sign(issuer.sk, rsa_lvas::BytesView{m.data(), m.size()}, params);
}

// ---------------- Handshake payload (server -> browser) ----------------
struct HandshakePayload {
  // chain records, from top to bottom:
  //   0: CARecord Root -> Intermediate
  //   1: CARecord Intermediate -> Issuing
  //   2: LeafRecord Issuing -> End-Entity
  std::vector<uint8_t> ca_record_root_to_inter;
  std::vector<uint8_t> ca_record_inter_to_issuing;
  std::vector<uint8_t> leaf_record;

  // stapled aux signatures for each record, serialized
  // aux is treated as a "normal signature" under RSA-LVAS Verify
  std::vector<uint8_t> aux_root_to_inter;
  std::vector<uint8_t> aux_inter_to_issuing;
  std::vector<uint8_t> aux_leaf;

  uint64_t epoch = 0;
};

int main() {
  rsa_lvas::Params params;
  params.rsa_bits = 2048;
  params.prime_bits = 256;

  // --- 1) Build a traditional-style CA hierarchy (3 layers) ---
  CA root = MakeCA("RootCA", params);
  CA inter = MakeCA("InterCA", params);
  CA issuing = MakeCA("IssuingCA", params);

  // --- 2) Construct CARecords (like CA certificates) ---
  CARecord r_root_inter;
  r_root_inter.issuer_ca_id = root.id;
  r_root_inter.subject_ca_id = inter.id;
  r_root_inter.subject_pk_blob = rsa_lvas::SerializePublicKey(inter.pk);
  r_root_inter.not_before = 1700000000;
  r_root_inter.not_after  = 1900000000;
  r_root_inter.path_len   = 1;

  auto bytes_root_inter = EncodeCARecord(r_root_inter);
  auto sig_root_inter   = SignRecord(root, bytes_root_inter, params);

  CARecord r_inter_iss;
  r_inter_iss.issuer_ca_id = inter.id;
  r_inter_iss.subject_ca_id = issuing.id;
  r_inter_iss.subject_pk_blob = rsa_lvas::SerializePublicKey(issuing.pk);
  r_inter_iss.not_before = 1700000000;
  r_inter_iss.not_after  = 1900000000;
  r_inter_iss.path_len   = 0;

  auto bytes_inter_iss = EncodeCARecord(r_inter_iss);
  auto sig_inter_iss   = SignRecord(inter, bytes_inter_iss, params);

  // --- 3) Construct LeafRecord (end-entity "certificate") ---
  pki_lvas::LeafRecord leaf;
  leaf.dns = "example.com";
  leaf.issuer_ca_id = issuing.id;
  leaf.not_before = 1700000000;
  leaf.not_after  = 1900000000;
  leaf.ee_pubkey = {'e','e','-','p','k'};

  auto bytes_leaf = pki_lvas::EncodeLeafRecord(leaf);
  auto sig_leaf   = SignRecord(issuing, bytes_leaf, params);

  // --- 4) Directory Log collects & aggregates per-CA (RSA-LVAS magic happens here) ---
  pki_lvas::DirectoryLog log(params);
  log.RegisterCA(root.id, root.pk);
  log.RegisterCA(inter.id, inter.pk);
  log.RegisterCA(issuing.id, issuing.pk);

  // submit signed hashes (m) to log under the issuer CA id
  auto m_root_inter = pki_lvas::Sha256(bytes_root_inter);
  auto m_inter_iss  = pki_lvas::Sha256(bytes_inter_iss);
  auto m_leaf       = pki_lvas::Sha256(bytes_leaf);

  log.SubmitRecord(root.id,   m_root_inter, sig_root_inter);
  log.SubmitRecord(inter.id,  m_inter_iss,  sig_inter_iss);
  log.SubmitRecord(issuing.id,m_leaf,       sig_leaf);

  log.CloseEpoch();
  uint64_t epoch = log.current_epoch();

  // --- 5) Server staples aux for each record (instead of sending raw cert signatures) ---
  rsa_lvas::Signature aux_root_inter = log.GetAuxLatest(root.id, m_root_inter);
  rsa_lvas::Signature aux_inter_iss  = log.GetAuxLatest(inter.id, m_inter_iss);
  rsa_lvas::Signature aux_leaf_sig   = log.GetAuxLatest(issuing.id, m_leaf);

  HandshakePayload hs;
  hs.ca_record_root_to_inter = bytes_root_inter;
  hs.ca_record_inter_to_issuing = bytes_inter_iss;
  hs.leaf_record = bytes_leaf;

  hs.aux_root_to_inter = rsa_lvas::SerializeSignature(aux_root_inter);
  hs.aux_inter_to_issuing = rsa_lvas::SerializeSignature(aux_inter_iss);
  hs.aux_leaf = rsa_lvas::SerializeSignature(aux_leaf_sig);
  hs.epoch = epoch;

  // --- 6) Browser verifies chain using ONLY Verify(pk, hash(record), aux) ---
  // Trust anchor: root pk is in trust store
  rsa_lvas::PublicKey trusted_root_pk = root.pk;

  // (a) Verify Root -> Inter CARecord
  auto aux1 = rsa_lvas::DeserializeSignature(hs.aux_root_to_inter);
  auto m1 = pki_lvas::Sha256(hs.ca_record_root_to_inter);
  bool ok1 = rsa_lvas::Verify(trusted_root_pk, rsa_lvas::BytesView{m1.data(), m1.size()}, aux1, params);
  if (!ok1) {
    std::cerr << "Chain verify failed at Root->Inter\n";
    return 1;
  }
  CARecord parsed1 = DecodeCARecord(hs.ca_record_root_to_inter);
  rsa_lvas::PublicKey inter_pk_from_record = rsa_lvas::DeserializePublicKey(parsed1.subject_pk_blob);

  // (b) Verify Inter -> Issuing CARecord
  auto aux2 = rsa_lvas::DeserializeSignature(hs.aux_inter_to_issuing);
  auto m2 = pki_lvas::Sha256(hs.ca_record_inter_to_issuing);
  bool ok2 = rsa_lvas::Verify(inter_pk_from_record, rsa_lvas::BytesView{m2.data(), m2.size()}, aux2, params);
  if (!ok2) {
    std::cerr << "Chain verify failed at Inter->Issuing\n";
    return 1;
  }
  CARecord parsed2 = DecodeCARecord(hs.ca_record_inter_to_issuing);
  rsa_lvas::PublicKey issuing_pk_from_record = rsa_lvas::DeserializePublicKey(parsed2.subject_pk_blob);

  // (c) Verify Issuing -> LeafRecord
  auto aux3 = rsa_lvas::DeserializeSignature(hs.aux_leaf);
  auto m3 = pki_lvas::Sha256(hs.leaf_record);
  bool ok3 = rsa_lvas::Verify(issuing_pk_from_record, rsa_lvas::BytesView{m3.data(), m3.size()}, aux3, params);
  if (!ok3) {
    std::cerr << "Chain verify failed at Issuing->Leaf\n";
    return 1;
  }

  // semantic check: DNS
  auto leaf_parsed = pki_lvas::DecodeLeafRecord(hs.leaf_record);
  if (leaf_parsed.dns != "example.com") {
    std::cerr << "DNS mismatch\n";
    return 1;
  }

  std::cout << "Multi-CA PKI demo verify ok? YES (epoch=" << hs.epoch << ")\n";
  return 0;
}
