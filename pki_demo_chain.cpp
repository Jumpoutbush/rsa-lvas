#include "rsa_lvas.h"
#include "pki_lvas.h"

#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

// ---------------- CARecord: "CA certificate" analogue ----------------
struct CARecord {
  std::string issuer_ca_id;                  // parent CA id (signer)
  std::string subject_ca_id;                 // child CA id
  std::vector<uint8_t> subject_pk_blob;      // SerializePublicKey(child_pk)
  uint64_t not_before = 0;
  uint64_t not_after  = 0;
  uint32_t path_len   = 0;                   // simplified constraint
};

// --- minimal TLV helpers ---
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
  std::vector<uint8_t> ca_record_root_to_inter;
  std::vector<uint8_t> ca_record_inter_to_issuing;
  std::vector<uint8_t> leaf_record;

  std::vector<uint8_t> aux_root_to_inter;
  std::vector<uint8_t> aux_inter_to_issuing;
  std::vector<uint8_t> aux_leaf;

  uint64_t epoch = 0;
};

int main() {
  rsa_lvas::Params params;
  params.rsa_bits = 3072;
  params.prime_bits = 256;

  // ---------------- Scale knobs ----------------
  constexpr size_t NUM_INTER = 2;
  constexpr size_t NUM_ISS_PER_INTER = 5;
  // 为了更明显体现 LVAS：每个 issuing 生成不少 leaf
  constexpr size_t LEAVES_PER_ISSUING = 80; // 你可调大到 500/1000 观察差异
  constexpr uint64_t NB = 1700000000;
  constexpr uint64_t NA = 1900000000;

  // ---------------- 1) Build CA hierarchy ----------------
  CA root = MakeCA("RootCA", params);

  std::vector<CA> inters;
  inters.reserve(NUM_INTER);
  for (size_t i = 0; i < NUM_INTER; i++) {
    inters.push_back(MakeCA("InterCA" + std::to_string(i), params));
  }

  // issuing[inter_idx][iss_idx]
  std::vector<std::vector<CA>> issuing(NUM_INTER);
  for (size_t i = 0; i < NUM_INTER; i++) {
    issuing[i].reserve(NUM_ISS_PER_INTER);
    for (size_t j = 0; j < NUM_ISS_PER_INTER; j++) {
      issuing[i].push_back(MakeCA("IssuingCA_" + std::to_string(i) + "_" + std::to_string(j), params));
    }
  }

  // ---------------- 2) Directory log register all CA public keys ----------------
  pki_lvas::DirectoryLog log(params);

  log.RegisterCA(root.id, root.pk);
  for (auto& ic : inters) log.RegisterCA(ic.id, ic.pk);
  for (size_t i = 0; i < NUM_INTER; i++) {
    for (size_t j = 0; j < NUM_ISS_PER_INTER; j++) {
      log.RegisterCA(issuing[i][j].id, issuing[i][j].pk);
    }
  }

  // ---------------- 3) Root issues InterCA records; Inter issues Issuing records ----------------
  // 保存每条 CARecord bytes 以便后续挑选链
  std::vector<std::vector<uint8_t>> bytes_root_to_inter(NUM_INTER);
  std::vector<std::vector<std::vector<uint8_t>>> bytes_inter_to_iss(NUM_INTER,
      std::vector<std::vector<uint8_t>>(NUM_ISS_PER_INTER));

  // (a) Root -> each Inter
  for (size_t i = 0; i < NUM_INTER; i++) {
    CARecord rec;
    rec.issuer_ca_id = root.id;
    rec.subject_ca_id = inters[i].id;
    rec.subject_pk_blob = rsa_lvas::SerializePublicKey(inters[i].pk);
    rec.not_before = NB;
    rec.not_after = NA;
    rec.path_len = 1; // can issue sub-CA

    auto bytes = EncodeCARecord(rec);
    auto sig = SignRecord(root, bytes, params);

    auto m = pki_lvas::Sha256(bytes);
    log.SubmitRecord(root.id, m, sig);

    bytes_root_to_inter[i] = std::move(bytes);
  }

  // (b) Inter -> each Issuing under it
  for (size_t i = 0; i < NUM_INTER; i++) {
    for (size_t j = 0; j < NUM_ISS_PER_INTER; j++) {
      CARecord rec;
      rec.issuer_ca_id = inters[i].id;
      rec.subject_ca_id = issuing[i][j].id;
      rec.subject_pk_blob = rsa_lvas::SerializePublicKey(issuing[i][j].pk);
      rec.not_before = NB;
      rec.not_after = NA;
      rec.path_len = 0; // issuing should not create more CAs

      auto bytes = EncodeCARecord(rec);
      auto sig = SignRecord(inters[i], bytes, params);

      auto m = pki_lvas::Sha256(bytes);
      log.SubmitRecord(inters[i].id, m, sig);

      bytes_inter_to_iss[i][j] = std::move(bytes);
    }
  }

  // ---------------- 4) Issuing issues many leaf records ----------------
  // 保存所有 leaf，方便挑一个来模拟“服务器握手”
  struct LeafEntry {
    size_t inter_idx;
    size_t iss_idx;
    size_t leaf_idx;
    std::string dns;
    std::vector<uint8_t> leaf_bytes;
  };
  std::vector<LeafEntry> all_leaves;
  all_leaves.reserve(NUM_INTER * NUM_ISS_PER_INTER * LEAVES_PER_ISSUING);

  for (size_t i = 0; i < NUM_INTER; i++) {
    for (size_t j = 0; j < NUM_ISS_PER_INTER; j++) {
      for (size_t k = 0; k < LEAVES_PER_ISSUING; k++) {
        pki_lvas::LeafRecord leaf;
        leaf.dns = "site-" + std::to_string(i) + "-" + std::to_string(j) + "-" + std::to_string(k) + ".example.com";
        leaf.issuer_ca_id = issuing[i][j].id;
        leaf.not_before = NB;
        leaf.not_after = NA;
        leaf.ee_pubkey = {'e','e','-', (uint8_t)i, (uint8_t)j, (uint8_t)k};

        auto bytes = pki_lvas::EncodeLeafRecord(leaf);
        auto sig = SignRecord(issuing[i][j], bytes, params);

        auto m = pki_lvas::Sha256(bytes);
        log.SubmitRecord(issuing[i][j].id, m, sig);

        all_leaves.push_back({i, j, k, leaf.dns, std::move(bytes)});
      }
    }
  }

  // ---------------- 5) Close epoch => Log aggregates per-CA ----------------
  log.CloseEpoch();
  uint64_t epoch = log.current_epoch();

  // ---------------- 6) Pick ONE leaf to simulate "server stapling chain" ----------------
  // 你可以换成随机选择；这里固定挑一个，便于复现实验
  const LeafEntry& target = all_leaves.at((NUM_INTER * NUM_ISS_PER_INTER * LEAVES_PER_ISSUING) / 2);

  const auto& bytes_r_i = bytes_root_to_inter[target.inter_idx];
  const auto& bytes_i_s = bytes_inter_to_iss[target.inter_idx][target.iss_idx];
  const auto& bytes_leaf = target.leaf_bytes;

  auto m_r_i = pki_lvas::Sha256(bytes_r_i);
  auto m_i_s = pki_lvas::Sha256(bytes_i_s);
  auto m_l   = pki_lvas::Sha256(bytes_leaf);

  // Log provides aux (LocalOpen) for each record
  rsa_lvas::Signature aux_r_i = log.GetAuxLatest(root.id, m_r_i);
  rsa_lvas::Signature aux_i_s = log.GetAuxLatest(inters[target.inter_idx].id, m_i_s);
  rsa_lvas::Signature aux_l   = log.GetAuxLatest(issuing[target.inter_idx][target.iss_idx].id, m_l);

  HandshakePayload hs;
  hs.ca_record_root_to_inter = bytes_r_i;
  hs.ca_record_inter_to_issuing = bytes_i_s;
  hs.leaf_record = bytes_leaf;

  hs.aux_root_to_inter = rsa_lvas::SerializeSignature(aux_r_i);
  hs.aux_inter_to_issuing = rsa_lvas::SerializeSignature(aux_i_s);
  hs.aux_leaf = rsa_lvas::SerializeSignature(aux_l);
  hs.epoch = epoch;

  // ---------------- 7) Browser verifies chain (trust anchor = root pk) ----------------
  rsa_lvas::PublicKey trusted_root_pk = root.pk;

  // (a) Verify Root -> Inter
  {
    auto aux = rsa_lvas::DeserializeSignature(hs.aux_root_to_inter);
    auto m = pki_lvas::Sha256(hs.ca_record_root_to_inter);
    bool ok = rsa_lvas::Verify(trusted_root_pk, rsa_lvas::BytesView{m.data(), m.size()}, aux, params);
    if (!ok) { std::cerr << "Fail at Root->Inter\n"; return 1; }
  }
  CARecord parsed1 = DecodeCARecord(hs.ca_record_root_to_inter);
  rsa_lvas::PublicKey inter_pk_from_record = rsa_lvas::DeserializePublicKey(parsed1.subject_pk_blob);

  // (b) Verify Inter -> Issuing
  {
    auto aux = rsa_lvas::DeserializeSignature(hs.aux_inter_to_issuing);
    auto m = pki_lvas::Sha256(hs.ca_record_inter_to_issuing);
    bool ok = rsa_lvas::Verify(inter_pk_from_record, rsa_lvas::BytesView{m.data(), m.size()}, aux, params);
    if (!ok) { std::cerr << "Fail at Inter->Issuing\n"; return 1; }
  }
  CARecord parsed2 = DecodeCARecord(hs.ca_record_inter_to_issuing);
  rsa_lvas::PublicKey issuing_pk_from_record = rsa_lvas::DeserializePublicKey(parsed2.subject_pk_blob);

  // (c) Verify Issuing -> Leaf
  {
    auto aux = rsa_lvas::DeserializeSignature(hs.aux_leaf);
    auto m = pki_lvas::Sha256(hs.leaf_record);
    bool ok = rsa_lvas::Verify(issuing_pk_from_record, rsa_lvas::BytesView{m.data(), m.size()}, aux, params);
    if (!ok) { std::cerr << "Fail at Issuing->Leaf\n"; return 1; }
  }

  auto leaf_parsed = pki_lvas::DecodeLeafRecord(hs.leaf_record);
  if (leaf_parsed.dns != target.dns) {
    std::cerr << "DNS mismatch\n";
    return 1;
  }

  // ---------------- 8) Print stats to highlight LVAS signature advantage ----------------
  const size_t num_ca_records = NUM_INTER + NUM_INTER * NUM_ISS_PER_INTER;
  const size_t num_leaf_records = NUM_INTER * NUM_ISS_PER_INTER * LEAVES_PER_ISSUING;
  const size_t total_records = num_ca_records + num_leaf_records;

  const size_t num_cas = 1 + NUM_INTER + (NUM_INTER * NUM_ISS_PER_INTER); // root + inter + issuing
  std::cout << "OK: verify chain for " << target.dns << " (epoch=" << hs.epoch << ")\n";
  std::cout << "Records submitted: CARecords=" << num_ca_records
            << ", LeafRecords=" << num_leaf_records
            << ", total=" << total_records << "\n";
  std::cout << "Traditional PKI would have ~" << total_records
            << " individual signatures stored/distributed.\n";
  std::cout << "LVAS Log stores ~1 aggregate signature per CA per epoch => "
            << num_cas << " aggregate signatures (plus message index).\n";

  return 0;
}
