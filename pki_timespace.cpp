#include "pki_timespace.h"

#include <stdexcept>

namespace pki_timespace {

// --- encoding helpers for HashBlock ---
static void put_u32(std::vector<uint8_t>& out, uint32_t x) {
  out.push_back((x >> 24) & 0xFF);
  out.push_back((x >> 16) & 0xFF);
  out.push_back((x >> 8) & 0xFF);
  out.push_back(x & 0xFF);
}
static void put_u64(std::vector<uint8_t>& out, uint64_t x) {
  for (int i = 7; i >= 0; --i) out.push_back(uint8_t((x >> (8*i)) & 0xFF));
}

std::vector<uint8_t> HashBlock(uint64_t epoch,
                               const std::string& ca_id,
                               uint64_t t,
                               const std::vector<std::vector<uint8_t>>& msg_hashes) {
  std::vector<uint8_t> buf;
  buf.insert(buf.end(), {'B','L','K',0x01});   // magic+ver
  put_u64(buf, epoch);
  put_u32(buf, (uint32_t)ca_id.size());
  buf.insert(buf.end(), ca_id.begin(), ca_id.end());
  put_u64(buf, t);

  // append each m_i (fixed 32 bytes in our design)
  for (const auto& m : msg_hashes) {
    if (m.size() != 32) throw std::runtime_error("HashBlock: msg hash must be 32 bytes");
    buf.insert(buf.end(), m.begin(), m.end());
  }
  return pki_lvas::Sha256(buf);
}

// ---------------- IssuerCA_TS ----------------
IssuerCA_TS::IssuerCA_TS(std::string ca_id, const rsa_lvas::Params& params)
  : ca_id_(std::move(ca_id)), params_(params) {
  auto kp = rsa_lvas::KeyGen(params_);
  pk_ = std::move(kp.first);
  sk_ = std::move(kp.second);
}

IssuerCA_TS::LeafItem IssuerCA_TS::IssueLeaf(const std::string& dns,
                                             const std::vector<uint8_t>& ee_pubkey,
                                             uint64_t not_before,
                                             uint64_t not_after) const {
  LeafItem out;
  out.record.dns = dns;
  out.record.issuer_ca_id = ca_id_;
  out.record.not_before = not_before;
  out.record.not_after = not_after;
  out.record.ee_pubkey = ee_pubkey;

  out.record_bytes = pki_lvas::EncodeLeafRecord(out.record);
  out.m = pki_lvas::Sha256(out.record_bytes);
  return out;
}

std::vector<IssuerCA_TS::SignedBlock>
IssuerCA_TS::BuildAndSignBlocks(const std::vector<LeafItem>& items,
                                uint64_t epoch,
                                size_t L2) const {
  if (L2 == 0) throw std::runtime_error("L2 must be > 0");

  std::vector<SignedBlock> out;
  uint64_t t = 0;

  for (size_t i = 0; i < items.size(); i += L2, ++t) {
    SignedBlock blk;
    blk.t = t;

    size_t end = std::min(items.size(), i + L2);
    blk.record_bytes.reserve(end - i);
    blk.msg_hashes.reserve(end - i);

    for (size_t k = i; k < end; k++) {
      blk.record_bytes.push_back(items[k].record_bytes);
      blk.msg_hashes.push_back(items[k].m);
    }

    blk.h_t = HashBlock(epoch, ca_id_, blk.t, blk.msg_hashes);

    // CA signs the block-hash h_t (1 signature per L2 records)
    blk.sig_h = rsa_lvas::Sign(sk_,
                              rsa_lvas::BytesView{blk.h_t.data(), blk.h_t.size()},
                              params_);
    out.push_back(std::move(blk));
  }
  return out;
}

// ---------------- DirectoryLog_TS ----------------
DirectoryLog_TS::DirectoryLog_TS(rsa_lvas::Params params, size_t L1, size_t L2)
  : params_(params), L1_(L1), L2_(L2) {
  if (L1_ == 0 || L2_ == 0) throw std::runtime_error("L1 and L2 must be > 0");
}

void DirectoryLog_TS::RegisterCA(const std::string& ca_id, const rsa_lvas::PublicKey& pk) {
  ca_pk_[ca_id] = pk;
}

void DirectoryLog_TS::SubmitBlock(const std::string& ca_id,
                                  uint64_t epoch,
                                  const IssuerCA_TS::SignedBlock& blk) {
  (void)epoch; // we index by "latest epoch" in this demo
  auto it = ca_pk_.find(ca_id);
  if (it == ca_pk_.end()) throw std::runtime_error("SubmitBlock: unknown CA");

  // verify signature on block-hash
  if (!rsa_lvas::Verify(it->second,
                        rsa_lvas::BytesView{blk.h_t.data(), blk.h_t.size()},
                        blk.sig_h,
                        params_)) {
    throw std::runtime_error("SubmitBlock: invalid block signature");
  }

  // basic sanity: h_t must match recomputation from msg_hashes
  auto h2 = HashBlock(epoch, ca_id, blk.t, blk.msg_hashes);
  if (h2 != blk.h_t) throw std::runtime_error("SubmitBlock: block hash mismatch");

  pending_blocks_[ca_id].push_back(blk);
}

void DirectoryLog_TS::CloseEpoch(uint64_t epoch) {
  epoch_ = epoch;

  for (auto& kv : pending_blocks_) {
    const std::string& ca_id = kv.first;
    auto& blocks = kv.second;
    if (blocks.empty()) continue;

    const auto& pk = ca_pk_.at(ca_id);

    EpochState st;
    st.epoch = epoch;

    // group blocks into super-blocks of L1
    size_t sb_count = 0;
    for (size_t i = 0; i < blocks.size(); i += L1_, ++sb_count) {
      size_t end = std::min(blocks.size(), i + L1_);

      SuperBlockState sb;
      sb.s = sb_count;
      sb.blocks.reserve(end - i);
      sb.h_list.reserve(end - i);

      std::vector<std::pair<std::vector<uint8_t>, rsa_lvas::Signature>> pairs;
      pairs.reserve(end - i);

      for (size_t k = i; k < end; k++) {
        sb.blocks.push_back(blocks[k]);
        sb.h_list.push_back(blocks[k].h_t);
        pairs.push_back({blocks[k].h_t, blocks[k].sig_h});
      }

      // Aggregate signatures on {h_t} within this super-block => Σ_s
      rsa_lvas::Signature agg = rsa_lvas::Aggregate(pk, pairs, params_);
      sb.agg_sig_bytes = rsa_lvas::SerializeSignature(agg);

      // build leaf index: for each leaf m inside blocks, map to (sb_idx, blk_idx)
      size_t local_blk_idx = 0;
      for (size_t k = i; k < end; k++, local_blk_idx++) {
        for (const auto& m : blocks[k].msg_hashes) {
          st.leaf_index.emplace(pki_lvas::Hex(m), EpochState::Loc{st.superblocks.size(), local_blk_idx});
        }
      }

      st.superblocks.push_back(std::move(sb));
    }

    latest_[ca_id] = std::move(st);
    blocks.clear(); // forget pending (tradeoff: we keep only super-block aggregates + blocks content)
  }
}

std::vector<uint8_t>
DirectoryLog_TS::OpenBlockHashAux(const std::string& ca_id,
                                  const SuperBlockState& sb,
                                  const std::vector<uint8_t>& target_h) const {
  const auto& pk = ca_pk_.at(ca_id);

  std::string key = pki_lvas::Hex(target_h);
  auto it = sb.aux_cache.find(key);
  if (it != sb.aux_cache.end()) return it->second;

  // Deserialize aggregate signature
  rsa_lvas::Signature agg = rsa_lvas::DeserializeSignature(sb.agg_sig_bytes);

  // find index j where h_list[j] == target_h
  size_t j = (size_t)-1;
  for (size_t i = 0; i < sb.h_list.size(); i++) {
    if (sb.h_list[i] == target_h) { j = i; break; }
  }
  if (j == (size_t)-1) throw std::runtime_error("OpenBlockHashAux: target not in super-block");

  // RSA-LVAS LocalOpen over messages = h_list (size <= L1)
  rsa_lvas::Signature aux = rsa_lvas::LocalOpen(pk, sb.h_list, agg, j, params_);
  auto aux_bytes = rsa_lvas::SerializeSignature(aux);

  sb.aux_cache.emplace(key, aux_bytes);
  return aux_bytes;
}

DirectoryLog_TS::Staple
DirectoryLog_TS::GetStapleLatest(const std::string& ca_id,
                                 const std::vector<uint8_t>& leaf_record_bytes) const {
  auto it = latest_.find(ca_id);
  if (it == latest_.end()) throw std::runtime_error("GetStapleLatest: no epoch for CA");
  const EpochState& st = it->second;

  std::vector<uint8_t> m = pki_lvas::Sha256(leaf_record_bytes);
  auto lit = st.leaf_index.find(pki_lvas::Hex(m));
  if (lit == st.leaf_index.end()) throw std::runtime_error("GetStapleLatest: leaf not found in latest epoch");

  const auto& loc = lit->second;
  const SuperBlockState& sb = st.superblocks.at(loc.sb_idx);
  const auto& blk = sb.blocks.at(loc.blk_idx);

  // compute aux for block-hash h_t
  std::vector<uint8_t> aux_bytes = OpenBlockHashAux(ca_id, sb, blk.h_t);

  Staple out;
  out.ca_id = ca_id;
  out.epoch = st.epoch;
  out.t = blk.t;
  out.leaf_record_bytes = leaf_record_bytes;
  out.block_record_bytes = blk.record_bytes;
  out.aux_sig_bytes = std::move(aux_bytes);
  return out;
}

size_t DirectoryLog_TS::StoredAggregateSigCount(const std::string& ca_id) const {
  auto it = latest_.find(ca_id);
  if (it == latest_.end()) return 0;
  return it->second.superblocks.size();
}

// ---------------- Browser_TS ----------------
void Browser_TS::AddTrustedCA(const std::string& ca_id, const rsa_lvas::PublicKey& pk) {
  trusted_[ca_id] = pk;
}

bool Browser_TS::VerifyStaple(const DirectoryLog_TS::Staple& st,
                              const rsa_lvas::Params& params,
                              const std::string& expected_dns) const {
  // 1) parse leaf record and check DNS (simplified semantic check)
  pki_lvas::LeafRecord leaf = pki_lvas::DecodeLeafRecord(st.leaf_record_bytes);
  if (leaf.dns != expected_dns) return false;

  // 2) find CA pk
  auto it = trusted_.find(st.ca_id);
  if (it == trusted_.end()) return false;
  const auto& pk = it->second;

  // 3) compute msg hashes for whole block
  std::vector<std::vector<uint8_t>> msg_hashes;
  msg_hashes.reserve(st.block_record_bytes.size());

  bool leaf_found = false;
  for (const auto& rb : st.block_record_bytes) {
    if (rb == st.leaf_record_bytes) leaf_found = true;
    msg_hashes.push_back(pki_lvas::Sha256(rb));
  }
  if (!leaf_found) return false;

  // 4) recompute block hash h_t
  std::vector<uint8_t> h_t = HashBlock(st.epoch, st.ca_id, st.t, msg_hashes);

  // 5) aux is treated as *signature on block hash* (RSA-LVAS property)
  rsa_lvas::Signature aux = rsa_lvas::DeserializeSignature(st.aux_sig_bytes);

  return rsa_lvas::Verify(pk, rsa_lvas::BytesView{h_t.data(), h_t.size()}, aux, params);
}

} // namespace pki_timespace
