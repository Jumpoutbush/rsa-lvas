#include "rsa_lvas.h"
#include "pki_lvas.h"

#include <cstdint>
#include <cstdlib>
#include <chrono>
#include <iostream>
#include <iomanip>
#include <stdexcept>
#include <string>
#include <vector>
#include <unordered_map>
#include <utility>
#include <algorithm>

struct PerfEntry {
  uint64_t calls = 0;
  uint64_t total_ns = 0;
};

class PerfMonitor {
public:
  void Add(const std::string& name, uint64_t ns) {
    auto& e = entries_[name];
    e.calls += 1;
    e.total_ns += ns;
  }

  void PrintSummary(std::ostream& os) const {
    if (entries_.empty()) return;
    std::vector<std::string> preferred = {
      "rsa.keygen",
      "sha256.record_hash_build",
      "sha256.block_hash",
      "sign.block_hash",
      "verify.block_sig_submit",
      "aggregate.superblock",
      "local_open.staple",
      "sha256.lookup_record",
      "sha256.record_hash_verify",
      "verify.aux_sig"
    };

    auto print_row = [&](const std::string& name, const PerfEntry& e) {
      double total_ms = static_cast<double>(e.total_ns) / 1e6;
      double avg_us = e.calls ? (static_cast<double>(e.total_ns) / 1e3 / static_cast<double>(e.calls)) : 0.0;
      os << std::left << std::setw(32) << name
         << std::right << std::setw(12) << e.calls
         << std::setw(16) << std::fixed << std::setprecision(3) << total_ms
         << std::setw(16) << std::fixed << std::setprecision(3) << avg_us << "\n";
    };

    os << "\n=== Timing Monitor (algorithm-level) ===\n";
    os << std::left << std::setw(32) << "Metric"
       << std::right << std::setw(12) << "Calls"
       << std::setw(16) << "Total(ms)"
       << std::setw(16) << "Avg(us)" << "\n";
    std::unordered_map<std::string, bool> printed;
    printed.reserve(entries_.size());

    for (const auto& name : preferred) {
      auto it = entries_.find(name);
      if (it == entries_.end()) continue;
      print_row(it->first, it->second);
      printed[it->first] = true;
    }

    std::vector<std::pair<std::string, PerfEntry>> others;
    others.reserve(entries_.size());
    for (const auto& kv : entries_) {
      if (!printed[kv.first]) others.push_back(kv);
    }
    std::sort(others.begin(), others.end(),
              [](const auto& a, const auto& b) { return a.first < b.first; });
    for (const auto& row : others) {
      print_row(row.first, row.second);
    }
  }

private:
  std::unordered_map<std::string, PerfEntry> entries_;
};

static PerfMonitor* g_perf = nullptr;
using PerfClock = std::chrono::steady_clock;

static void PerfAdd(const char* metric, PerfClock::time_point t0) {
  if (!g_perf) return;
  auto ns = std::chrono::duration_cast<std::chrono::nanoseconds>(PerfClock::now() - t0).count();
  g_perf->Add(metric, static_cast<uint64_t>(ns));
}

static std::pair<rsa_lvas::PublicKey, rsa_lvas::SecretKey>
KeyGenTimed(const rsa_lvas::Params& params) {
  auto t0 = PerfClock::now();
  auto kp = rsa_lvas::KeyGen(params);
  PerfAdd("rsa.keygen", t0);
  return kp;
}

static std::vector<uint8_t> Sha256Timed(const std::vector<uint8_t>& in, const char* metric) {
  auto t0 = PerfClock::now();
  auto out = pki_lvas::Sha256(in);
  PerfAdd(metric, t0);
  return out;
}

static rsa_lvas::Signature SignTimed(const rsa_lvas::SecretKey& sk,
                                     const std::vector<uint8_t>& msg,
                                     const rsa_lvas::Params& params,
                                     const char* metric) {
  auto t0 = PerfClock::now();
  auto sig = rsa_lvas::Sign(sk, rsa_lvas::BytesView{msg.data(), msg.size()}, params);
  PerfAdd(metric, t0);
  return sig;
}

static bool VerifyTimed(const rsa_lvas::PublicKey& pk,
                        const std::vector<uint8_t>& msg,
                        const rsa_lvas::Signature& sig,
                        const rsa_lvas::Params& params,
                        const char* metric) {
  auto t0 = PerfClock::now();
  bool ok = rsa_lvas::Verify(pk, rsa_lvas::BytesView{msg.data(), msg.size()}, sig, params);
  PerfAdd(metric, t0);
  return ok;
}

static rsa_lvas::Signature AggregateTimed(
    const rsa_lvas::PublicKey& pk,
    const std::vector<std::pair<std::vector<uint8_t>, rsa_lvas::Signature>>& pairs,
    const rsa_lvas::Params& params,
    const char* metric) {
  auto t0 = PerfClock::now();
  auto agg = rsa_lvas::Aggregate(pk, pairs, params);
  PerfAdd(metric, t0);
  return agg;
}

static rsa_lvas::Signature LocalOpenTimed(
    const rsa_lvas::PublicKey& pk,
    const std::vector<std::vector<uint8_t>>& messages,
    const rsa_lvas::Signature& agg,
    size_t index,
    const rsa_lvas::Params& params,
    const char* metric) {
  auto t0 = PerfClock::now();
  auto aux = rsa_lvas::LocalOpen(pk, messages, agg, index, params);
  PerfAdd(metric, t0);
  return aux;
}

// -------------------- small helpers --------------------
static void put_u32(std::vector<uint8_t>& out, uint32_t x) {
  out.push_back((x >> 24) & 0xFF);
  out.push_back((x >> 16) & 0xFF);
  out.push_back((x >> 8) & 0xFF);
  out.push_back(x & 0xFF);
}
static void put_u64(std::vector<uint8_t>& out, uint64_t x) {
  for (int i = 7; i >= 0; --i) out.push_back(uint8_t((x >> (8 * i)) & 0xFF));
}
static void put_str(std::vector<uint8_t>& out, const std::string& s) {
  put_u32(out, (uint32_t)s.size());
  out.insert(out.end(), s.begin(), s.end());
}
static void put_blob(std::vector<uint8_t>& out, const std::vector<uint8_t>& b) {
  put_u32(out, (uint32_t)b.size());
  out.insert(out.end(), b.begin(), b.end());
}
static std::string hex_of(const std::vector<uint8_t>& b) {
  static const char* h = "0123456789abcdef";
  std::string s;
  s.reserve(b.size() * 2);
  for (uint8_t x : b) {
    s.push_back(h[x >> 4]);
    s.push_back(h[x & 0xF]);
  }
  return s;
}

// -------------------- CARecord (CA cert analogue) --------------------
struct CARecord {
  std::string issuer_ca_id;
  std::string subject_ca_id;
  std::vector<uint8_t> subject_pk_blob; // SerializePublicKey(child_pk)
  uint64_t not_before = 0;
  uint64_t not_after  = 0;
  uint32_t path_len   = 0;
};

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

// decode CARecord using the DecodeCARecord from your previous pki_demo_chain version
// To keep this demo self-contained, we re-implement a minimal decoder:

static uint32_t get_u32(const std::vector<uint8_t>& in, size_t& off) {
  if (off + 4 > in.size()) throw std::runtime_error("decode overflow(u32)");
  uint32_t x = (uint32_t(in[off]) << 24) | (uint32_t(in[off + 1]) << 16) |
               (uint32_t(in[off + 2]) << 8) | uint32_t(in[off + 3]);
  off += 4;
  return x;
}
static uint64_t get_u64(const std::vector<uint8_t>& in, size_t& off) {
  if (off + 8 > in.size()) throw std::runtime_error("decode overflow(u64)");
  uint64_t x = 0;
  for (int i = 0; i < 8; i++) x = (x << 8) | in[off + i];
  off += 8;
  return x;
}
static std::string get_str(const std::vector<uint8_t>& in, size_t& off) {
  uint32_t len = get_u32(in, off);
  if (off + len > in.size()) throw std::runtime_error("decode overflow(str)");
  std::string s(in.begin() + off, in.begin() + off + len);
  off += len;
  return s;
}
static std::vector<uint8_t> get_blob(const std::vector<uint8_t>& in, size_t& off) {
  uint32_t len = get_u32(in, off);
  if (off + len > in.size()) throw std::runtime_error("decode overflow(blob)");
  std::vector<uint8_t> b(in.begin() + off, in.begin() + off + len);
  off += len;
  return b;
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
  r.not_after  = get_u64(bytes, off);
  r.path_len   = get_u32(bytes, off);
  if (off != bytes.size()) throw std::runtime_error("CARecord trailing bytes");
  return r;
}

// -------------------- time-space block hash --------------------
// h_t = SHA256( "BLK1" || epoch || issuer_id || t || concat(m_i) ), where m_i=SHA256(record_bytes)
static std::vector<uint8_t> HashBlock(uint64_t epoch,
                                      const std::string& issuer_id,
                                      uint64_t t,
                                      const std::vector<std::vector<uint8_t>>& msg_hashes_32) {
  std::vector<uint8_t> buf;
  buf.insert(buf.end(), {'B','L','K',0x01});
  put_u64(buf, epoch);
  put_str(buf, issuer_id);
  put_u64(buf, t);
  for (const auto& m : msg_hashes_32) {
    if (m.size() != 32) throw std::runtime_error("HashBlock: msg hash must be 32 bytes");
    buf.insert(buf.end(), m.begin(), m.end());
  }
  return Sha256Timed(buf, "sha256.block_hash");
}

// -------------------- CA object --------------------
struct CA {
  std::string id;
  rsa_lvas::PublicKey pk;
  rsa_lvas::SecretKey sk;
};

static CA MakeCA(const std::string& id, const rsa_lvas::Params& params) {
  CA ca;
  ca.id = id;
  auto kp = KeyGenTimed(params);
  ca.pk = std::move(kp.first);
  ca.sk = std::move(kp.second);
  return ca;
}

// -------------------- DirectoryLog_TS (per-issuer block/superblock aggregation) --------------------
class DirectoryLog_TS {
public:
  struct Block {
    uint64_t t = 0;
    std::vector<std::vector<uint8_t>> record_bytes; // up to L2 records
    std::vector<std::vector<uint8_t>> msg_hashes;   // each 32 bytes
    std::vector<uint8_t> h_t;                       // 32 bytes
    rsa_lvas::Signature sig_h;                      // issuer signs h_t
  };

  struct Staple {
    std::string issuer_id;
    uint64_t epoch = 0;
    uint64_t t = 0;
    std::vector<uint8_t> record_bytes;                   // the target record
    std::vector<std::vector<uint8_t>> block_record_bytes; // the whole block (<=L2)
    std::vector<uint8_t> aux_sig_bytes;                  // signature on h_t (opened from agg)
  };

  DirectoryLog_TS(rsa_lvas::Params params, size_t L1, size_t L2)
    : params_(params), L1_(L1), L2_(L2) {
    if (L1_ == 0 || L2_ == 0) throw std::runtime_error("L1 and L2 must be > 0");
  }

  void RegisterCA(const std::string& issuer_id, const rsa_lvas::PublicKey& pk) {
    ca_pk_[issuer_id] = pk;
  }

  // CA submits a whole signed block (signature is on h_t)
  void SubmitBlock(const std::string& issuer_id, uint64_t epoch, const Block& blk) {
    auto it = ca_pk_.find(issuer_id);
    if (it == ca_pk_.end()) throw std::runtime_error("SubmitBlock: unknown issuer");

    // sanity: recompute hash
    auto h2 = HashBlock(epoch, issuer_id, blk.t, blk.msg_hashes);
    if (h2 != blk.h_t) throw std::runtime_error("SubmitBlock: block hash mismatch");

    // verify signature on block hash
    bool ok = VerifyTimed(it->second, blk.h_t, blk.sig_h, params_, "verify.block_sig_submit");
    if (!ok) throw std::runtime_error("SubmitBlock: invalid block signature");

    pending_[issuer_id].push_back(blk);
  }

  void CloseEpoch(uint64_t epoch) {
    epoch_ = epoch;
    latest_.clear();

    for (auto& kv : pending_) {
      const std::string& issuer_id = kv.first;
      auto& blocks = kv.second;
      if (blocks.empty()) continue;

      EpochState es;
      es.epoch = epoch;

      // group blocks into superblocks of L1
      for (size_t i = 0; i < blocks.size(); i += L1_) {
        size_t end = std::min(blocks.size(), i + L1_);

        SuperBlock sb;
        sb.blocks.reserve(end - i);
        sb.h_list.reserve(end - i);

        std::vector<std::pair<std::vector<uint8_t>, rsa_lvas::Signature>> pairs;
        pairs.reserve(end - i);

        for (size_t k = i; k < end; k++) {
          sb.blocks.push_back(blocks[k]);
          sb.h_list.push_back(blocks[k].h_t);
          pairs.push_back({blocks[k].h_t, blocks[k].sig_h});
        }

        // Aggregate signatures on {h_t}
        const auto& pk = ca_pk_.at(issuer_id);
        rsa_lvas::Signature agg = AggregateTimed(pk, pairs, params_, "aggregate.superblock");
        sb.agg_sig_bytes = rsa_lvas::SerializeSignature(agg);

        // build index: each record hash -> (sb_idx, blk_idx_in_sb)
        size_t blk_local = 0;
        for (size_t k = i; k < end; k++, blk_local++) {
          for (const auto& m : blocks[k].msg_hashes) {
            es.index.emplace(hex_of(m), Loc{es.superblocks.size(), blk_local});
          }
        }

        es.superblocks.push_back(std::move(sb));
      }

      latest_[issuer_id] = std::move(es);
      blocks.clear();
    }

    pending_.clear();
  }

  uint64_t epoch() const { return epoch_; }

  // get stapling payload for the target record under issuer_id
  Staple GetStaple(const std::string& issuer_id, const std::vector<uint8_t>& record_bytes) const {
    auto itE = latest_.find(issuer_id);
    if (itE == latest_.end()) throw std::runtime_error("GetStaple: no epoch state for issuer");

    const EpochState& es = itE->second;
    std::vector<uint8_t> m = Sha256Timed(record_bytes, "sha256.lookup_record");
    auto it = es.index.find(hex_of(m));
    if (it == es.index.end()) throw std::runtime_error("GetStaple: record not found");

    const Loc loc = it->second;
    const SuperBlock& sb = es.superblocks.at(loc.sb_idx);
    const Block& blk = sb.blocks.at(loc.blk_idx);

    // find j where h_list[j] == blk.h_t
    size_t j = (size_t)-1;
    for (size_t x = 0; x < sb.h_list.size(); x++) {
      if (sb.h_list[x] == blk.h_t) { j = x; break; }
    }
    if (j == (size_t)-1) throw std::runtime_error("GetStaple: internal index error");

    // LocalOpen over messages = h_list
    const auto& pk = ca_pk_.at(issuer_id);
    rsa_lvas::Signature agg = rsa_lvas::DeserializeSignature(sb.agg_sig_bytes);
    rsa_lvas::Signature aux = LocalOpenTimed(pk, sb.h_list, agg, j, params_, "local_open.staple");
    auto aux_bytes = rsa_lvas::SerializeSignature(aux);

    Staple st;
    st.issuer_id = issuer_id;
    st.epoch = es.epoch;
    st.t = blk.t;
    st.record_bytes = record_bytes;
    st.block_record_bytes = blk.record_bytes;
    st.aux_sig_bytes = std::move(aux_bytes);
    return st;
  }

  // stats
  struct Stats {
    size_t num_blocks = 0;
    size_t num_superblocks = 0;
    size_t num_agg_sigs = 0; // == num_superblocks
  };

  Stats GetIssuerStats(const std::string& issuer_id) const {
    Stats s;
    auto it = latest_.find(issuer_id);
    if (it == latest_.end()) return s;
    const EpochState& es = it->second;
    s.num_superblocks = es.superblocks.size();
    s.num_agg_sigs = s.num_superblocks;
    for (const auto& sb : es.superblocks) s.num_blocks += sb.blocks.size();
    return s;
  }

private:
  struct SuperBlock {
    std::vector<uint8_t> agg_sig_bytes;
    std::vector<std::vector<uint8_t>> h_list; // block hashes in this superblock
    std::vector<Block> blocks;
  };
  struct Loc { size_t sb_idx; size_t blk_idx; };
  struct EpochState {
    uint64_t epoch = 0;
    std::unordered_map<std::string, Loc> index; // hex(m_record) -> location
    std::vector<SuperBlock> superblocks;
  };

  rsa_lvas::Params params_;
  size_t L1_;
  size_t L2_;
  uint64_t epoch_ = 1;

  std::unordered_map<std::string, rsa_lvas::PublicKey> ca_pk_;
  std::unordered_map<std::string, std::vector<Block>> pending_;
  std::unordered_map<std::string, EpochState> latest_;
};

// -------------------- CA builds blocks (size L2) and signs block hash --------------------
static std::vector<DirectoryLog_TS::Block>
BuildBlocksAndSign(const CA& issuer,
                   uint64_t epoch,
                   size_t L2,
                   const std::vector<std::vector<uint8_t>>& records_bytes,
                   const rsa_lvas::Params& params) {
  if (L2 == 0) throw std::runtime_error("L2 must be >0");

  std::vector<DirectoryLog_TS::Block> blocks;
  uint64_t t = 0;

  for (size_t i = 0; i < records_bytes.size(); i += L2, ++t) {
    size_t end = std::min(records_bytes.size(), i + L2);

    DirectoryLog_TS::Block blk;
    blk.t = t;
    blk.record_bytes.reserve(end - i);
    blk.msg_hashes.reserve(end - i);

    for (size_t k = i; k < end; k++) {
      blk.record_bytes.push_back(records_bytes[k]);
      blk.msg_hashes.push_back(Sha256Timed(records_bytes[k], "sha256.record_hash_build")); // 32 bytes
    }

    blk.h_t = HashBlock(epoch, issuer.id, blk.t, blk.msg_hashes);
    blk.sig_h = SignTimed(issuer.sk, blk.h_t, params, "sign.block_hash");
    blocks.push_back(std::move(blk));
  }

  return blocks;
}

// -------------------- Browser verification of one stapled record --------------------
static bool VerifyStapleRecord(const DirectoryLog_TS::Staple& st,
                               const rsa_lvas::PublicKey& issuer_pk,
                               const rsa_lvas::Params& params) {
  // membership: record_bytes must be inside block_record_bytes
  bool found = false;
  std::vector<std::vector<uint8_t>> msg_hashes;
  msg_hashes.reserve(st.block_record_bytes.size());

  for (const auto& rb : st.block_record_bytes) {
    if (rb == st.record_bytes) found = true;
    msg_hashes.push_back(Sha256Timed(rb, "sha256.record_hash_verify"));
  }
  if (!found) return false;

  // recompute h_t
  std::vector<uint8_t> h_t = HashBlock(st.epoch, st.issuer_id, st.t, msg_hashes);

  // verify aux as signature on h_t
  rsa_lvas::Signature aux = rsa_lvas::DeserializeSignature(st.aux_sig_bytes);
  return VerifyTimed(issuer_pk, h_t, aux, params, "verify.aux_sig");
}

// -------------------- CLI parsing --------------------
static uint64_t parse_u64(const std::string& s) {
  if (s.empty()) throw std::runtime_error("empty number");
  uint64_t x = 0;
  for (char c : s) {
    if (c < '0' || c > '9') throw std::runtime_error("invalid number: " + s);
    x = x * 10 + uint64_t(c - '0');
  }
  return x;
}

int main(int argc, char** argv) {
  // defaults
  uint64_t L1 = 4;
  uint64_t L2 = 8;
  uint64_t leaves_per_issuing = 200;

  for (int i = 1; i < argc; i++) {
    std::string a = argv[i];
    auto need = [&](const char* name) -> std::string {
      if (i + 1 >= argc) throw std::runtime_error(std::string("missing value for ") + name);
      return argv[++i];
    };
    if (a == "--l1") L1 = parse_u64(need("--l1"));
    else if (a == "--l2") L2 = parse_u64(need("--l2"));
    else if (a == "--leaves") leaves_per_issuing = parse_u64(need("--leaves"));
    else if (a == "--help" || a == "-h") {
      std::cout << "Usage: pki_demo_chain_ts --l1 <L1> --l2 <L2> [--leaves <N>]\n"
                   "  L1: blocks per superblock (Log stores ~O(#blocks/L1) agg sigs)\n"
                   "  L2: records per block (CA signs per block; client hashes O(L2) per verify)\n"
                   "  leaves: leaf records per issuing CA (default 200)\n";
      return 0;
    } else {
      throw std::runtime_error("unknown arg: " + a);
    }
  }

  if (L1 == 0 || L2 == 0) throw std::runtime_error("L1 and L2 must be > 0");

  rsa_lvas::Params params;
  params.rsa_bits = 2048;
  params.prime_bits = 256;
  PerfMonitor perf;
  g_perf = &perf;

  constexpr size_t NUM_INTER = 2;
  constexpr size_t NUM_ISS_PER_INTER = 5;
  constexpr uint64_t NB = 1700000000;
  constexpr uint64_t NA = 1900000000;
  const uint64_t epoch = 1;

  // ---------------- 1) Build CA keys ----------------
  CA root = MakeCA("RootCA", params);
  std::vector<CA> inters;
  for (size_t i = 0; i < NUM_INTER; i++) inters.push_back(MakeCA("InterCA" + std::to_string(i), params));

  std::vector<std::vector<CA>> issuing(NUM_INTER);
  for (size_t i = 0; i < NUM_INTER; i++) {
    for (size_t j = 0; j < NUM_ISS_PER_INTER; j++) {
      issuing[i].push_back(MakeCA("IssuingCA_" + std::to_string(i) + "_" + std::to_string(j), params));
    }
  }

  // ---------------- 2) Prepare records per issuer (NO per-record signatures!) ----------------
  // Root issues 2 CARecords (root->inter)
  std::vector<std::vector<uint8_t>> root_records;
  root_records.reserve(NUM_INTER);

  // Keep bytes for later selecting chain
  std::vector<std::vector<uint8_t>> bytes_root_to_inter(NUM_INTER);

  for (size_t i = 0; i < NUM_INTER; i++) {
    CARecord rec;
    rec.issuer_ca_id = root.id;
    rec.subject_ca_id = inters[i].id;
    rec.subject_pk_blob = rsa_lvas::SerializePublicKey(inters[i].pk);
    rec.not_before = NB;
    rec.not_after = NA;
    rec.path_len = 1;

    auto bytes = EncodeCARecord(rec);
    bytes_root_to_inter[i] = bytes;
    root_records.push_back(std::move(bytes));
  }

  // Each Inter issues 5 CARecords (inter->issuing)
  std::vector<std::vector<std::vector<uint8_t>>> inter_records(NUM_INTER);
  std::vector<std::vector<std::vector<uint8_t>>> bytes_inter_to_iss(NUM_INTER,
      std::vector<std::vector<uint8_t>>(NUM_ISS_PER_INTER));

  for (size_t i = 0; i < NUM_INTER; i++) {
    inter_records[i].reserve(NUM_ISS_PER_INTER);
    for (size_t j = 0; j < NUM_ISS_PER_INTER; j++) {
      CARecord rec;
      rec.issuer_ca_id = inters[i].id;
      rec.subject_ca_id = issuing[i][j].id;
      rec.subject_pk_blob = rsa_lvas::SerializePublicKey(issuing[i][j].pk);
      rec.not_before = NB;
      rec.not_after = NA;
      rec.path_len = 0;

      auto bytes = EncodeCARecord(rec);
      bytes_inter_to_iss[i][j] = bytes;
      inter_records[i].push_back(std::move(bytes));
    }
  }

  // Each Issuing issues many LeafRecords
  std::vector<std::vector<std::vector<std::vector<uint8_t>>>> issuing_records(NUM_INTER);
  issuing_records.assign(NUM_INTER, {});
  for (size_t i = 0; i < NUM_INTER; i++) {
    issuing_records[i].resize(NUM_ISS_PER_INTER);
    for (size_t j = 0; j < NUM_ISS_PER_INTER; j++) {
      issuing_records[i][j].reserve(leaves_per_issuing);
      for (size_t k = 0; k < leaves_per_issuing; k++) {
        pki_lvas::LeafRecord leaf;
        leaf.dns = "site-" + std::to_string(i) + "-" + std::to_string(j) + "-" + std::to_string(k) + ".example.com";
        leaf.issuer_ca_id = issuing[i][j].id;
        leaf.not_before = NB;
        leaf.not_after  = NA;
        leaf.ee_pubkey = {'e','e','-', (uint8_t)i, (uint8_t)j, (uint8_t)(k & 0xFF)};

        issuing_records[i][j].push_back(pki_lvas::EncodeLeafRecord(leaf));
      }
    }
  }

  // ---------------- 3) Log setup ----------------
  DirectoryLog_TS log(params, (size_t)L1, (size_t)L2);

  log.RegisterCA(root.id, root.pk);
  for (auto& ic : inters) log.RegisterCA(ic.id, ic.pk);
  for (size_t i = 0; i < NUM_INTER; i++) {
    for (size_t j = 0; j < NUM_ISS_PER_INTER; j++) {
      log.RegisterCA(issuing[i][j].id, issuing[i][j].pk);
    }
  }

  // ---------------- 4) Each issuer builds blocks, signs block-hash, submits blocks ----------------
  // Root
  {
    auto blocks = BuildBlocksAndSign(root, epoch, (size_t)L2, root_records, params);
    for (const auto& b : blocks) log.SubmitBlock(root.id, epoch, b);
  }

  // Inters
  for (size_t i = 0; i < NUM_INTER; i++) {
    auto blocks = BuildBlocksAndSign(inters[i], epoch, (size_t)L2, inter_records[i], params);
    for (const auto& b : blocks) log.SubmitBlock(inters[i].id, epoch, b);
  }

  // Issuing
  for (size_t i = 0; i < NUM_INTER; i++) {
    for (size_t j = 0; j < NUM_ISS_PER_INTER; j++) {
      auto blocks = BuildBlocksAndSign(issuing[i][j], epoch, (size_t)L2, issuing_records[i][j], params);
      for (const auto& b : blocks) log.SubmitBlock(issuing[i][j].id, epoch, b);
    }
  }

  // ---------------- 5) Close epoch => superblock aggregate signatures per issuer ----------------
  log.CloseEpoch(epoch);

  // ---------------- 6) Pick one target leaf, staple (3 pieces: root->inter, inter->iss, leaf) ----------------
  size_t pick_inter = 1;
  size_t pick_iss   = 3;
  size_t pick_leaf  = (size_t)std::min<uint64_t>(leaves_per_issuing - 1, 17);

  const std::vector<uint8_t>& bytes_r_i = bytes_root_to_inter[pick_inter];
  const std::vector<uint8_t>& bytes_i_s = bytes_inter_to_iss[pick_inter][pick_iss];
  const std::vector<uint8_t>& bytes_leaf = issuing_records[pick_inter][pick_iss][pick_leaf];

  DirectoryLog_TS::Staple st_r_i = log.GetStaple(root.id, bytes_r_i);
  DirectoryLog_TS::Staple st_i_s = log.GetStaple(inters[pick_inter].id, bytes_i_s);
  DirectoryLog_TS::Staple st_l   = log.GetStaple(issuing[pick_inter][pick_iss].id, bytes_leaf);

  // ---------------- 7) Browser verify chain ----------------
  // trust anchor = root.pk
  if (!VerifyStapleRecord(st_r_i, root.pk, params)) {
    std::cerr << "Verify failed: Root->Inter staple\n";
    perf.PrintSummary(std::cout);
    return 1;
  }
  CARecord parsed1 = DecodeCARecord(bytes_r_i);
  rsa_lvas::PublicKey inter_pk_from_record = rsa_lvas::DeserializePublicKey(parsed1.subject_pk_blob);

  if (!VerifyStapleRecord(st_i_s, inter_pk_from_record, params)) {
    std::cerr << "Verify failed: Inter->Issuing staple\n";
    perf.PrintSummary(std::cout);
    return 1;
  }
  CARecord parsed2 = DecodeCARecord(bytes_i_s);
  rsa_lvas::PublicKey issuing_pk_from_record = rsa_lvas::DeserializePublicKey(parsed2.subject_pk_blob);

  if (!VerifyStapleRecord(st_l, issuing_pk_from_record, params)) {
    std::cerr << "Verify failed: Issuing->Leaf staple\n";
    perf.PrintSummary(std::cout);
    return 1;
  }

  auto leaf_parsed = pki_lvas::DecodeLeafRecord(bytes_leaf);
  std::cout << "OK: verified leaf dns=" << leaf_parsed.dns
            << " under chain Root->Inter" << pick_inter
            << "->Issuing(" << pick_inter << "," << pick_iss << ")"
            << " with L1=" << L1 << " L2=" << L2 << "\n";

  // ---------------- 8) Print stats: show time-space benefits ----------------
  size_t total_records = 0;
  total_records += root_records.size();
  for (size_t i = 0; i < NUM_INTER; i++) total_records += inter_records[i].size();
  for (size_t i = 0; i < NUM_INTER; i++)
    for (size_t j = 0; j < NUM_ISS_PER_INTER; j++)
      total_records += issuing_records[i][j].size();

  // In this TS design, CA signs per BLOCK: about total_records / L2 signatures.
  size_t total_blocks = 0;
  size_t total_agg_sigs = 0;

  // root
  {
    auto s = log.GetIssuerStats(root.id);
    total_blocks += s.num_blocks;
    total_agg_sigs += s.num_agg_sigs;
  }
  // inters
  for (size_t i = 0; i < NUM_INTER; i++) {
    auto s = log.GetIssuerStats(inters[i].id);
    total_blocks += s.num_blocks;
    total_agg_sigs += s.num_agg_sigs;
  }
  // issuing
  for (size_t i = 0; i < NUM_INTER; i++) {
    for (size_t j = 0; j < NUM_ISS_PER_INTER; j++) {
      auto s = log.GetIssuerStats(issuing[i][j].id);
      total_blocks += s.num_blocks;
      total_agg_sigs += s.num_agg_sigs;
    }
  }

  const size_t num_cas = 1 + NUM_INTER + (NUM_INTER * NUM_ISS_PER_INTER);

  std::cout << "---- Stats ----\n";
  std::cout << "CAs: " << num_cas << " (root=1, inter=" << NUM_INTER
            << ", issuing=" << (NUM_INTER * NUM_ISS_PER_INTER) << ")\n";
  std::cout << "Total records (CARecord+LeafRecord): " << total_records << "\n";
  std::cout << "CA block signatures (one per block, ~ceil(records/L2)): " << total_blocks << "\n";
  std::cout << "Log aggregate signatures stored (one per superblock, ~ceil(blocks/L1)): " << total_agg_sigs << "\n";
  std::cout << "Rough scaling: blocks ~ N/L2, agg_sigs ~ N/(L1*L2) (per-CA, summed)\n";
  perf.PrintSummary(std::cout);

  return 0;
}
// ./build/pki_demo_chain_timespace --l1 4 --l2 8 --leaves 200
