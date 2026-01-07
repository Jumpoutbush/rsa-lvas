#pragma once

#include "rsa_lvas.h"
#include "pki_lvas.h"

#include <cstdint>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace pki_timespace {

// ---- Block hash: h_t = SHA256( epoch || ca_id || t || concat(msg_hashes) ) ----
std::vector<uint8_t> HashBlock(uint64_t epoch,
                               const std::string& ca_id,
                               uint64_t t,
                               const std::vector<std::vector<uint8_t>>& msg_hashes);

// ---- CA: issues leaf records, then forms blocks and signs block-hashes ----
class IssuerCA_TS {
public:
  IssuerCA_TS(std::string ca_id, const rsa_lvas::Params& params);

  const std::string& id() const { return ca_id_; }
  const rsa_lvas::PublicKey& public_key() const { return pk_; }
  const rsa_lvas::SecretKey& secret_key() const { return sk_; }

  struct LeafItem {
    pki_lvas::LeafRecord record;
    std::vector<uint8_t> record_bytes;
    std::vector<uint8_t> m; // SHA256(record_bytes), 32 bytes
  };

  LeafItem IssueLeaf(const std::string& dns,
                     const std::vector<uint8_t>& ee_pubkey,
                     uint64_t not_before,
                     uint64_t not_after) const;

  struct SignedBlock {
    uint64_t t = 0;
    std::vector<std::vector<uint8_t>> record_bytes;   // size L2
    std::vector<std::vector<uint8_t>> msg_hashes;     // size L2, each 32 bytes
    std::vector<uint8_t> h_t;                         // 32 bytes
    rsa_lvas::Signature sig_h;                        // Sign(h_t)
  };

  // Deterministically chunk items into blocks of L2, compute h_t, sign it.
  std::vector<SignedBlock> BuildAndSignBlocks(const std::vector<LeafItem>& items,
                                              uint64_t epoch,
                                              size_t L2) const;

private:
  std::string ca_id_;
  rsa_lvas::Params params_;
  rsa_lvas::PublicKey pk_;
  rsa_lvas::SecretKey sk_;
};

// ---- Log: groups blocks into super-blocks of L1 and aggregates signatures ----
class DirectoryLog_TS {
public:
  DirectoryLog_TS(rsa_lvas::Params params, size_t L1, size_t L2);

  void RegisterCA(const std::string& ca_id, const rsa_lvas::PublicKey& pk);

  // Submit CA-signed blocks for an epoch (streaming or batch).
  void SubmitBlock(const std::string& ca_id,
                   uint64_t epoch,
                   const IssuerCA_TS::SignedBlock& blk);

  // Close epoch: for each CA, group blocks into super-blocks of L1 and store aggregate signature per super-block.
  void CloseEpoch(uint64_t epoch);

  uint64_t current_epoch() const { return epoch_; }
  size_t L1() const { return L1_; }
  size_t L2() const { return L2_; }

  // Query by leaf record bytes (or by message hash if you prefer). Returns stapling payload:
  // - leaf record bytes
  // - full block records bytes (L2)
  // - aux (signature on block hash h_t)
  struct Staple {
    std::string ca_id;
    uint64_t epoch = 0;
    uint64_t t = 0;                    // block index
    std::vector<uint8_t> leaf_record_bytes;
    std::vector<std::vector<uint8_t>> block_record_bytes; // size L2
    std::vector<uint8_t> aux_sig_bytes; // SerializeSignature(aux)
  };

  Staple GetStapleLatest(const std::string& ca_id,
                         const std::vector<uint8_t>& leaf_record_bytes) const;

  // Stats
  size_t StoredAggregateSigCount(const std::string& ca_id) const;

private:
  struct SuperBlockState {
    uint64_t s = 0;
    std::vector<uint8_t> agg_sig_bytes;                // serialized aggregate signature Σ_s (mod N element)
    std::vector<std::vector<uint8_t>> h_list;          // messages for LVAS = {h_t} of this super-block
    std::vector<IssuerCA_TS::SignedBlock> blocks;       // L1 blocks (each contains L2 records)
    mutable std::unordered_map<std::string, std::vector<uint8_t>> aux_cache; // Hex(h_t) -> serialized aux
  };

  struct EpochState {
    uint64_t epoch = 0;
    // message index: Hex(m_leaf) -> (superblock idx, block idx within superblock)
    struct Loc { size_t sb_idx; size_t blk_idx; };
    std::unordered_map<std::string, Loc> leaf_index;

    // super-block list for this CA+epoch
    std::vector<SuperBlockState> superblocks;
  };

  // helper: compute aux for given superblock + target h_t
  std::vector<uint8_t> OpenBlockHashAux(const std::string& ca_id,
                                        const SuperBlockState& sb,
                                        const std::vector<uint8_t>& target_h) const;

  rsa_lvas::Params params_;
  size_t L1_;
  size_t L2_;
  uint64_t epoch_ = 0;

  std::unordered_map<std::string, rsa_lvas::PublicKey> ca_pk_;

  // pending blocks before CloseEpoch
  std::unordered_map<std::string, std::vector<IssuerCA_TS::SignedBlock>> pending_blocks_;

  // latest closed epoch per CA
  std::unordered_map<std::string, EpochState> latest_;
};

// ---- Browser: verify stapled payload ----
class Browser_TS {
public:
  void AddTrustedCA(const std::string& ca_id, const rsa_lvas::PublicKey& pk);

  bool VerifyStaple(const DirectoryLog_TS::Staple& st,
                    const rsa_lvas::Params& params,
                    const std::string& expected_dns) const;

private:
  std::unordered_map<std::string, rsa_lvas::PublicKey> trusted_;
};

} // namespace pki_timespace
