#pragma once

#include "rsa_lvas.h"

#include <cstdint>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace pki_lvas {

// ---------- helpers ----------
std::vector<uint8_t> Sha256(const std::vector<uint8_t>& data);
std::string Hex(const std::vector<uint8_t>& bytes);

// ---------- records (very small, deterministic TLV-ish encoding) ----------
struct LeafRecord {
  std::string dns;                 // e.g. "example.com"
  std::string issuer_ca_id;        // e.g. "CA1"
  uint64_t not_before = 0;         // unix seconds
  uint64_t not_after = 0;          // unix seconds
  std::vector<uint8_t> ee_pubkey;  // demo bytes
};

std::vector<uint8_t> EncodeLeafRecord(const LeafRecord& r);
LeafRecord DecodeLeafRecord(const std::vector<uint8_t>& bytes);

// ---------- Issuer CA ----------
class IssuerCA {
public:
  IssuerCA(std::string ca_id, const rsa_lvas::Params& params);

  const std::string& id() const { return ca_id_; }
  const rsa_lvas::PublicKey& public_key() const { return pk_; }
  const rsa_lvas::SecretKey& secret_key() const { return sk_; }

  // issue a leaf record, sign m = SHA256(record_bytes)
  struct Issued {
    LeafRecord record;
    std::vector<uint8_t> record_bytes;
    std::vector<uint8_t> m;            // 32 bytes
    rsa_lvas::Signature sig;           // signature on m
  };

  Issued IssueLeaf(const std::string& dns,
                   const std::vector<uint8_t>& ee_pubkey,
                   uint64_t not_before,
                   uint64_t not_after) const;

private:
  std::string ca_id_;
  rsa_lvas::Params params_;
  rsa_lvas::PublicKey pk_;
  rsa_lvas::SecretKey sk_;
};

// ---------- Directory / Log (per-CA single-signer aggregation) ----------
class DirectoryLog {
public:
  explicit DirectoryLog(rsa_lvas::Params params);

  void RegisterCA(const std::string& ca_id, const rsa_lvas::PublicKey& pk);

  // Collect a signed record into current epoch (keeps individual sigs only until CloseEpoch()).
  void SubmitRecord(const std::string& ca_id,
                    const std::vector<uint8_t>& m,
                    const rsa_lvas::Signature& sig);

  // Aggregate all pending records into one aggregate signature per CA for this epoch,
  // then forget individual signatures (keeps only message list + aggregate sig).
  void CloseEpoch();

  uint64_t current_epoch() const { return epoch_; }

  // Returns aux for m (aux acts as "individual signature" in RSA-LVAS).
  // Uses the latest closed epoch state for that CA.
  rsa_lvas::Signature GetAuxLatest(const std::string& ca_id,
                                  const std::vector<uint8_t>& m) const;

  // Expose latest epoch aggregate signature (optional for debugging/audit)
  const rsa_lvas::Signature& LatestAggSig(const std::string& ca_id) const;

  const rsa_lvas::PublicKey& GetCAPublicKey(const std::string& ca_id) const;

private:
  struct Pending {
    std::vector<std::vector<uint8_t>> messages;  // m_i
    std::vector<rsa_lvas::Signature> sigs;       // sig_i
  };

  struct EpochState {
    uint64_t epoch = 0;
    rsa_lvas::Signature agg_sig;
    std::vector<std::vector<uint8_t>> messages;   // stable order
    std::unordered_map<std::string, size_t> idx;  // Hex(m) -> index in messages
    mutable std::unordered_map<std::string, rsa_lvas::Signature> aux_cache; // Hex(m) -> aux
  };

  rsa_lvas::Params params_;
  uint64_t epoch_ = 0;

  std::unordered_map<std::string, rsa_lvas::PublicKey> ca_pk_;
  std::unordered_map<std::string, Pending> pending_;

  // latest closed epoch per CA
  std::unordered_map<std::string, EpochState> latest_;
};

// ---------- WebServer (stapling) ----------
class WebServer {
public:
  WebServer(std::string ca_id,
            LeafRecord record,
            std::vector<uint8_t> record_bytes);

  // ask log for aux and cache it
  void RefreshStaple(const DirectoryLog& log);

  struct HandshakePayload {
    std::string ca_id;
    std::vector<uint8_t> record_bytes;
    std::vector<uint8_t> aux_sig_bytes; // serialized signature (rsa_lvas::SerializeSignature)
    uint64_t epoch = 0;
  };

  HandshakePayload MakeHandshakePayload() const;

private:
  std::string ca_id_;
  LeafRecord record_;
  std::vector<uint8_t> record_bytes_;
  std::vector<uint8_t> m_; // SHA256(record_bytes)
  rsa_lvas::Signature aux_;
  uint64_t epoch_ = 0;
};

// ---------- Browser (verifier) ----------
class Browser {
public:
  // In a real PKI, browser would learn CA pk via root chain / CAR; here we assume known.
  void AddTrustedCA(const std::string& ca_id, const rsa_lvas::PublicKey& pk);

  bool VerifyHandshake(const WebServer::HandshakePayload& hs,
                       const rsa_lvas::Params& params,
                       std::string expected_dns) const;

private:
  std::unordered_map<std::string, rsa_lvas::PublicKey> trusted_ca_;
};

} // namespace pki_lvas
