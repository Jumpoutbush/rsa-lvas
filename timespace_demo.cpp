#include "pki_timespace.h"

#include <chrono>
#include <iomanip>
#include <iostream>
#include <string>
#include <vector>

using Clock = std::chrono::steady_clock;

static void print_ms(const std::string& name, Clock::time_point a, Clock::time_point b) {
  auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(b - a).count();
  std::cout << std::left << std::setw(28) << name << ms << " ms\n";
}

int main() {
  rsa_lvas::Params params;
  params.rsa_bits = 2048;
  params.prime_bits = 256;

  // ---- tradeoff parameters ----
  const size_t L2 = 8;  // records per block (client work ~ O(L2))
  const size_t L1 = 4;  // blocks per superblock (log open cost ~ O(L1))
  const uint64_t epoch = 1;

  const size_t N = 64;        // number of leaf records
  const size_t target = 13;   // pick a leaf to verify

  std::cout << "N=" << N << " L2=" << L2 << " L1=" << L1 << "\n";

  // ---- CA ----
  auto t0 = Clock::now();
  pki_timespace::IssuerCA_TS ca("CA1", params);
  auto t1 = Clock::now();
  print_ms("KeyGen(CA)", t0, t1);

  // Issue N leaf records
  std::vector<pki_timespace::IssuerCA_TS::LeafItem> items;
  items.reserve(N);

  t0 = Clock::now();
  for (size_t i = 0; i < N; i++) {
    std::string dns = "site" + std::to_string(i) + ".example.com";
    std::vector<uint8_t> ee_pk = {'p','k', (uint8_t)(i & 0xFF)};
    items.push_back(ca.IssueLeaf(dns, ee_pk, 1700000000, 1900000000));
  }
  t1 = Clock::now();
  print_ms("IssueLeaf(N)", t0, t1);

  // Build blocks and sign block hashes (1 signature per L2 records)
  t0 = Clock::now();
  auto blocks = ca.BuildAndSignBlocks(items, epoch, L2);
  t1 = Clock::now();
  print_ms("Build+SignBlocks", t0, t1);

  const size_t num_blocks = blocks.size();
  const size_t num_superblocks = (num_blocks + L1 - 1) / L1;
  std::cout << "num_blocks=" << num_blocks
            << " num_superblocks=" << num_superblocks
            << " (store ~ O(num_blocks/L1) agg sigs)\n";

  // ---- Log ----
  pki_timespace::DirectoryLog_TS log(params, L1, L2);
  log.RegisterCA(ca.id(), ca.public_key());

  t0 = Clock::now();
  for (const auto& b : blocks) log.SubmitBlock(ca.id(), epoch, b);
  t1 = Clock::now();
  print_ms("SubmitBlocks(Log)", t0, t1);

  t0 = Clock::now();
  log.CloseEpoch(epoch);
  t1 = Clock::now();
  print_ms("CloseEpoch+Aggregate", t0, t1);

  std::cout << "Stored agg signatures: " << log.StoredAggregateSigCount(ca.id()) << "\n";

  // ---- Stapling for target leaf ----
  auto leaf_bytes = items[target].record_bytes;

  t0 = Clock::now();
  auto staple = log.GetStapleLatest(ca.id(), leaf_bytes);
  t1 = Clock::now();
  print_ms("GetStapleLatest", t0, t1);

  // ---- Browser verify ----
  pki_timespace::Browser_TS br;
  br.AddTrustedCA(ca.id(), ca.public_key());

  std::string expected_dns = items[target].record.dns;

  t0 = Clock::now();
  bool ok = br.VerifyStaple(staple, params, expected_dns);
  t1 = Clock::now();
  print_ms("BrowserVerifyStaple", t0, t1);

  std::cout << "verify ok? " << (ok ? "YES" : "NO") << "\n";
  return ok ? 0 : 1;
}
