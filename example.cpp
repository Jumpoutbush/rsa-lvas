#include "rsa_lvas.h"
#include <iostream>
#include <string>
#include <vector>

int main() {
  rsa_lvas::Params params;
  params.rsa_bits = 2048;
  params.prime_bits = 256;

  auto [pk, sk] = rsa_lvas::KeyGen(params);

  std::vector<std::vector<uint8_t>> msgs = {
    std::vector<uint8_t>{'c','e','r','t','-','1'},
    std::vector<uint8_t>{'y','y','c','y','e','s'},
    std::vector<uint8_t>{'c','e','r','t','-','2'},
    std::vector<uint8_t>{'c','e','r','t','-','3'},
  };

  // Sign individually
  std::vector<rsa_lvas::Signature> sigs;
  for (auto& m : msgs) {
    sigs.emplace_back(rsa_lvas::Sign(sk, rsa_lvas::View(m), params));
  }

  // Verify individually
  for (size_t i = 0; i < msgs.size(); i++) {
    bool ok = rsa_lvas::Verify(pk, rsa_lvas::View(msgs[i]), sigs[i], params);
    std::cout << "sig[" << i << "] ok? " << (ok ? "YES" : "NO") << "\n";
  }

  // Aggregate
  std::vector<std::pair<std::vector<uint8_t>, rsa_lvas::Signature>> pairs;
  for (size_t i = 0; i < msgs.size(); i++) {
    // move signature into pair
    pairs.push_back({msgs[i], std::move(sigs[i])});
  }
  rsa_lvas::Signature agg = rsa_lvas::Aggregate(pk, pairs, params);

  // AggVerify
  bool agg_ok = rsa_lvas::AggVerify(pk, msgs, agg, params);
  std::cout << "agg ok? " << (agg_ok ? "YES" : "NO") << "\n";

  // LocalOpen for j=1
  size_t j = 1;
  rsa_lvas::Signature aux = rsa_lvas::LocalOpen(pk, msgs, agg, j, params);

  // RSA-LVAS local verify: just Verify(msg_j, aux)
  bool local_ok = rsa_lvas::LocalAggVerify(pk, rsa_lvas::View(msgs[j]), aux, params);
  std::cout << "local ok? " << (local_ok ? "YES" : "NO") << "\n";

  // Serialize/deserialize pk and aux
  auto pk_blob = rsa_lvas::SerializePublicKey(pk);
  auto pk2 = rsa_lvas::DeserializePublicKey(pk_blob);

  auto aux_blob = rsa_lvas::SerializeSignature(aux);
  auto aux2 = rsa_lvas::DeserializeSignature(aux_blob);

  bool local_ok2 = rsa_lvas::LocalAggVerify(pk2, rsa_lvas::View(msgs[j]), aux2, params);
  std::cout << "local ok after serialize? " << (local_ok2 ? "YES" : "NO") << "\n";

  return 0;
}
