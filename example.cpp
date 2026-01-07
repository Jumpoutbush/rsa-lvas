#include "rsa_lvas.h"
#include <chrono>
#include <iostream>
#include <string>
#include <vector>

int main() {
  auto now = []() { return std::chrono::steady_clock::now(); };
  auto us = [](std::chrono::steady_clock::duration d) {
    return std::chrono::duration_cast<std::chrono::microseconds>(d).count();
  };

  rsa_lvas::Params params;
  params.rsa_bits = 2048;
  params.prime_bits = 256;

  auto t0 = now();
  auto [pk, sk] = rsa_lvas::KeyGen(params);
  std::cout << "KeyGen time(us): " << us(now() - t0) << "\n";

  std::vector<std::vector<uint8_t>> msgs = {
    std::vector<uint8_t>{'c','e','r','t','-','1'},
    std::vector<uint8_t>{'c','e','r','t','-','2'},
    std::vector<uint8_t>{'c','e','r','t','-','3'},
  };

  // Sign individually
  std::vector<rsa_lvas::Signature> sigs;
  for (auto& m : msgs) {
    auto ts = now();
    sigs.emplace_back(rsa_lvas::Sign(sk, rsa_lvas::View(m), params));
    std::cout << "Sign time(us): " << us(now() - ts) << "\n";
  }

  // Verify individually
  for (size_t i = 0; i < msgs.size(); i++) {
    auto tv = now();
    bool ok = rsa_lvas::Verify(pk, rsa_lvas::View(msgs[i]), sigs[i], params);
    std::cout << "sig[" << i << "] ok? " << (ok ? "YES" : "NO") << "\n";
    std::cout << "Verify " << i << " time(us): " << us(now() - tv) << "\n";
  }

  // Aggregate
  std::vector<std::pair<std::vector<uint8_t>, rsa_lvas::Signature>> pairs;
  for (size_t i = 0; i < msgs.size(); i++) {
    // move signature into pair
    pairs.push_back({msgs[i], std::move(sigs[i])});
  }
  auto ta = now();
  rsa_lvas::Signature agg = rsa_lvas::Aggregate(pk, pairs, params);
  std::cout << "Aggregate time(us): " << us(now() - ta) << "\n";

  // AggVerify
  auto tav = now();
  bool agg_ok = rsa_lvas::AggVerify(pk, msgs, agg, params);
  std::cout << "agg ok? " << (agg_ok ? "YES" : "NO") << "\n";
  std::cout << "AggVerify time(us): " << us(now() - tav) << "\n";

  // LocalOpen for j=1
  size_t j = 0;
  auto tlo = now();
  rsa_lvas::Signature aux = rsa_lvas::LocalOpen(pk, msgs, agg, j, params);
  std::cout << "LocalOpen time(us): " << us(now() - tlo) << "\n";

  // RSA-LVAS local verify: just Verify(msg_j, aux)
  auto tlv = now();
  bool local_ok = rsa_lvas::LocalAggVerify(pk, rsa_lvas::View(msgs[j]), aux, params);
  std::cout << "local ok? " << (local_ok ? "YES" : "NO") << "\n";
  std::cout << "LocalAggVerify time(us): " << us(now() - tlv) << "\n";

  // Serialize/deserialize pk and aux
  auto tsp = now();
  auto pk_blob = rsa_lvas::SerializePublicKey(pk);
  auto pk2 = rsa_lvas::DeserializePublicKey(pk_blob);
  std::cout << "Serialize+Deserialize pk time(us): " << us(now() - tsp) << "\n";

  auto tss = now();
  auto aux_blob = rsa_lvas::SerializeSignature(aux);
  auto aux2 = rsa_lvas::DeserializeSignature(aux_blob);
  std::cout << "Serialize+Deserialize sig time(us): " << us(now() - tss) << "\n";

  auto tlv2 = now();
  bool local_ok2 = rsa_lvas::LocalAggVerify(pk2, rsa_lvas::View(msgs[j]), aux2, params);
  std::cout << "local ok after serialize? " << (local_ok2 ? "YES" : "NO") << "\n";
  std::cout << "LocalAggVerify(after serialize) time(us): " << us(now() - tlv2) << "\n";

  return 0;
}
