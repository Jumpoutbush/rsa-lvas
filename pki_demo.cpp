#include "pki_lvas.h"

#include <iostream>
#include <vector>

int main() {
  rsa_lvas::Params params;
  params.rsa_bits = 2048;
  params.prime_bits = 256;

  // 1) Issuer CA
  pki_lvas::IssuerCA ca("CA1", params);

  // 2) Directory log (register CA)
  pki_lvas::DirectoryLog log(params);
  log.RegisterCA(ca.id(), ca.public_key());

  // 3) CA issues a leaf "cert record"
  std::vector<uint8_t> ee_pubkey = {'d','e','m','o','-','p','k'};
  auto issued = ca.IssueLeaf("example.com", ee_pubkey, /*nb=*/1700000000, /*na=*/1900000000);

  // 4) CA submits signed record hash to log
  log.SubmitRecord(ca.id(), issued.m, issued.sig);

  // 5) close epoch => log aggregates and forgets individual signatures
  log.CloseEpoch();

  // 6) Web server staples aux for its record
  pki_lvas::WebServer server(ca.id(), issued.record, issued.record_bytes);
  server.RefreshStaple(log);
  auto hs = server.MakeHandshakePayload();

  // 7) Browser trusts CA pk (in real PKI: would be via root chain)
  pki_lvas::Browser br;
  br.AddTrustedCA(ca.id(), ca.public_key());

  bool ok = br.VerifyHandshake(hs, params, "example.com");
  std::cout << "PKI handshake verify ok? " << (ok ? "YES" : "NO") << "\n";

  return ok ? 0 : 1;
}
