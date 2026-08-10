#include "scopepact/envelope.hpp"

#include <nlohmann/json.hpp>

#include <fstream>
#include <iostream>
#include <stdexcept>

namespace {

using Json = nlohmann::json;

void require(bool condition, std::string_view message) {
  if (!condition) throw std::runtime_error(std::string(message));
}

scopepact::Envelope parse_envelope(const Json& value) {
  const auto interaction = value.at("interaction");
  return scopepact::Envelope{
      .protocol_major = value.at("protocol_major").get<std::uint16_t>(),
      .protocol_minor = value.at("protocol_minor").get<std::uint16_t>(),
      .session = scopepact::decode_hex(value.at("session").get<std::string>(), 16),
      .interaction = interaction.is_null()
                         ? std::nullopt
                         : std::optional(scopepact::decode_hex(
                               interaction.get<std::string>(), 16)),
      .sequence = value.at("sequence").get<std::uint64_t>(),
      .nonce = scopepact::decode_hex(value.at("nonce").get<std::string>(), 16),
      .issued_at_ms = value.at("issued_at_ms").get<std::int64_t>(),
      .expires_at_ms = value.at("expires_at_ms").get<std::int64_t>(),
      .sender = scopepact::decode_hex(value.at("sender").get<std::string>(), 32),
      .audience = scopepact::decode_hex(value.at("audience").get<std::string>(), 32),
      .policy_epoch = value.at("policy_epoch").get<std::uint64_t>(),
      .message_kind = value.at("message_kind").get<std::uint16_t>(),
      .payload_schema = scopepact::decode_hex(
          value.at("payload_schema").get<std::string>(), 32),
      .payload_digest = scopepact::decode_hex(
          value.at("payload_digest").get<std::string>(), 32),
      .critical_extensions =
          value.at("critical_extensions").get<std::vector<std::string>>(),
  };
}

}  // namespace

int main() {
  try {
    std::ifstream input(SCOPEPACT_VECTOR_PATH);
    require(input.good(), "could not open the shared vector");
    const Json vector = Json::parse(input);
    const Json frame = vector.at("frame");
    auto envelope = parse_envelope(frame.at("envelope"));

    require(scopepact::encode_hex(scopepact::signing_transcript(envelope)) ==
                vector.at("transcript_hex").get<std::string>(),
            "C++ transcript did not match the shared vector");

    const auto seed = scopepact::decode_hex(
        vector.at("sender_seed_hex").get<std::string>(), 32);
    const auto public_key = scopepact::public_key_from_seed(seed);
    require(scopepact::encode_hex(public_key) ==
                vector.at("sender_public_key_hex").get<std::string>(),
            "C++ public key did not match the shared vector");

    const auto signature = scopepact::sign(envelope, seed);
    require(scopepact::encode_hex(signature) ==
                frame.at("signature").get<std::string>(),
            "C++ signature did not match the shared vector");
    require(scopepact::verify(envelope, signature, public_key),
            "C++ did not verify the shared signature");

    envelope.policy_epoch += 1;
    require(!scopepact::verify(envelope, signature, public_key),
            "C++ accepted a signature after an authenticated mutation");
    std::cout << "ScopePact C++ shared vector passed\n";
    return 0;
  } catch (const std::exception& error) {
    std::cerr << error.what() << '\n';
    return 1;
  }
}
