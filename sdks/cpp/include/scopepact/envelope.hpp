#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace scopepact {

using Bytes = std::vector<std::uint8_t>;

/// Every field authenticated by a ScopePact v0 envelope signature.
struct Envelope {
  std::uint16_t protocol_major{};
  std::uint16_t protocol_minor{};
  Bytes session;
  std::optional<Bytes> interaction;
  std::uint64_t sequence{};
  Bytes nonce;
  std::int64_t issued_at_ms{};
  std::int64_t expires_at_ms{};
  Bytes sender;
  Bytes audience;
  std::uint64_t policy_epoch{};
  std::uint16_t message_kind{};
  Bytes payload_schema;
  Bytes payload_digest;
  std::vector<std::string> critical_extensions;
};

/// Produces the exact, domain-separated bytes signed by ScopePact v0.
[[nodiscard]] Bytes signing_transcript(const Envelope& envelope);

/// Signs an envelope with a 32-byte RFC 8032 Ed25519 private seed.
[[nodiscard]] Bytes sign(const Envelope& envelope,
                         std::span<const std::uint8_t> private_seed);

/// Verifies an envelope with a 32-byte RFC 8032 Ed25519 public key.
[[nodiscard]] bool verify(const Envelope& envelope,
                          std::span<const std::uint8_t> signature,
                          std::span<const std::uint8_t> public_key);

/// Derives the raw Ed25519 public key for a 32-byte private seed.
[[nodiscard]] Bytes public_key_from_seed(
    std::span<const std::uint8_t> private_seed);

/// Returns the SHA-256 identity bound to a raw Ed25519 public key.
[[nodiscard]] Bytes key_id(std::span<const std::uint8_t> public_key);

[[nodiscard]] Bytes decode_hex(std::string_view value,
                               std::size_t expected_size);
[[nodiscard]] std::string encode_hex(std::span<const std::uint8_t> value);

}  // namespace scopepact
