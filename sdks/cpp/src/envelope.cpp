#include "scopepact/envelope.hpp"

#include <openssl/evp.h>

#include <array>
#include <limits>
#include <memory>
#include <stdexcept>

namespace scopepact {
namespace {

constexpr std::string_view kEnvelopeDomain{"SCOPEPACT-ENVELOPE-V0\0", 22};
constexpr std::size_t kEd25519SeedSize = 32;
constexpr std::size_t kEd25519PublicKeySize = 32;
constexpr std::size_t kEd25519SignatureSize = 64;

using PKey = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using DigestContext = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;

void require_size(std::span<const std::uint8_t> value, std::size_t expected,
                  std::string_view field) {
  if (value.size() != expected) {
    throw std::invalid_argument(std::string(field) + " must contain " +
                                std::to_string(expected) + " bytes");
  }
}

void append_u16(Bytes& output, std::uint16_t value) {
  output.push_back(static_cast<std::uint8_t>(value >> 8));
  output.push_back(static_cast<std::uint8_t>(value));
}

void append_u32(Bytes& output, std::uint32_t value) {
  for (int shift = 24; shift >= 0; shift -= 8) {
    output.push_back(static_cast<std::uint8_t>(value >> shift));
  }
}

void append_u64(Bytes& output, std::uint64_t value) {
  for (int shift = 56; shift >= 0; shift -= 8) {
    output.push_back(static_cast<std::uint8_t>(value >> shift));
  }
}

void append_bytes(Bytes& output, std::span<const std::uint8_t> value) {
  if (value.size() > std::numeric_limits<std::uint32_t>::max()) {
    throw std::invalid_argument("length-prefixed field is too large");
  }
  append_u32(output, static_cast<std::uint32_t>(value.size()));
  output.insert(output.end(), value.begin(), value.end());
}

PKey private_key(std::span<const std::uint8_t> seed) {
  require_size(seed, kEd25519SeedSize, "private seed");
  auto* raw = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr,
                                            seed.data(), seed.size());
  if (raw == nullptr) {
    throw std::runtime_error("OpenSSL could not import the Ed25519 private seed");
  }
  return PKey(raw, EVP_PKEY_free);
}

PKey public_key(std::span<const std::uint8_t> encoded) {
  require_size(encoded, kEd25519PublicKeySize, "public key");
  auto* raw = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr,
                                           encoded.data(), encoded.size());
  if (raw == nullptr) {
    throw std::runtime_error("OpenSSL could not import the Ed25519 public key");
  }
  return PKey(raw, EVP_PKEY_free);
}

int hex_nibble(char value) {
  if (value >= '0' && value <= '9') return value - '0';
  if (value >= 'a' && value <= 'f') return value - 'a' + 10;
  return -1;
}

}  // namespace

Bytes signing_transcript(const Envelope& envelope) {
  require_size(envelope.session, 16, "session");
  if (envelope.interaction.has_value()) {
    require_size(*envelope.interaction, 16, "interaction");
  }
  require_size(envelope.nonce, 16, "nonce");
  require_size(envelope.sender, 32, "sender");
  require_size(envelope.audience, 32, "audience");
  require_size(envelope.payload_schema, 32, "payload schema");
  require_size(envelope.payload_digest, 32, "payload digest");
  if (envelope.critical_extensions.size() >
      std::numeric_limits<std::uint32_t>::max()) {
    throw std::invalid_argument("too many critical extensions");
  }

  Bytes output(kEnvelopeDomain.begin(), kEnvelopeDomain.end());
  append_u16(output, envelope.protocol_major);
  append_u16(output, envelope.protocol_minor);
  append_bytes(output, envelope.session);
  if (envelope.interaction.has_value()) {
    output.push_back(1);
    append_bytes(output, *envelope.interaction);
  } else {
    output.push_back(0);
  }
  append_u64(output, envelope.sequence);
  append_bytes(output, envelope.nonce);
  append_u64(output, static_cast<std::uint64_t>(envelope.issued_at_ms));
  append_u64(output, static_cast<std::uint64_t>(envelope.expires_at_ms));
  append_bytes(output, envelope.sender);
  append_bytes(output, envelope.audience);
  append_u64(output, envelope.policy_epoch);
  append_u16(output, envelope.message_kind);
  append_bytes(output, envelope.payload_schema);
  append_bytes(output, envelope.payload_digest);
  append_u32(output,
             static_cast<std::uint32_t>(envelope.critical_extensions.size()));
  for (const auto& extension : envelope.critical_extensions) {
    append_bytes(output, std::span(
                             reinterpret_cast<const std::uint8_t*>(extension.data()),
                             extension.size()));
  }
  return output;
}

Bytes sign(const Envelope& envelope,
           std::span<const std::uint8_t> private_seed) {
  auto key = private_key(private_seed);
  auto transcript = signing_transcript(envelope);
  DigestContext context(EVP_MD_CTX_new(), EVP_MD_CTX_free);
  if (!context || EVP_DigestSignInit(context.get(), nullptr, nullptr, nullptr,
                                     key.get()) != 1) {
    throw std::runtime_error("OpenSSL could not initialize Ed25519 signing");
  }
  Bytes signature(kEd25519SignatureSize);
  std::size_t signature_size = signature.size();
  if (EVP_DigestSign(context.get(), signature.data(), &signature_size,
                     transcript.data(), transcript.size()) != 1 ||
      signature_size != kEd25519SignatureSize) {
    throw std::runtime_error("OpenSSL Ed25519 signing failed");
  }
  return signature;
}

bool verify(const Envelope& envelope, std::span<const std::uint8_t> signature,
            std::span<const std::uint8_t> encoded_public_key) {
  if (signature.size() != kEd25519SignatureSize) return false;
  auto key = public_key(encoded_public_key);
  auto transcript = signing_transcript(envelope);
  DigestContext context(EVP_MD_CTX_new(), EVP_MD_CTX_free);
  if (!context || EVP_DigestVerifyInit(context.get(), nullptr, nullptr, nullptr,
                                       key.get()) != 1) {
    throw std::runtime_error("OpenSSL could not initialize Ed25519 verification");
  }
  const int result = EVP_DigestVerify(context.get(), signature.data(),
                                      signature.size(), transcript.data(),
                                      transcript.size());
  if (result < 0) {
    throw std::runtime_error("OpenSSL Ed25519 verification failed");
  }
  return result == 1;
}

Bytes public_key_from_seed(std::span<const std::uint8_t> private_seed) {
  auto key = private_key(private_seed);
  Bytes output(kEd25519PublicKeySize);
  std::size_t output_size = output.size();
  if (EVP_PKEY_get_raw_public_key(key.get(), output.data(), &output_size) != 1 ||
      output_size != kEd25519PublicKeySize) {
    throw std::runtime_error("OpenSSL could not derive the Ed25519 public key");
  }
  return output;
}

Bytes key_id(std::span<const std::uint8_t> encoded_public_key) {
  require_size(encoded_public_key, kEd25519PublicKeySize, "public key");
  Bytes output(EVP_MAX_MD_SIZE);
  unsigned int output_size = 0;
  if (EVP_Digest(encoded_public_key.data(), encoded_public_key.size(),
                 output.data(), &output_size, EVP_sha256(), nullptr) != 1 ||
      output_size != 32) {
    throw std::runtime_error("OpenSSL SHA-256 failed");
  }
  output.resize(output_size);
  return output;
}

Bytes decode_hex(std::string_view value, std::size_t expected_size) {
  if (value.size() != expected_size * 2) {
    throw std::invalid_argument("hexadecimal value has the wrong length");
  }
  Bytes output;
  output.reserve(expected_size);
  for (std::size_t index = 0; index < value.size(); index += 2) {
    const int high = hex_nibble(value[index]);
    const int low = hex_nibble(value[index + 1]);
    if (high < 0 || low < 0) {
      throw std::invalid_argument("hexadecimal value must use lowercase ASCII");
    }
    output.push_back(static_cast<std::uint8_t>((high << 4) | low));
  }
  return output;
}

std::string encode_hex(std::span<const std::uint8_t> value) {
  constexpr std::string_view digits = "0123456789abcdef";
  std::string output;
  output.reserve(value.size() * 2);
  for (const auto byte : value) {
    output.push_back(digits[byte >> 4]);
    output.push_back(digits[byte & 0x0f]);
  }
  return output;
}

}  // namespace scopepact
