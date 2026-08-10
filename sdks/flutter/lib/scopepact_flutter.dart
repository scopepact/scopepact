library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

const _envelopeDomain = 'SCOPEPACT-ENVELOPE-V0\u0000';

/// The fields authenticated by a ScopePact v0 envelope signature.
final class ScopePactEnvelope {
  ScopePactEnvelope({
    required this.protocolMajor,
    required this.protocolMinor,
    required this.session,
    required this.interaction,
    required this.sequence,
    required this.nonce,
    required this.issuedAtMs,
    required this.expiresAtMs,
    required this.sender,
    required this.audience,
    required this.policyEpoch,
    required this.messageKind,
    required this.payloadSchema,
    required this.payloadDigest,
    this.criticalExtensions = const [],
  });

  factory ScopePactEnvelope.fromJson(Map<String, Object?> json) {
    return ScopePactEnvelope(
      protocolMajor: json['protocol_major']! as int,
      protocolMinor: json['protocol_minor']! as int,
      session: _decodeHex(json['session']! as String, 16),
      interaction: switch (json['interaction']) {
        final String value => _decodeHex(value, 16),
        null => null,
        _ => throw const FormatException(
            'interaction must be hexadecimal or null'),
      },
      sequence: BigInt.from(json['sequence']! as int),
      nonce: _decodeHex(json['nonce']! as String, 16),
      issuedAtMs: BigInt.from(json['issued_at_ms']! as int),
      expiresAtMs: BigInt.from(json['expires_at_ms']! as int),
      sender: _decodeHex(json['sender']! as String, 32),
      audience: _decodeHex(json['audience']! as String, 32),
      policyEpoch: BigInt.from(json['policy_epoch']! as int),
      messageKind: json['message_kind']! as int,
      payloadSchema: _decodeHex(json['payload_schema']! as String, 32),
      payloadDigest: _decodeHex(json['payload_digest']! as String, 32),
      criticalExtensions: List<String>.unmodifiable(
        (json['critical_extensions']! as List<Object?>).cast<String>(),
      ),
    );
  }

  final int protocolMajor;
  final int protocolMinor;
  final Uint8List session;
  final Uint8List? interaction;
  final BigInt sequence;
  final Uint8List nonce;
  final BigInt issuedAtMs;
  final BigInt expiresAtMs;
  final Uint8List sender;
  final Uint8List audience;
  final BigInt policyEpoch;
  final int messageKind;
  final Uint8List payloadSchema;
  final Uint8List payloadDigest;
  final List<String> criticalExtensions;

  /// Produces the exact, domain-separated bytes signed by ScopePact v0.
  Uint8List signingTranscript() {
    _requireUnsigned(protocolMajor, 16, 'protocolMajor');
    _requireUnsigned(protocolMinor, 16, 'protocolMinor');
    _requireUnsigned(messageKind, 16, 'messageKind');
    _requireLength(session, 16, 'session');
    if (interaction case final value?) _requireLength(value, 16, 'interaction');
    _requireLength(nonce, 16, 'nonce');
    _requireLength(sender, 32, 'sender');
    _requireLength(audience, 32, 'audience');
    _requireLength(payloadSchema, 32, 'payloadSchema');
    _requireLength(payloadDigest, 32, 'payloadDigest');

    final output = BytesBuilder(copy: false)
      ..add(ascii.encode(_envelopeDomain))
      ..add(_integer(BigInt.from(protocolMajor), 2))
      ..add(_integer(BigInt.from(protocolMinor), 2))
      ..add(_lengthPrefixed(session));
    if (interaction case final value?) {
      output
        ..addByte(1)
        ..add(_lengthPrefixed(value));
    } else {
      output.addByte(0);
    }
    output
      ..add(_integer(sequence, 8))
      ..add(_lengthPrefixed(nonce))
      ..add(_integer(issuedAtMs, 8, signed: true))
      ..add(_integer(expiresAtMs, 8, signed: true))
      ..add(_lengthPrefixed(sender))
      ..add(_lengthPrefixed(audience))
      ..add(_integer(policyEpoch, 8))
      ..add(_integer(BigInt.from(messageKind), 2))
      ..add(_lengthPrefixed(payloadSchema))
      ..add(_lengthPrefixed(payloadDigest))
      ..add(_integer(BigInt.from(criticalExtensions.length), 4));
    for (final extension in criticalExtensions) {
      output.add(_lengthPrefixed(utf8.encode(extension)));
    }
    return output.takeBytes();
  }
}

/// Ed25519 helpers for the portable envelope profile.
final class ScopePactCrypto {
  ScopePactCrypto({Ed25519? ed25519, Sha256? sha256})
      : _ed25519 = ed25519 ?? Ed25519(),
        _sha256 = sha256 ?? Sha256();

  final Ed25519 _ed25519;
  final Sha256 _sha256;

  Future<SimpleKeyPair> keyPairFromSeed(List<int> seed) {
    _requireLength(seed, 32, 'seed');
    return _ed25519.newKeyPairFromSeed(seed);
  }

  Future<Uint8List> keyId(SimplePublicKey publicKey) async {
    final digest = await _sha256.hash(publicKey.bytes);
    return Uint8List.fromList(digest.bytes);
  }

  Future<Uint8List> sign(
    ScopePactEnvelope envelope,
    SimpleKeyPair keyPair,
  ) async {
    final signature = await _ed25519.sign(
      envelope.signingTranscript(),
      keyPair: keyPair,
    );
    return Uint8List.fromList(signature.bytes);
  }

  Future<bool> verify(
    ScopePactEnvelope envelope, {
    required List<int> signature,
    required SimplePublicKey publicKey,
  }) {
    return _ed25519.verify(
      envelope.signingTranscript(),
      signature: Signature(signature, publicKey: publicKey),
    );
  }
}

Uint8List _decodeHex(String value, int expectedBytes) {
  if (value.length != expectedBytes * 2 ||
      !RegExp(r'^[0-9a-f]+$').hasMatch(value)) {
    throw FormatException(
        'expected $expectedBytes-byte lowercase hexadecimal value');
  }
  return Uint8List.fromList([
    for (var index = 0; index < value.length; index += 2)
      int.parse(value.substring(index, index + 2), radix: 16),
  ]);
}

Uint8List _lengthPrefixed(List<int> value) {
  return Uint8List.fromList([
    ..._integer(BigInt.from(value.length), 4),
    ...value,
  ]);
}

Uint8List _integer(BigInt value, int width, {bool signed = false}) {
  final bits = width * 8;
  final modulus = BigInt.one << bits;
  final minimum = signed ? -(BigInt.one << (bits - 1)) : BigInt.zero;
  final maximum =
      signed ? (BigInt.one << (bits - 1)) - BigInt.one : modulus - BigInt.one;
  if (value < minimum || value > maximum) {
    throw RangeError(
        '$value does not fit in ${signed ? 'signed' : 'unsigned'} $bits-bit integer');
  }
  var encoded = value.isNegative ? modulus + value : value;
  final output = Uint8List(width);
  for (var index = width - 1; index >= 0; index -= 1) {
    output[index] = (encoded & BigInt.from(0xff)).toInt();
    encoded >>= 8;
  }
  return output;
}

void _requireLength(List<int> value, int expected, String field) {
  if (value.length != expected) {
    throw ArgumentError.value(
        value.length, field, 'must contain $expected bytes');
  }
}

void _requireUnsigned(int value, int bits, String field) {
  if (value < 0 || BigInt.from(value) >= (BigInt.one << bits)) {
    throw ArgumentError.value(
        value, field, 'must fit an unsigned $bits-bit integer');
  }
}
