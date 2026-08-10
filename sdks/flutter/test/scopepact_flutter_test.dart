import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:scopepact_flutter/scopepact_flutter.dart';

void main() {
  final vector = jsonDecode(
    File('../../conformance/vectors/envelope-v0.json').readAsStringSync(),
  ) as Map<String, Object?>;
  final frame = vector['frame']! as Map<String, Object?>;
  final envelope = ScopePactEnvelope.fromJson(
    frame['envelope']! as Map<String, Object?>,
  );
  final crypto = ScopePactCrypto();

  test('matches the shared ScopePact v0 transcript', () {
    expect(_hex(envelope.signingTranscript()), vector['transcript_hex']);
  });

  test('matches and verifies the shared Ed25519 signature', () async {
    final keyPair = await crypto.keyPairFromSeed(
      _bytes(vector['sender_seed_hex']! as String),
    );
    final publicKey = await keyPair.extractPublicKey();
    expect(_hex(publicKey.bytes), vector['sender_public_key_hex']);

    final signature = await crypto.sign(envelope, keyPair);
    expect(_hex(signature), frame['signature']);
    expect(
      await crypto.verify(
        envelope,
        signature: signature,
        publicKey: publicKey,
      ),
      isTrue,
    );
  });

  test('rejects a signature after an authenticated field changes', () async {
    final publicKey = SimplePublicKey(
      _bytes(vector['sender_public_key_hex']! as String),
      type: KeyPairType.ed25519,
    );
    final altered = ScopePactEnvelope.fromJson({
      ...(frame['envelope']! as Map<String, Object?>),
      'policy_epoch': 8,
    });
    expect(
      await crypto.verify(
        altered,
        signature: _bytes(frame['signature']! as String),
        publicKey: publicKey,
      ),
      isFalse,
    );
  });
}

Uint8List _bytes(String value) => Uint8List.fromList([
      for (var index = 0; index < value.length; index += 2)
        int.parse(value.substring(index, index + 2), radix: 16),
    ]);

String _hex(List<int> value) =>
    value.map((byte) => byte.toRadixString(16).padLeft(2, '0')).join();
