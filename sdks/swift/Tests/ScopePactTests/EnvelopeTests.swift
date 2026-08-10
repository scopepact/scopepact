import CryptoKit
import Foundation
import Testing

@testable import ScopePact

struct EnvelopeTests {
    private let vector: [String: Any]
    private let frame: [String: Any]
    private let envelope: ScopePactEnvelope

    init() throws {
        let vectorURL = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .appendingPathComponent("conformance/vectors/envelope-v0.json")
        vector = try #require(
            JSONSerialization.jsonObject(with: Data(contentsOf: vectorURL)) as? [String: Any]
        )
        frame = try #require(vector["frame"] as? [String: Any])
        let raw = try #require(frame["envelope"] as? [String: Any])
        envelope = ScopePactEnvelope(
            protocolMajor: UInt16(try number(raw, "protocol_major")),
            protocolMinor: UInt16(try number(raw, "protocol_minor")),
            session: try requiredData(raw, "session"),
            interaction: try optionalData(raw, "interaction"),
            sequence: try number(raw, "sequence"),
            nonce: try requiredData(raw, "nonce"),
            issuedAtMilliseconds: Int64(try number(raw, "issued_at_ms")),
            expiresAtMilliseconds: Int64(try number(raw, "expires_at_ms")),
            sender: try requiredData(raw, "sender"),
            audience: try requiredData(raw, "audience"),
            policyEpoch: try number(raw, "policy_epoch"),
            messageKind: UInt16(try number(raw, "message_kind")),
            payloadSchema: try requiredData(raw, "payload_schema"),
            payloadDigest: try requiredData(raw, "payload_digest"),
            criticalExtensions: try #require(raw["critical_extensions"] as? [String])
        )
    }

    @Test func sharedTranscriptMatches() throws {
        #expect(try envelope.signingTranscript().hex == vector["transcript_hex"] as? String)
    }

    @Test func sharedSignatureVerifiesAndLocalSigningWorks() throws {
        let seed = try Data(hex: #require(vector["sender_seed_hex"] as? String))
        let privateKey = try ScopePactCrypto.privateKey(seed: seed)
        #expect(privateKey.publicKey.rawRepresentation.hex == vector["sender_public_key_hex"] as? String)

        let sharedSignature = try Data(hex: #require(frame["signature"] as? String))
        #expect(
            try ScopePactCrypto.verify(
                envelope,
                signature: sharedSignature,
                publicKey: privateKey.publicKey
            )
        )

        // CryptoKit randomizes Ed25519 signatures. Interoperability depends on
        // verification of the transcript, not byte-for-byte signature equality.
        let localSignature = try ScopePactCrypto.sign(envelope, with: privateKey)
        #expect(localSignature.count == 64)
        #expect(
            try ScopePactCrypto.verify(
                envelope,
                signature: localSignature,
                publicKey: privateKey.publicKey
            )
        )
    }

    @Test func authenticatedFieldChangeIsRejected() throws {
        let signature = try Data(hex: #require(frame["signature"] as? String))
        let publicKey = try Curve25519.Signing.PublicKey(
            rawRepresentation: Data(hex: #require(vector["sender_public_key_hex"] as? String))
        )
        let altered = ScopePactEnvelope(
            protocolMajor: envelope.protocolMajor,
            protocolMinor: envelope.protocolMinor,
            session: envelope.session,
            interaction: envelope.interaction,
            sequence: envelope.sequence,
            nonce: envelope.nonce,
            issuedAtMilliseconds: envelope.issuedAtMilliseconds,
            expiresAtMilliseconds: envelope.expiresAtMilliseconds,
            sender: envelope.sender,
            audience: envelope.audience,
            policyEpoch: 8,
            messageKind: envelope.messageKind,
            payloadSchema: envelope.payloadSchema,
            payloadDigest: envelope.payloadDigest
        )
        #expect(try !ScopePactCrypto.verify(altered, signature: signature, publicKey: publicKey))
    }
}

private func number(_ source: [String: Any], _ key: String) throws -> UInt64 {
    try #require(source[key] as? NSNumber).uint64Value
}

private func requiredData(_ source: [String: Any], _ key: String) throws -> Data {
    try Data(hex: #require(source[key] as? String))
}

private func optionalData(_ source: [String: Any], _ key: String) throws -> Data? {
    guard let value = source[key] else { return nil }
    guard !(value is NSNull) else { return nil }
    return try Data(hex: #require(value as? String))
}

private extension Data {
    init(hex: String) throws {
        guard hex.count.isMultiple(of: 2), hex.allSatisfy(\.isHexDigit) else {
            throw ScopePactError.invalidField("malformed hexadecimal value")
        }
        self.init()
        reserveCapacity(hex.count / 2)
        var index = hex.startIndex
        while index < hex.endIndex {
            let end = hex.index(index, offsetBy: 2)
            guard let byte = UInt8(hex[index..<end], radix: 16) else {
                throw ScopePactError.invalidField("malformed hexadecimal value")
            }
            append(byte)
            index = end
        }
    }

    var hex: String { map { String(format: "%02x", $0) }.joined() }
}
