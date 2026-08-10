import CryptoKit
import Foundation

public enum ScopePactError: Error, Equatable {
    case invalidField(String)
    case integerOutOfRange(String)
}

/// The fields authenticated by a ScopePact v0 envelope signature.
public struct ScopePactEnvelope: Sendable {
    public let protocolMajor: UInt16
    public let protocolMinor: UInt16
    public let session: Data
    public let interaction: Data?
    public let sequence: UInt64
    public let nonce: Data
    public let issuedAtMilliseconds: Int64
    public let expiresAtMilliseconds: Int64
    public let sender: Data
    public let audience: Data
    public let policyEpoch: UInt64
    public let messageKind: UInt16
    public let payloadSchema: Data
    public let payloadDigest: Data
    public let criticalExtensions: [String]

    public init(
        protocolMajor: UInt16,
        protocolMinor: UInt16,
        session: Data,
        interaction: Data?,
        sequence: UInt64,
        nonce: Data,
        issuedAtMilliseconds: Int64,
        expiresAtMilliseconds: Int64,
        sender: Data,
        audience: Data,
        policyEpoch: UInt64,
        messageKind: UInt16,
        payloadSchema: Data,
        payloadDigest: Data,
        criticalExtensions: [String] = []
    ) {
        self.protocolMajor = protocolMajor
        self.protocolMinor = protocolMinor
        self.session = session
        self.interaction = interaction
        self.sequence = sequence
        self.nonce = nonce
        self.issuedAtMilliseconds = issuedAtMilliseconds
        self.expiresAtMilliseconds = expiresAtMilliseconds
        self.sender = sender
        self.audience = audience
        self.policyEpoch = policyEpoch
        self.messageKind = messageKind
        self.payloadSchema = payloadSchema
        self.payloadDigest = payloadDigest
        self.criticalExtensions = criticalExtensions
    }

    /// Produces the exact, domain-separated bytes signed by ScopePact v0.
    public func signingTranscript() throws -> Data {
        try require(session, count: 16, field: "session")
        if let interaction {
            try require(interaction, count: 16, field: "interaction")
        }
        try require(nonce, count: 16, field: "nonce")
        try require(sender, count: 32, field: "sender")
        try require(audience, count: 32, field: "audience")
        try require(payloadSchema, count: 32, field: "payloadSchema")
        try require(payloadDigest, count: 32, field: "payloadDigest")
        guard criticalExtensions.count <= Int(UInt32.max) else {
            throw ScopePactError.integerOutOfRange("criticalExtensions")
        }

        var output = Data("SCOPEPACT-ENVELOPE-V0\0".utf8)
        output.appendInteger(protocolMajor)
        output.appendInteger(protocolMinor)
        try output.appendLengthPrefixed(session)
        if let interaction {
            output.append(1)
            try output.appendLengthPrefixed(interaction)
        } else {
            output.append(0)
        }
        output.appendInteger(sequence)
        try output.appendLengthPrefixed(nonce)
        output.appendInteger(UInt64(bitPattern: issuedAtMilliseconds))
        output.appendInteger(UInt64(bitPattern: expiresAtMilliseconds))
        try output.appendLengthPrefixed(sender)
        try output.appendLengthPrefixed(audience)
        output.appendInteger(policyEpoch)
        output.appendInteger(messageKind)
        try output.appendLengthPrefixed(payloadSchema)
        try output.appendLengthPrefixed(payloadDigest)
        output.appendInteger(UInt32(criticalExtensions.count))
        for value in criticalExtensions {
            try output.appendLengthPrefixed(Data(value.utf8))
        }
        return output
    }
}

public enum ScopePactCrypto {
    public static func privateKey(seed: Data) throws -> Curve25519.Signing.PrivateKey {
        try Curve25519.Signing.PrivateKey(rawRepresentation: seed)
    }

    public static func keyID(_ publicKey: Curve25519.Signing.PublicKey) -> Data {
        Data(SHA256.hash(data: publicKey.rawRepresentation))
    }

    public static func sign(
        _ envelope: ScopePactEnvelope,
        with privateKey: Curve25519.Signing.PrivateKey
    ) throws -> Data {
        try privateKey.signature(for: envelope.signingTranscript())
    }

    public static func verify(
        _ envelope: ScopePactEnvelope,
        signature: Data,
        publicKey: Curve25519.Signing.PublicKey
    ) throws -> Bool {
        publicKey.isValidSignature(signature, for: try envelope.signingTranscript())
    }
}

private func require(_ data: Data, count: Int, field: String) throws {
    guard data.count == count else {
        throw ScopePactError.invalidField("\(field) must contain \(count) bytes")
    }
}

private extension Data {
    mutating func appendInteger<T: FixedWidthInteger>(_ value: T) {
        var bigEndian = value.bigEndian
        Swift.withUnsafeBytes(of: &bigEndian) { append(contentsOf: $0) }
    }

    mutating func appendLengthPrefixed(_ value: Data) throws {
        guard value.count <= Int(UInt32.max) else {
            throw ScopePactError.integerOutOfRange("length-prefixed field")
        }
        appendInteger(UInt32(value.count))
        append(value)
    }
}
