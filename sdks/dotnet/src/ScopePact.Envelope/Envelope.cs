using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using NSec.Cryptography;

namespace ScopePact;

/// <summary>Every field authenticated by a ScopePact v0 signature.</summary>
public sealed record Envelope(
    ushort ProtocolMajor,
    ushort ProtocolMinor,
    byte[] Session,
    byte[]? Interaction,
    ulong Sequence,
    byte[] Nonce,
    long IssuedAtMilliseconds,
    long ExpiresAtMilliseconds,
    byte[] Sender,
    byte[] Audience,
    ulong PolicyEpoch,
    ushort MessageKind,
    byte[] PayloadSchema,
    byte[] PayloadDigest,
    IReadOnlyList<string> CriticalExtensions)
{
    private static readonly byte[] Domain =
        Encoding.ASCII.GetBytes("SCOPEPACT-ENVELOPE-V0\0");

    /// <summary>Produces the exact domain-separated bytes signed by v0.</summary>
    public byte[] SigningTranscript()
    {
        RequireLength(Session, 16, nameof(Session));
        if (Interaction is not null)
        {
            RequireLength(Interaction, 16, nameof(Interaction));
        }
        RequireLength(Nonce, 16, nameof(Nonce));
        RequireLength(Sender, 32, nameof(Sender));
        RequireLength(Audience, 32, nameof(Audience));
        RequireLength(PayloadSchema, 32, nameof(PayloadSchema));
        RequireLength(PayloadDigest, 32, nameof(PayloadDigest));

        using var output = new MemoryStream();
        output.Write(Domain);
        WriteUInt16(output, ProtocolMajor);
        WriteUInt16(output, ProtocolMinor);
        WriteBytes(output, Session);
        if (Interaction is null)
        {
            output.WriteByte(0);
        }
        else
        {
            output.WriteByte(1);
            WriteBytes(output, Interaction);
        }
        WriteUInt64(output, Sequence);
        WriteBytes(output, Nonce);
        WriteUInt64(output, unchecked((ulong)IssuedAtMilliseconds));
        WriteUInt64(output, unchecked((ulong)ExpiresAtMilliseconds));
        WriteBytes(output, Sender);
        WriteBytes(output, Audience);
        WriteUInt64(output, PolicyEpoch);
        WriteUInt16(output, MessageKind);
        WriteBytes(output, PayloadSchema);
        WriteBytes(output, PayloadDigest);
        WriteUInt32(output, checked((uint)CriticalExtensions.Count));
        foreach (var extension in CriticalExtensions)
        {
            WriteBytes(output, Encoding.UTF8.GetBytes(extension));
        }
        return output.ToArray();
    }

    private static void RequireLength(byte[] value, int expected, string field)
    {
        ArgumentNullException.ThrowIfNull(value);
        if (value.Length != expected)
        {
            throw new ArgumentException($"{field} must contain {expected} bytes", field);
        }
    }

    private static void WriteBytes(Stream output, ReadOnlySpan<byte> value)
    {
        WriteUInt32(output, checked((uint)value.Length));
        output.Write(value);
    }

    private static void WriteUInt16(Stream output, ushort value)
    {
        Span<byte> encoded = stackalloc byte[sizeof(ushort)];
        BinaryPrimitives.WriteUInt16BigEndian(encoded, value);
        output.Write(encoded);
    }

    private static void WriteUInt32(Stream output, uint value)
    {
        Span<byte> encoded = stackalloc byte[sizeof(uint)];
        BinaryPrimitives.WriteUInt32BigEndian(encoded, value);
        output.Write(encoded);
    }

    private static void WriteUInt64(Stream output, ulong value)
    {
        Span<byte> encoded = stackalloc byte[sizeof(ulong)];
        BinaryPrimitives.WriteUInt64BigEndian(encoded, value);
        output.Write(encoded);
    }
}

/// <summary>Ed25519 helpers for the portable envelope profile.</summary>
public static class EnvelopeCrypto
{
    private static readonly SignatureAlgorithm Algorithm = SignatureAlgorithm.Ed25519;

    public static byte[] Sign(Envelope envelope, ReadOnlySpan<byte> privateSeed)
    {
        ArgumentNullException.ThrowIfNull(envelope);
        RequireLength(privateSeed, 32, nameof(privateSeed));
        using var key = Key.Import(Algorithm, privateSeed, KeyBlobFormat.RawPrivateKey);
        return Algorithm.Sign(key, envelope.SigningTranscript());
    }

    public static bool Verify(
        Envelope envelope,
        ReadOnlySpan<byte> signature,
        ReadOnlySpan<byte> publicKey)
    {
        ArgumentNullException.ThrowIfNull(envelope);
        RequireLength(publicKey, 32, nameof(publicKey));
        if (signature.Length != Algorithm.SignatureSize)
        {
            return false;
        }
        var imported = PublicKey.Import(Algorithm, publicKey, KeyBlobFormat.RawPublicKey);
        return Algorithm.Verify(imported, envelope.SigningTranscript(), signature);
    }

    public static byte[] PublicKeyFromSeed(ReadOnlySpan<byte> privateSeed)
    {
        RequireLength(privateSeed, 32, nameof(privateSeed));
        using var key = Key.Import(Algorithm, privateSeed, KeyBlobFormat.RawPrivateKey);
        return key.PublicKey.Export(KeyBlobFormat.RawPublicKey);
    }

    public static byte[] KeyId(ReadOnlySpan<byte> publicKey)
    {
        RequireLength(publicKey, 32, nameof(publicKey));
        return SHA256.HashData(publicKey);
    }

    private static void RequireLength(ReadOnlySpan<byte> value, int expected, string field)
    {
        if (value.Length != expected)
        {
            throw new ArgumentException($"{field} must contain {expected} bytes", field);
        }
    }
}
