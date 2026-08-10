using System.Text.Json;
using System.Text.Json.Serialization;
using ScopePact;

var vectorPath = Path.Combine(AppContext.BaseDirectory, "envelope-v0.json");
var vector = JsonSerializer.Deserialize<SharedVector>(File.ReadAllText(vectorPath))
    ?? throw new InvalidOperationException("Could not parse the shared vector");
var raw = vector.Frame.Envelope;
var envelope = new Envelope(
    raw.ProtocolMajor,
    raw.ProtocolMinor,
    Convert.FromHexString(raw.Session),
    raw.Interaction is null ? null : Convert.FromHexString(raw.Interaction),
    raw.Sequence,
    Convert.FromHexString(raw.Nonce),
    raw.IssuedAtMilliseconds,
    raw.ExpiresAtMilliseconds,
    Convert.FromHexString(raw.Sender),
    Convert.FromHexString(raw.Audience),
    raw.PolicyEpoch,
    raw.MessageKind,
    Convert.FromHexString(raw.PayloadSchema),
    Convert.FromHexString(raw.PayloadDigest),
    raw.CriticalExtensions);

Require(
    Convert.ToHexString(envelope.SigningTranscript()).ToLowerInvariant() == vector.TranscriptHex,
    "C# transcript did not match the shared vector");

var seed = Convert.FromHexString(vector.SenderSeedHex);
var publicKey = EnvelopeCrypto.PublicKeyFromSeed(seed);
Require(
    Convert.ToHexString(publicKey).ToLowerInvariant() == vector.SenderPublicKeyHex,
    "C# public key did not match the shared vector");

var signature = EnvelopeCrypto.Sign(envelope, seed);
Require(
    Convert.ToHexString(signature).ToLowerInvariant() == vector.Frame.Signature,
    "C# signature did not match the shared vector");
Require(
    EnvelopeCrypto.Verify(envelope, signature, publicKey),
    "C# did not verify the shared signature");

var altered = envelope with { PolicyEpoch = envelope.PolicyEpoch + 1 };
Require(
    !EnvelopeCrypto.Verify(altered, signature, publicKey),
    "C# accepted a signature after an authenticated mutation");

Console.WriteLine("ScopePact C# shared vector passed");

static void Require(bool condition, string message)
{
    if (!condition)
    {
        throw new InvalidOperationException(message);
    }
}

internal sealed record SharedVector(
    [property: JsonPropertyName("sender_seed_hex")] string SenderSeedHex,
    [property: JsonPropertyName("sender_public_key_hex")] string SenderPublicKeyHex,
    [property: JsonPropertyName("transcript_hex")] string TranscriptHex,
    [property: JsonPropertyName("frame")] SharedFrame Frame);

internal sealed record SharedFrame(
    [property: JsonPropertyName("envelope")] RawEnvelope Envelope,
    [property: JsonPropertyName("signature")] string Signature);

internal sealed record RawEnvelope(
    [property: JsonPropertyName("protocol_major")] ushort ProtocolMajor,
    [property: JsonPropertyName("protocol_minor")] ushort ProtocolMinor,
    [property: JsonPropertyName("session")] string Session,
    [property: JsonPropertyName("interaction")] string? Interaction,
    [property: JsonPropertyName("sequence")] ulong Sequence,
    [property: JsonPropertyName("nonce")] string Nonce,
    [property: JsonPropertyName("issued_at_ms")] long IssuedAtMilliseconds,
    [property: JsonPropertyName("expires_at_ms")] long ExpiresAtMilliseconds,
    [property: JsonPropertyName("sender")] string Sender,
    [property: JsonPropertyName("audience")] string Audience,
    [property: JsonPropertyName("policy_epoch")] ulong PolicyEpoch,
    [property: JsonPropertyName("message_kind")] ushort MessageKind,
    [property: JsonPropertyName("payload_schema")] string PayloadSchema,
    [property: JsonPropertyName("payload_digest")] string PayloadDigest,
    [property: JsonPropertyName("critical_extensions")] string[] CriticalExtensions);
