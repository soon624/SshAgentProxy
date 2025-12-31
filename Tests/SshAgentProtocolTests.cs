using System.Buffers.Binary;
using SshAgentProxy.Protocol;

namespace SshAgentProxy.Tests;

public class SshAgentProtocolTests
{
    #region ParseSignRequest Tests

    [Fact]
    public void ParseSignRequest_ValidPayload_ReturnsCorrectValues()
    {
        // Arrange: Create a valid sign request payload
        var keyBlob = new byte[] { 0x01, 0x02, 0x03, 0x04 };
        var data = new byte[] { 0x10, 0x20, 0x30 };
        uint flags = 0x02;
        var payload = CreateSignRequestPayload(keyBlob, data, flags);

        // Act
        var (resultKeyBlob, resultData, resultFlags) = SshAgentProtocol.ParseSignRequest(payload);

        // Assert
        Assert.Equal(keyBlob, resultKeyBlob);
        Assert.Equal(data, resultData);
        Assert.Equal(flags, resultFlags);
    }

    [Fact]
    public void ParseSignRequest_WithoutFlags_ReturnsZeroFlags()
    {
        // Arrange: Create payload without flags
        var keyBlob = new byte[] { 0x01, 0x02 };
        var data = new byte[] { 0x10 };
        var payload = CreateSignRequestPayload(keyBlob, data, includeFlags: false);

        // Act
        var (_, _, resultFlags) = SshAgentProtocol.ParseSignRequest(payload);

        // Assert
        Assert.Equal(0u, resultFlags);
    }

    [Fact]
    public void ParseSignRequest_EmptyPayload_ThrowsInvalidDataException()
    {
        // Arrange
        var payload = ReadOnlyMemory<byte>.Empty;

        // Act & Assert
        Assert.Throws<InvalidDataException>(() => SshAgentProtocol.ParseSignRequest(payload));
    }

    [Fact]
    public void ParseSignRequest_TruncatedKeyBlobLength_ThrowsInvalidDataException()
    {
        // Arrange: Only 2 bytes (needs 4 for length)
        var payload = new byte[] { 0x00, 0x00 };

        // Act & Assert
        Assert.Throws<InvalidDataException>(() => SshAgentProtocol.ParseSignRequest(payload));
    }

    [Fact]
    public void ParseSignRequest_KeyBlobLengthExceedsPayload_ThrowsInvalidDataException()
    {
        // Arrange: keyBlobLen = 100, but payload is too short
        var payload = new byte[8];
        BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(0), 100); // keyBlobLen = 100

        // Act & Assert
        Assert.Throws<InvalidDataException>(() => SshAgentProtocol.ParseSignRequest(payload));
    }

    [Fact]
    public void ParseSignRequest_DataLengthExceedsPayload_ThrowsInvalidDataException()
    {
        // Arrange: Valid keyBlob, but dataLen exceeds remaining payload
        var keyBlob = new byte[] { 0x01 };
        using var ms = new MemoryStream();
        using var writer = new BinaryWriter(ms);
        WriteUInt32BE(writer, 1); // keyBlobLen
        writer.Write(keyBlob);
        WriteUInt32BE(writer, 1000); // dataLen = 1000 (way too big)
        var payload = ms.ToArray();

        // Act & Assert
        Assert.Throws<InvalidDataException>(() => SshAgentProtocol.ParseSignRequest(payload));
    }

    #endregion

    #region ParseIdentitiesAnswer Tests

    [Fact]
    public void ParseIdentitiesAnswer_ValidPayload_ReturnsIdentities()
    {
        // Arrange
        var identities = new[]
        {
            (KeyBlob: new byte[] { 0x01, 0x02, 0x03 }, Comment: "key1"),
            (KeyBlob: new byte[] { 0x04, 0x05 }, Comment: "key2"),
        };
        var payload = CreateIdentitiesAnswerPayload(identities);

        // Act
        var result = SshAgentProtocol.ParseIdentitiesAnswer(payload);

        // Assert
        Assert.Equal(2, result.Count);
        Assert.Equal(identities[0].KeyBlob, result[0].PublicKeyBlob);
        Assert.Equal(identities[0].Comment, result[0].Comment);
        Assert.Equal(identities[1].KeyBlob, result[1].PublicKeyBlob);
        Assert.Equal(identities[1].Comment, result[1].Comment);
    }

    [Fact]
    public void ParseIdentitiesAnswer_EmptyList_ReturnsEmptyList()
    {
        // Arrange
        var payload = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(payload, 0); // count = 0

        // Act
        var result = SshAgentProtocol.ParseIdentitiesAnswer(payload);

        // Assert
        Assert.Empty(result);
    }

    [Fact]
    public void ParseIdentitiesAnswer_EmptyPayload_ThrowsInvalidDataException()
    {
        // Arrange
        var payload = ReadOnlyMemory<byte>.Empty;

        // Act & Assert
        Assert.Throws<InvalidDataException>(() => SshAgentProtocol.ParseIdentitiesAnswer(payload));
    }

    [Fact]
    public void ParseIdentitiesAnswer_TooShortForCount_ThrowsInvalidDataException()
    {
        // Arrange: Only 2 bytes (needs 4 for count)
        var payload = new byte[] { 0x00, 0x00 };

        // Act & Assert
        Assert.Throws<InvalidDataException>(() => SshAgentProtocol.ParseIdentitiesAnswer(payload));
    }

    [Fact]
    public void ParseIdentitiesAnswer_CountExceedsLimit_ThrowsInvalidDataException()
    {
        // Arrange: count = 1001 (exceeds limit of 1000)
        var payload = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(payload, 1001);

        // Act & Assert
        var ex = Assert.Throws<InvalidDataException>(() => SshAgentProtocol.ParseIdentitiesAnswer(payload));
        Assert.Contains("exceeds limit", ex.Message);
    }

    [Fact]
    public void ParseIdentitiesAnswer_TruncatedIdentity_ThrowsInvalidDataException()
    {
        // Arrange: count = 1, but no identity data
        var payload = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(payload, 1); // count = 1

        // Act & Assert
        Assert.Throws<InvalidDataException>(() => SshAgentProtocol.ParseIdentitiesAnswer(payload));
    }

    #endregion

    #region CreateIdentitiesAnswer Tests

    [Fact]
    public void CreateIdentitiesAnswer_ValidIdentities_CreatesValidPayload()
    {
        // Arrange
        var identities = new List<SshIdentity>
        {
            new(new byte[] { 0x01, 0x02, 0x03 }, "test-key"),
        };

        // Act
        var payload = SshAgentProtocol.CreateIdentitiesAnswer(identities);

        // Assert: Parse it back to verify
        var parsed = SshAgentProtocol.ParseIdentitiesAnswer(payload);
        Assert.Single(parsed);
        Assert.Equal(identities[0].PublicKeyBlob, parsed[0].PublicKeyBlob);
        Assert.Equal(identities[0].Comment, parsed[0].Comment);
    }

    [Fact]
    public void CreateIdentitiesAnswer_EmptyList_CreatesValidPayload()
    {
        // Arrange
        var identities = new List<SshIdentity>();

        // Act
        var payload = SshAgentProtocol.CreateIdentitiesAnswer(identities);

        // Assert
        Assert.Equal(4, payload.Length);
        Assert.Equal(0u, BinaryPrimitives.ReadUInt32BigEndian(payload));
    }

    #endregion

    #region SshIdentity Tests

    [Fact]
    public void SshIdentity_Fingerprint_ReturnsSha256Prefix()
    {
        // Arrange
        var keyBlob = new byte[] { 0x00, 0x00, 0x00, 0x07, 0x73, 0x73, 0x68, 0x2d, 0x72, 0x73, 0x61 }; // "ssh-rsa"
        var identity = new SshIdentity(keyBlob, "test");

        // Act
        var fingerprint = identity.Fingerprint;

        // Assert
        Assert.Equal(16, fingerprint.Length); // First 16 hex chars of SHA256
        Assert.Matches("^[0-9A-F]+$", fingerprint);
    }

    #endregion

    #region Helper Methods

    private static byte[] CreateSignRequestPayload(byte[] keyBlob, byte[] data, uint flags = 0, bool includeFlags = true)
    {
        using var ms = new MemoryStream();
        using var writer = new BinaryWriter(ms);

        WriteUInt32BE(writer, (uint)keyBlob.Length);
        writer.Write(keyBlob);
        WriteUInt32BE(writer, (uint)data.Length);
        writer.Write(data);
        if (includeFlags)
        {
            WriteUInt32BE(writer, flags);
        }

        return ms.ToArray();
    }

    private static byte[] CreateIdentitiesAnswerPayload((byte[] KeyBlob, string Comment)[] identities)
    {
        using var ms = new MemoryStream();
        using var writer = new BinaryWriter(ms);

        WriteUInt32BE(writer, (uint)identities.Length);
        foreach (var (keyBlob, comment) in identities)
        {
            WriteUInt32BE(writer, (uint)keyBlob.Length);
            writer.Write(keyBlob);
            var commentBytes = System.Text.Encoding.UTF8.GetBytes(comment);
            WriteUInt32BE(writer, (uint)commentBytes.Length);
            writer.Write(commentBytes);
        }

        return ms.ToArray();
    }

    private static void WriteUInt32BE(BinaryWriter writer, uint value)
    {
        Span<byte> buffer = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(buffer, value);
        writer.Write(buffer);
    }

    #endregion
}
