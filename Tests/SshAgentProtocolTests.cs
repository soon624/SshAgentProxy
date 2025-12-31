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

    #region ReadMessageAsync Tests

    [Fact]
    public async Task ReadMessageAsync_ValidMessage_ReturnsMessage()
    {
        // Arrange
        var messageType = SshAgentMessageType.SSH_AGENTC_REQUEST_IDENTITIES;
        var payload = new byte[] { 0x01, 0x02, 0x03 };
        var stream = CreateMessageStream(messageType, payload);

        // Act
        var result = await SshAgentProtocol.ReadMessageAsync(stream);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(messageType, result.Value.Type);
        Assert.Equal(payload, result.Value.Payload.ToArray());
    }

    [Fact]
    public async Task ReadMessageAsync_EmptyStream_ReturnsNull()
    {
        // Arrange
        var stream = new MemoryStream();

        // Act
        var result = await SshAgentProtocol.ReadMessageAsync(stream);

        // Assert
        Assert.Null(result);
    }

    [Fact]
    public async Task ReadMessageAsync_PartialHeader_ThrowsInvalidDataException()
    {
        // Arrange: Only 2 bytes of header (needs 4)
        var stream = new MemoryStream(new byte[] { 0x00, 0x00 });

        // Act & Assert
        await Assert.ThrowsAsync<InvalidDataException>(() => SshAgentProtocol.ReadMessageAsync(stream));
    }

    [Fact]
    public async Task ReadMessageAsync_ZeroLength_ThrowsInvalidDataException()
    {
        // Arrange: length = 0
        var stream = new MemoryStream(new byte[] { 0x00, 0x00, 0x00, 0x00 });

        // Act & Assert
        await Assert.ThrowsAsync<InvalidDataException>(() => SshAgentProtocol.ReadMessageAsync(stream));
    }

    [Fact]
    public async Task ReadMessageAsync_LengthExceedsLimit_ThrowsInvalidDataException()
    {
        // Arrange: length = 300KB (exceeds 256KB limit)
        var header = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(header, 300 * 1024);
        var stream = new MemoryStream(header);

        // Act & Assert
        await Assert.ThrowsAsync<InvalidDataException>(() => SshAgentProtocol.ReadMessageAsync(stream));
    }

    [Fact]
    public async Task ReadMessageAsync_TruncatedPayload_ThrowsInvalidDataException()
    {
        // Arrange: header says 10 bytes, but only 5 available
        var header = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(header, 10);
        var data = new byte[9]; // header + 5 bytes (not 10)
        Array.Copy(header, data, 4);
        data[4] = 0x0B; // message type
        var stream = new MemoryStream(data);

        // Act & Assert
        await Assert.ThrowsAsync<InvalidDataException>(() => SshAgentProtocol.ReadMessageAsync(stream));
    }

    #endregion

    #region WriteMessageAsync Tests

    [Fact]
    public async Task WriteMessageAsync_ValidMessage_WritesCorrectBytes()
    {
        // Arrange
        var messageType = SshAgentMessageType.SSH_AGENT_SUCCESS;
        var payload = new byte[] { 0x01, 0x02 };
        var message = new SshAgentMessage(messageType, payload);
        var stream = new MemoryStream();

        // Act
        await SshAgentProtocol.WriteMessageAsync(stream, message);

        // Assert
        var result = stream.ToArray();
        Assert.Equal(7, result.Length); // 4 (length) + 1 (type) + 2 (payload)
        Assert.Equal(3u, BinaryPrimitives.ReadUInt32BigEndian(result.AsSpan(0, 4))); // length = 3
        Assert.Equal((byte)messageType, result[4]);
        Assert.Equal(payload, result[5..]);
    }

    [Fact]
    public async Task WriteMessageAsync_EmptyPayload_WritesCorrectBytes()
    {
        // Arrange
        var message = SshAgentMessage.Success();
        var stream = new MemoryStream();

        // Act
        await SshAgentProtocol.WriteMessageAsync(stream, message);

        // Assert
        var result = stream.ToArray();
        Assert.Equal(5, result.Length); // 4 (length) + 1 (type)
        Assert.Equal(1u, BinaryPrimitives.ReadUInt32BigEndian(result.AsSpan(0, 4))); // length = 1
        Assert.Equal((byte)SshAgentMessageType.SSH_AGENT_SUCCESS, result[4]);
    }

    #endregion

    #region SshAgentMessage Static Methods Tests

    [Fact]
    public void SshAgentMessage_Failure_ReturnsCorrectMessage()
    {
        // Act
        var message = SshAgentMessage.Failure();

        // Assert
        Assert.Equal(SshAgentMessageType.SSH_AGENT_FAILURE, message.Type);
        Assert.Empty(message.Payload.ToArray());
    }

    [Fact]
    public void SshAgentMessage_Success_ReturnsCorrectMessage()
    {
        // Act
        var message = SshAgentMessage.Success();

        // Assert
        Assert.Equal(SshAgentMessageType.SSH_AGENT_SUCCESS, message.Type);
        Assert.Empty(message.Payload.ToArray());
    }

    [Fact]
    public void SshAgentMessage_IdentitiesAnswer_ReturnsCorrectMessage()
    {
        // Arrange
        var identities = new List<SshIdentity>
        {
            new(new byte[] { 0x01, 0x02 }, "test-key"),
        };

        // Act
        var message = SshAgentMessage.IdentitiesAnswer(identities);

        // Assert
        Assert.Equal(SshAgentMessageType.SSH_AGENT_IDENTITIES_ANSWER, message.Type);
        Assert.True(message.Payload.Length > 0);
    }

    [Fact]
    public void SshAgentMessage_SignResponse_ReturnsCorrectMessage()
    {
        // Arrange
        var signature = new byte[] { 0x01, 0x02, 0x03, 0x04 };

        // Act
        var message = SshAgentMessage.SignResponse(signature);

        // Assert
        Assert.Equal(SshAgentMessageType.SSH_AGENT_SIGN_RESPONSE, message.Type);
        // Payload should be: 4 bytes length + signature
        Assert.Equal(8, message.Payload.Length);
        var sigLen = BinaryPrimitives.ReadUInt32BigEndian(message.Payload.Span[..4]);
        Assert.Equal(4u, sigLen);
        Assert.Equal(signature, message.Payload.Span[4..].ToArray());
    }

    #endregion

    #region ParseIdentitiesAnswer Edge Cases

    [Fact]
    public void ParseIdentitiesAnswer_TruncatedKeyBlobLength_ThrowsInvalidDataException()
    {
        // Arrange: count = 1, keyBlobLen starts but truncated
        using var ms = new MemoryStream();
        using var writer = new BinaryWriter(ms);
        WriteUInt32BE(writer, 1); // count
        writer.Write(new byte[] { 0x00, 0x00 }); // partial keyBlobLen
        var payload = ms.ToArray();

        // Act & Assert
        Assert.Throws<InvalidDataException>(() => SshAgentProtocol.ParseIdentitiesAnswer(payload));
    }

    [Fact]
    public void ParseIdentitiesAnswer_KeyBlobLengthExceedsPayload_ThrowsInvalidDataException()
    {
        // Arrange: count = 1, keyBlobLen = 100 but not enough data
        using var ms = new MemoryStream();
        using var writer = new BinaryWriter(ms);
        WriteUInt32BE(writer, 1); // count
        WriteUInt32BE(writer, 100); // keyBlobLen
        writer.Write(new byte[5]); // only 5 bytes
        var payload = ms.ToArray();

        // Act & Assert
        Assert.Throws<InvalidDataException>(() => SshAgentProtocol.ParseIdentitiesAnswer(payload));
    }

    [Fact]
    public void ParseIdentitiesAnswer_TruncatedCommentLength_ThrowsInvalidDataException()
    {
        // Arrange: count = 1, valid keyBlob, but commentLen truncated
        using var ms = new MemoryStream();
        using var writer = new BinaryWriter(ms);
        WriteUInt32BE(writer, 1); // count
        WriteUInt32BE(writer, 2); // keyBlobLen
        writer.Write(new byte[] { 0x01, 0x02 }); // keyBlob
        writer.Write(new byte[] { 0x00, 0x00 }); // partial commentLen
        var payload = ms.ToArray();

        // Act & Assert
        Assert.Throws<InvalidDataException>(() => SshAgentProtocol.ParseIdentitiesAnswer(payload));
    }

    [Fact]
    public void ParseIdentitiesAnswer_CommentLengthExceedsPayload_ThrowsInvalidDataException()
    {
        // Arrange: count = 1, valid keyBlob, commentLen = 100 but not enough
        using var ms = new MemoryStream();
        using var writer = new BinaryWriter(ms);
        WriteUInt32BE(writer, 1); // count
        WriteUInt32BE(writer, 2); // keyBlobLen
        writer.Write(new byte[] { 0x01, 0x02 }); // keyBlob
        WriteUInt32BE(writer, 100); // commentLen
        writer.Write(new byte[5]); // only 5 bytes
        var payload = ms.ToArray();

        // Act & Assert
        Assert.Throws<InvalidDataException>(() => SshAgentProtocol.ParseIdentitiesAnswer(payload));
    }

    #endregion

    #region ParseSignRequest Edge Cases

    [Fact]
    public void ParseSignRequest_TruncatedDataLength_ThrowsInvalidDataException()
    {
        // Arrange: Valid keyBlob, but dataLen field truncated
        using var ms = new MemoryStream();
        using var writer = new BinaryWriter(ms);
        WriteUInt32BE(writer, 2); // keyBlobLen
        writer.Write(new byte[] { 0x01, 0x02 }); // keyBlob
        writer.Write(new byte[] { 0x00, 0x00 }); // partial dataLen
        var payload = ms.ToArray();

        // Act & Assert
        Assert.Throws<InvalidDataException>(() => SshAgentProtocol.ParseSignRequest(payload));
    }

    #endregion

    #region Helper Methods

    private static MemoryStream CreateMessageStream(SshAgentMessageType type, byte[] payload)
    {
        var ms = new MemoryStream();
        var length = 1 + payload.Length;
        var header = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(header, (uint)length);
        ms.Write(header);
        ms.WriteByte((byte)type);
        ms.Write(payload);
        ms.Position = 0;
        return ms;
    }

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
