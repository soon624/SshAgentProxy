using System.Buffers.Binary;

namespace SshAgentProxy.Protocol;

public static class SshAgentProtocol
{
    public static async Task<SshAgentMessage?> ReadMessageAsync(Stream stream, CancellationToken ct = default)
    {
        var lengthBuffer = new byte[4];
        var bytesRead = await stream.ReadAsync(lengthBuffer, ct);
        if (bytesRead == 0)
        {
            System.Diagnostics.Debug.WriteLine("[Protocol] Read 0 bytes - client disconnected");
            return null;
        }
        if (bytesRead < 4)
        {
            System.Diagnostics.Debug.WriteLine($"[Protocol] Read only {bytesRead} bytes for length header");
            throw new InvalidDataException("Failed to read message length");
        }

        var length = BinaryPrimitives.ReadUInt32BigEndian(lengthBuffer);
        if (length == 0 || length > 256 * 1024)
            throw new InvalidDataException($"Invalid message length: {length}");

        var payload = new byte[length];
        var totalRead = 0;
        while (totalRead < length)
        {
            bytesRead = await stream.ReadAsync(payload.AsMemory(totalRead, (int)length - totalRead), ct);
            if (bytesRead == 0)
                throw new InvalidDataException("Unexpected end of stream");
            totalRead += bytesRead;
        }

        return new SshAgentMessage((SshAgentMessageType)payload[0], payload.AsMemory(1));
    }

    public static async Task WriteMessageAsync(Stream stream, SshAgentMessage message, CancellationToken ct = default)
    {
        var length = 1 + message.Payload.Length;
        var buffer = new byte[4 + length];

        BinaryPrimitives.WriteUInt32BigEndian(buffer.AsSpan(0, 4), (uint)length);
        buffer[4] = (byte)message.Type;
        message.Payload.Span.CopyTo(buffer.AsSpan(5));

        await stream.WriteAsync(buffer, ct);
        await stream.FlushAsync(ct);
    }

    public static byte[] CreateIdentitiesAnswer(IReadOnlyList<SshIdentity> identities)
    {
        using var ms = new MemoryStream();
        using var writer = new BinaryWriter(ms);

        WriteUInt32BigEndian(writer, (uint)identities.Count);

        foreach (var identity in identities)
        {
            WriteString(writer, identity.PublicKeyBlob);
            WriteString(writer, identity.Comment);
        }

        return ms.ToArray();
    }

    public static (byte[] keyBlob, byte[] data, uint flags) ParseSignRequest(ReadOnlyMemory<byte> payload)
    {
        var span = payload.Span;
        var offset = 0;

        var keyBlobLen = BinaryPrimitives.ReadUInt32BigEndian(span[offset..]);
        offset += 4;
        var keyBlob = span.Slice(offset, (int)keyBlobLen).ToArray();
        offset += (int)keyBlobLen;

        var dataLen = BinaryPrimitives.ReadUInt32BigEndian(span[offset..]);
        offset += 4;
        var data = span.Slice(offset, (int)dataLen).ToArray();
        offset += (int)dataLen;

        uint flags = 0;
        if (offset + 4 <= span.Length)
        {
            flags = BinaryPrimitives.ReadUInt32BigEndian(span[offset..]);
        }

        return (keyBlob, data, flags);
    }

    public static List<SshIdentity> ParseIdentitiesAnswer(ReadOnlyMemory<byte> payload)
    {
        var span = payload.Span;
        var offset = 0;
        var identities = new List<SshIdentity>();

        var count = BinaryPrimitives.ReadUInt32BigEndian(span[offset..]);
        offset += 4;

        for (var i = 0; i < count; i++)
        {
            var keyBlobLen = BinaryPrimitives.ReadUInt32BigEndian(span[offset..]);
            offset += 4;
            var keyBlob = span.Slice(offset, (int)keyBlobLen).ToArray();
            offset += (int)keyBlobLen;

            var commentLen = BinaryPrimitives.ReadUInt32BigEndian(span[offset..]);
            offset += 4;
            var comment = System.Text.Encoding.UTF8.GetString(span.Slice(offset, (int)commentLen));
            offset += (int)commentLen;

            identities.Add(new SshIdentity(keyBlob, comment));
        }

        return identities;
    }

    private static void WriteUInt32BigEndian(BinaryWriter writer, uint value)
    {
        Span<byte> buffer = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(buffer, value);
        writer.Write(buffer);
    }

    private static void WriteString(BinaryWriter writer, byte[] data)
    {
        WriteUInt32BigEndian(writer, (uint)data.Length);
        writer.Write(data);
    }

    private static void WriteString(BinaryWriter writer, string data)
    {
        var bytes = System.Text.Encoding.UTF8.GetBytes(data);
        WriteUInt32BigEndian(writer, (uint)bytes.Length);
        writer.Write(bytes);
    }
}

public readonly record struct SshAgentMessage(SshAgentMessageType Type, ReadOnlyMemory<byte> Payload)
{
    public static SshAgentMessage Failure() => new(SshAgentMessageType.SSH_AGENT_FAILURE, ReadOnlyMemory<byte>.Empty);
    public static SshAgentMessage Success() => new(SshAgentMessageType.SSH_AGENT_SUCCESS, ReadOnlyMemory<byte>.Empty);

    public static SshAgentMessage IdentitiesAnswer(IReadOnlyList<SshIdentity> identities)
        => new(SshAgentMessageType.SSH_AGENT_IDENTITIES_ANSWER, SshAgentProtocol.CreateIdentitiesAnswer(identities));

    public static SshAgentMessage SignResponse(byte[] signature)
    {
        var payload = new byte[4 + signature.Length];
        BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(0, 4), (uint)signature.Length);
        signature.CopyTo(payload.AsSpan(4));
        return new(SshAgentMessageType.SSH_AGENT_SIGN_RESPONSE, payload);
    }
}

public record SshIdentity(byte[] PublicKeyBlob, string Comment)
{
    public string Fingerprint => Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(PublicKeyBlob))[..16];
}
