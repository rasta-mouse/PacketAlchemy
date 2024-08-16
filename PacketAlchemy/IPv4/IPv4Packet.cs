using System.Net;

namespace PacketAlchemy.IPv4;

public sealed class IPv4Packet<T> where T : IPacket, new()
{
    public byte Version => 4;

    // header length in 32-bit words (minimum is 5 for the standard 20-byte header)
    public byte HeaderLength =>
        (byte)((20 + Options.Length) / 4);

    public byte TypeOfService { get; set; } = 0;

    // length of the header (including options) + the length of the data
    public ushort TotalLength => 
        (ushort)(HeaderLength * 4 + Data.GetBytes().Length);

    public ushort Identification { get; set; } = 0;
    public ushort FlagsAndFragmentOffset { get; set; } = 0; // 3 bits (Flags) + 13 bits (Fragment Offset)
    public byte TimeToLive { get; set; } = 64;
    public byte Protocol { get; set; }

    public ushort HeaderChecksum => 
        CalculateChecksum();

    public IPAddress SourceAddress { get; set; } = IPAddress.None;
    public IPAddress DestinationAddress { get; set; } = IPAddress.None;
    public byte[] Options { get; set; } = []; // variable length (if IHL > 5)
    
    public T Data { get; private set; } = new();

    public IPv4Packet()
    {
        Protocol = Data.Protocol;
    }

    private byte[] SerializeHeader()
    {
        var header = new byte[HeaderLength * 4];

        header[0] = (byte)((Version << 4) | HeaderLength);
        header[1] = TypeOfService;
        BitConverter.GetBytes(TotalLength.ToNetworkOrder()).CopyTo(header, 2);
        BitConverter.GetBytes(Identification.ToNetworkOrder()).CopyTo(header, 4);
        BitConverter.GetBytes(FlagsAndFragmentOffset.ToNetworkOrder()).CopyTo(header, 6);
        header[8] = TimeToLive;
        header[9] = Protocol;
        
        // leave checksum as 0
        
        SourceAddress.GetAddressBytes().CopyTo(header, 12);
        DestinationAddress.GetAddressBytes().CopyTo(header, 16);

        // add options if present
        if (Options.Length > 0)
        {
            Array.Copy(Options, 0, header, 20, Options.Length);
        }

        return header;
    }
    
    private ushort CalculateChecksum()
    {
        var header = SerializeHeader();

        uint checksum = 0;

        for (var i = 0; i < header.Length; i += 2)
        {
            var word = BitConverter.ToUInt16(header, i);
            checksum += word;

            if (checksum > 0xFFFF)
            {
                checksum = (checksum & 0xFFFF) + 1;
            }
        }

        return (ushort)~checksum;
    }

    public static IPv4Packet<T> Parse(byte[] bytes)
    {
        if (bytes.Length < 20) // minimum length for an IPv4 packet header
            throw new InvalidDataException("Invalid IPv4 packet. Length too short.");

        var packet = new IPv4Packet<T>
        {
            TypeOfService = bytes[1],
            Identification = BitConverter.ToUInt16(bytes, 4).ToHostOrder(),
            FlagsAndFragmentOffset = BitConverter.ToUInt16(bytes, 6).ToHostOrder(),
            TimeToLive = bytes[8],
            Protocol = bytes[9],
            SourceAddress = new IPAddress(BitConverter.ToUInt32(bytes, 12)),
            DestinationAddress = new IPAddress(BitConverter.ToUInt32(bytes, 16))
        };

        // Parse options if present
        var headerLength = (byte)(bytes[0] & 0x0F);
        var headerLengthBytes = headerLength * 4;
        
        if (headerLengthBytes > 20)
        {
            packet.Options = new byte[headerLengthBytes - 20];
            Array.Copy(bytes, 20, packet.Options, 0, packet.Options.Length);
        }
        
        // parse data
        var totalLength = BitConverter.ToUInt16(bytes, 2).ToHostOrder();
        var dataLength = totalLength - headerLengthBytes;
        
        var dataBytes = bytes.Skip(headerLengthBytes).Take(dataLength).ToArray();
        
        packet.Data = new T();
        packet.Data.ParseBytes(dataBytes);
        
        return packet;
    }

    public byte[] ToByteArray()
    {
        var packet = new byte[TotalLength];
        
        // add header
        var header = SerializeHeader();
        Array.Copy(header, 0, packet, 0, header.Length);

        // add data
        var data = Data.GetBytes();
        Array.Copy(data, 0, packet, HeaderLength * 4, data.Length);

        return packet;
    }
}