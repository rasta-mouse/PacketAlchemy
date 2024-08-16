namespace PacketAlchemy.IPv4.ICMP;

public sealed class ICMPEcho : ICMPBase
{
    public ushort Identifier { get; set; } = Utilities.GetRandomU16();
    public ushort SequenceNumber { get; set; } = 0;

    public uint? TimestampSeconds { get; set; }
    public uint? TimestampMicroseconds { get; set; }
    
    public byte[] Data { get; set; } = [];

    public ICMPEcho()
    {
        Type = 8;
        Code = 0;
    }

    public override ushort Checksum
    {
        get
        {
            var data = Serialize();
            return CalculateChecksum(data);
        }
    }

    private byte[] Serialize()
    {
        // check if we need to include stupid timestamps
        var szHeader = TimestampSeconds is null ? 8 : 16;
        var packet = new byte[szHeader + Data.Length];

        packet[0] = Type;
        packet[1] = Code;
        
        // leave checksum empty
        
        BitConverter.GetBytes(Identifier).CopyTo(packet, 4);
        BitConverter.GetBytes(SequenceNumber).CopyTo(packet, 6);
        
        // timestamps?
        if (TimestampSeconds is not null && TimestampMicroseconds is not null)
        {
            BitConverter.GetBytes(TimestampSeconds.Value.ToNetworkOrder()).CopyTo(packet, 8);
            BitConverter.GetBytes(TimestampMicroseconds.Value.ToNetworkOrder()).CopyTo(packet, 12);
            
            Data.CopyTo(packet, 16);
        }
        else
        {
            Data.CopyTo(packet, 8);
        }
        
        return packet;
    }

    public override byte[] GetBytes()
    {
        var packet = Serialize();

        // add checksum
        BitConverter.GetBytes(Checksum).CopyTo(packet, 2);

        return packet;
    }

    public override void ParseBytes(byte[] data)
    {
        if (data.Length < 8)
            throw new InvalidDataException("Invalid ICMP packet.");

        Type = data[0];
        Code = data[1];
        Identifier = BitConverter.ToUInt16(data, 4);
        SequenceNumber = BitConverter.ToUInt16(data, 6);
        
        // if the data was only 8 bytes then there's nothing else to read
        if (data.Length == 8)
            return;
        
        // some bsd dev thought it would be clever to add an
        // 8-byte unix timestamp after the header, but before the data
        
        // first 4 bytes are seconds
        // second 4 bytes are microseconds

        // data length must be at least 16 to have the timestamp
        if (data.Length >= 16)
        {
            // we have to read 8 bytes and see if it looks like a timestamp
            var seconds = BitConverter.ToUInt32(data, 8).ToHostOrder();
            var microseconds = BitConverter.ToUInt32(data, 12).ToHostOrder();
            var date = DateTimeOffset.FromUnixTimeSeconds(seconds).DateTime;
            
            // some sanity check on the values
            if (date.Year >= 1970 && date.Year <= DateTime.Now.Year && microseconds <= 999999)
            {
                // seems plausible
                TimestampSeconds = seconds;
                TimestampMicroseconds = microseconds;

                // adjust the data field to account for the timestamp
                Data = new byte[data.Length - 16];
                Array.Copy(data, 16, Data, 0, Data.Length);
            }
            else
            {
                // not a valid timestamp, assume there's no timestamp and the data starts right after the header
                Data = new byte[data.Length - 8];
                Array.Copy(data, 8, Data, 0, Data.Length);
            }
        }
        else
        {
            Data = new byte[data.Length - 8];
            Array.Copy(data, 8, Data, 0, Data.Length);    
        }
    }
}