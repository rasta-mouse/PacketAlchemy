namespace PacketAlchemy.IPv4.ICMP;

public abstract class ICMPBase : IPacket
{
    public byte Protocol => 1;
    
    public byte Type { get; set; }
    public byte Code { get; set; }
    
    public abstract ushort Checksum { get; }

    public abstract byte[] GetBytes();
    public abstract void ParseBytes(byte[] data);
    
    protected ushort CalculateChecksum(byte[] data)
    {
        uint sum = 0;

        for (var i = 0; i < data.Length; i += 2)
        {
            var word = BitConverter.ToUInt16(data, i);
            sum += word;
        }

        while (sum >> 16 != 0)
        {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        return (ushort)~sum;
    }
}