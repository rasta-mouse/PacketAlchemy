using PacketAlchemy.IPv4;

namespace PacketAlchemy.Tests;

public sealed class DummyPacket : IPacket
{
    public byte Protocol => 1;
    
    public byte[] GetBytes()
    {
        return [];
    }

    public void ParseBytes(byte[] data)
    {
        
    }
}