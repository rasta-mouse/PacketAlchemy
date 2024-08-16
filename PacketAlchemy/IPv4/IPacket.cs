namespace PacketAlchemy.IPv4;

public interface IPacket
{
    byte Protocol { get; }
    
    byte[] GetBytes();
    void ParseBytes(byte[] data);
}