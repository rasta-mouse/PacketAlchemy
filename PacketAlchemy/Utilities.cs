using System.Security.Cryptography;

namespace PacketAlchemy;

public static class Utilities
{
    public static ushort GetRandomU16()
    {
        var buf = new byte[2];
        
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(buf);
        
        return BitConverter.ToUInt16(buf, 0);
    }
    
    public static ushort ToHostOrder(this ushort networkOrderValue)
    {
        if (BitConverter.IsLittleEndian)
        {
            return (ushort)((networkOrderValue >> 8) | (networkOrderValue << 8));
        }
        
        return networkOrderValue;
    }

    public static uint ToHostOrder(this uint networkOrderValue)
    {
        if (BitConverter.IsLittleEndian)
        {
            return (networkOrderValue >> 24) |
                   ((networkOrderValue >> 8) & 0x0000FF00) |
                   ((networkOrderValue << 8) & 0x00FF0000) |
                   (networkOrderValue << 24);
        }
        
        return networkOrderValue;
    }
    
    public static ushort ToNetworkOrder(this ushort hostOrderValue)
    {
        if (BitConverter.IsLittleEndian)
        {
            return (ushort)((hostOrderValue >> 8) | (hostOrderValue << 8));
        }
        
        return hostOrderValue;
    }

    public static uint ToNetworkOrder(this uint hostOrderValue)
    {
        if (BitConverter.IsLittleEndian)
        {
            return (hostOrderValue >> 24) |
                   ((hostOrderValue >> 8) & 0x0000FF00) |
                   ((hostOrderValue << 8) & 0x00FF0000) |
                   (hostOrderValue << 24);
        }
        
        return hostOrderValue;
    }
}