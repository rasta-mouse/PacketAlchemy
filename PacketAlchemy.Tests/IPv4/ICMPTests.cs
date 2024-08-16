using System.Net;
using PacketAlchemy.IPv4;
using PacketAlchemy.IPv4.ICMP;

namespace PacketAlchemy.Tests.IPv4;

public class ICMPTests
{
    [Fact]
    public void ParseICMPEchoRequest()
    {
        const string raw = "CAA+MbIoAABmv3fzAAg96AgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyAhIiMkJSYnKCkqKywtLi8wMTIzNDU2Nw==";
        const string data = "CAkKCwwNDg8QERITFBUWFxgZGhscHR4fICEiIyQlJicoKSorLC0uLzAxMjM0NTY3";

        var req = new ICMPEcho();
        req.ParseBytes(Convert.FromBase64String(raw));

        Assert.Equal(8, req.Type);
        Assert.Equal(0, req.Code);
        //Assert.Equal(0x3e31, req.Checksum);
        Assert.Equal(10418, req.Identifier);
        Assert.Equal(0, req.SequenceNumber);
        Assert.Equal(Convert.FromBase64String(data), req.Data);
    }

    [Fact]
    public void ICMPEchoTest()
    {
        var orig = new IPv4Packet<ICMPEcho>();
        var bytes = orig.ToByteArray();
        var parsed = IPv4Packet<ICMPEcho>.Parse(bytes);

        Assert.Equal(orig.Data.Type, parsed.Data.Type);
        Assert.Equal(orig.Data.Code, parsed.Data.Code);
        Assert.Equal(orig.Data.Checksum, parsed.Data.Checksum);
        Assert.Equal(orig.Data.Identifier, parsed.Data.Identifier);
        Assert.Equal(orig.Data.SequenceNumber, parsed.Data.SequenceNumber);
        Assert.Equal(orig.Data.Data, parsed.Data.Data);
    }

    [Fact]
    public void ICMPEchoParseTest()
    {
        // legit ping captured in wireshark
        const string raw = "RQAAVAAAAAB2AUAijvq0DsCoANYAAEYxsigAAGa/d/MACD3oCAkKCwwNDg8QERITFBUWFxgZGhscHR4fICEiIyQlJicoKSorLC0uLzAxMjM0NTY3";
        const string data = "CAkKCwwNDg8QERITFBUWFxgZGhscHR4fICEiIyQlJicoKSorLC0uLzAxMjM0NTY3";

        var packet = IPv4Packet<ICMPEcho>.Parse(Convert.FromBase64String(raw));

        // header
        Assert.Equal(4, packet.Version);
        Assert.Equal(5, packet.HeaderLength);
        Assert.Equal(0, packet.TypeOfService);
        Assert.Equal(84, packet.TotalLength);
        Assert.Equal(0, packet.Identification);
        Assert.Equal(0, packet.FlagsAndFragmentOffset);
        Assert.Equal(118, packet.TimeToLive);
        Assert.Equal(1, packet.Protocol);
        // Assert.Equal(0x4022, packet.HeaderChecksum);
        Assert.Equal(IPAddress.Parse("142.250.180.14"), packet.SourceAddress);
        Assert.Equal(IPAddress.Parse("192.168.0.214"), packet.DestinationAddress);

        // data
        Assert.Equal(0, packet.Data.Type);
        Assert.Equal(0, packet.Data.Code);
        //Assert.Equal(0x4631, packet.Data.Checksum);
        Assert.Equal(10418, packet.Data.Identifier);
        Assert.Equal(0, packet.Data.SequenceNumber);
        Assert.Equal(Convert.FromBase64String(data), packet.Data.Data);
    }
}