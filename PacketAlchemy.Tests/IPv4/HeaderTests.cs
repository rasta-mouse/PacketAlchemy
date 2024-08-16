using System.Net;
using PacketAlchemy.IPv4;
using PacketAlchemy.IPv4.ICMP;

namespace PacketAlchemy.Tests.IPv4;

public sealed class HeaderTests
{
    [Fact]
    public void ParseIPv4HeaderTest()
    {
        const string raw = "RQAAVKLSAABAAdNPwKgA1o76tA4=";

        var header = IPv4Packet<DummyPacket>.Parse(Convert.FromBase64String(raw));
        
        Assert.Equal(4, header.Version);
        Assert.Equal(5, header.HeaderLength);
        Assert.Equal(0, header.TypeOfService);
        //Assert.Equal(84, header.TotalLength);
        Assert.Equal(0xa2d2, header.Identification);
        Assert.Equal(0, header.FlagsAndFragmentOffset);
        Assert.Equal(64, header.TimeToLive);
        Assert.Equal(1, header.Protocol);
        //Assert.Equal(0xd34f, header.HeaderChecksum);
        Assert.Equal(IPAddress.Parse("192.168.0.214"), header.SourceAddress);
        Assert.Equal(IPAddress.Parse("142.250.180.14"), header.DestinationAddress);
        Assert.Empty(header.Options);
    }
    
    [Fact]
    public void IPv4HeaderTest()
    {
        var orig = new IPv4Packet<ICMPEcho>();
        var bytes = orig.ToByteArray();
        var parsed = IPv4Packet<ICMPEcho>.Parse(bytes);
        
        Assert.Equal(orig.Version, parsed.Version);
        Assert.Equal(orig.TypeOfService, parsed.TypeOfService);
        Assert.Equal(orig.TotalLength, parsed.TotalLength);
        Assert.Equal(orig.Identification, parsed.Identification);
        Assert.Equal(orig.FlagsAndFragmentOffset, parsed.FlagsAndFragmentOffset);
        Assert.Equal(orig.TimeToLive, parsed.TimeToLive);
        Assert.Equal(orig.Protocol, parsed.Protocol);
        Assert.Equal(orig.HeaderChecksum, parsed.HeaderChecksum);
        Assert.Equal(orig.SourceAddress, parsed.SourceAddress);
        Assert.Equal(orig.DestinationAddress, parsed.DestinationAddress);
        Assert.Equal(orig.Options, parsed.Options);
    }
}