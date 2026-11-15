using System.Net;
using DnsServerCore.Dns;
using Xunit;

namespace DnsServerCore.Tests
{
    public sealed class ForwardedClientAddress
    {
        static readonly IPAddress Peer = IPAddress.Parse("192.168.1.40");

        [Fact]
        public void PrivilegedHeaderFromARemotePeerIsIgnored()
        {
            Assert.Equal(Peer, DnsServer.SelectForwardedClientAddress(Peer, IPAddress.Loopback, true));
            Assert.Equal(Peer, DnsServer.SelectForwardedClientAddress(Peer, IPAddress.IPv6Loopback, true));
            Assert.Equal(Peer, DnsServer.SelectForwardedClientAddress(Peer, IPAddress.Parse("127.0.0.2"), true));
            Assert.Equal(Peer, DnsServer.SelectForwardedClientAddress(Peer, IPAddress.Any, true));
            Assert.Equal(Peer, DnsServer.SelectForwardedClientAddress(Peer, IPAddress.IPv6Any, true));
            Assert.Equal(IPAddress.Parse("10.1.2.3"), DnsServer.SelectForwardedClientAddress(IPAddress.Parse("::ffff:10.1.2.3"), IPAddress.Parse("::ffff:127.0.0.1"), true));
        }

        [Fact]
        public void OrdinaryHeaderFromATrustedProxyIsKept()
        {
            IPAddress client = IPAddress.Parse("203.0.113.8");

            Assert.Equal(client, DnsServer.SelectForwardedClientAddress(Peer, client, true));
            Assert.Equal(client, DnsServer.SelectForwardedClientAddress(IPAddress.Loopback, client, true));
            Assert.Equal(client, DnsServer.SelectForwardedClientAddress(null, client, true));
        }

        [Fact]
        public void HeaderIsIgnoredWhenThePeerIsNotTrusted()
        {
            Assert.Equal(Peer, DnsServer.SelectForwardedClientAddress(Peer, IPAddress.Parse("203.0.113.8"), false));
            Assert.Null(DnsServer.SelectForwardedClientAddress(null, IPAddress.Loopback, false));
        }

        [Fact]
        public void LocalConnectionMayUseALoopbackHeader()
        {
            Assert.Equal(IPAddress.Loopback, DnsServer.SelectForwardedClientAddress(IPAddress.Loopback, IPAddress.Loopback, true));
            Assert.Equal(IPAddress.Loopback, DnsServer.SelectForwardedClientAddress(null, IPAddress.Parse("::ffff:127.0.0.1"), true));
        }
    }
}
