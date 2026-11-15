using System.Net;
using Xunit;

namespace DnsServerCore.Tests
{
    public sealed class HealthCheckLoopback
    {
        [Fact]
        public void LocalhostConnectionsAreAccepted()
        {
            Assert.True(DnsWebService.IsConnectionLoopback(IPAddress.Loopback));
            Assert.True(DnsWebService.IsConnectionLoopback(IPAddress.IPv6Loopback));
            Assert.True(DnsWebService.IsConnectionLoopback(IPAddress.Parse("::ffff:127.0.0.1")));
        }

        [Fact]
        public void OtherAddressesAreRejected()
        {
            Assert.False(DnsWebService.IsConnectionLoopback(null));
            Assert.False(DnsWebService.IsConnectionLoopback(IPAddress.Any));
            Assert.False(DnsWebService.IsConnectionLoopback(IPAddress.IPv6Any));
            Assert.False(DnsWebService.IsConnectionLoopback(IPAddress.Parse("127.0.0.2")));
            Assert.False(DnsWebService.IsConnectionLoopback(IPAddress.Parse("10.0.0.1")));
            Assert.False(DnsWebService.IsConnectionLoopback(IPAddress.Parse("192.168.1.5")));
            Assert.False(DnsWebService.IsConnectionLoopback(IPAddress.Parse("203.0.113.5")));
            Assert.False(DnsWebService.IsConnectionLoopback(IPAddress.Parse("::ffff:203.0.113.5")));
        }
    }
}
