using System.Net;
using Xunit;

namespace DnsServerCore.Tests
{
    public sealed class LoginRateLimitAddress
    {
        [Fact]
        public void ConnectionAddressIsTheRateLimitBucket()
        {
            Assert.Equal(IPAddress.Parse("203.0.113.5"), DnsWebService.SelectRateLimitAddress(IPAddress.Parse("203.0.113.5")));
            Assert.Equal(IPAddress.Parse("203.0.113.5"), DnsWebService.SelectRateLimitAddress(IPAddress.Parse("::ffff:203.0.113.5")));
            Assert.Equal(IPAddress.Parse("192.168.1.9"), DnsWebService.SelectRateLimitAddress(IPAddress.Parse("192.168.1.9")));
            Assert.Equal(IPAddress.IPv6Loopback, DnsWebService.SelectRateLimitAddress(IPAddress.IPv6Loopback));
        }

        [Fact]
        public void MissingConnectionUsesLoopback()
        {
            Assert.Equal(IPAddress.Loopback, DnsWebService.SelectRateLimitAddress(null));
        }
    }
}
