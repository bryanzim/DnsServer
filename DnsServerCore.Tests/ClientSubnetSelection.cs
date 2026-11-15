using System.Net;
using DnsServerCore.Dns;
using TechnitiumLibrary.Net;
using Xunit;

namespace DnsServerCore.Tests
{
    public sealed class ClientSubnetSelection
    {
        static readonly IPAddress Client = IPAddress.Parse("203.0.113.10");

        [Fact]
        public void PrefixThatContainsTheClientIsCapped()
        {
            NetworkAddress selected = DnsServer.SelectClientSubnet(Client, IPAddress.Parse("203.0.113.10"), 32, 24);

            Assert.NotNull(selected);
            Assert.Equal(24, selected.PrefixLength);
            Assert.True(selected.Contains(Client));
        }

        [Fact]
        public void WiderPrefixThatContainsTheClientIsKept()
        {
            NetworkAddress selected = DnsServer.SelectClientSubnet(Client, IPAddress.Parse("203.0.0.0"), 16, 24);

            Assert.NotNull(selected);
            Assert.Equal(16, selected.PrefixLength);
            Assert.True(selected.Contains(Client));
        }

        [Fact]
        public void ForeignPrefixIsIgnored()
        {
            Assert.Null(DnsServer.SelectClientSubnet(Client, IPAddress.Parse("198.51.100.0"), 24, 24));
            Assert.Null(DnsServer.SelectClientSubnet(Client, Client, 0, 24));
            Assert.Null(DnsServer.SelectClientSubnet(IPAddress.Parse("2001:db8::1"), Client, 24, 56));
            Assert.Null(DnsServer.SelectClientSubnet(null, Client, 24, 24));
        }

        [Fact]
        public void IPv4MappedClientUsesTheIPv4Prefix()
        {
            NetworkAddress selected = DnsServer.SelectClientSubnet(IPAddress.Parse("::ffff:203.0.113.10"), IPAddress.Parse("203.0.113.10"), 32, 24);

            Assert.NotNull(selected);
            Assert.Equal(24, selected.PrefixLength);
            Assert.True(selected.Contains(Client));
        }

        [Fact]
        public void IPv6PrefixThatContainsTheClientIsCapped()
        {
            IPAddress client = IPAddress.Parse("2001:db8:1:2:3::1");
            NetworkAddress selected = DnsServer.SelectClientSubnet(client, client, 128, 56);

            Assert.NotNull(selected);
            Assert.Equal(56, selected.PrefixLength);
            Assert.True(selected.Contains(client));
        }
    }
}
