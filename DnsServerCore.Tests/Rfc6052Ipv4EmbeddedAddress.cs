using System;
using System.Net;
using TechnitiumLibrary.Net;
using Xunit;

namespace DnsServerCore.Tests
{
    // RFC 6052: IPv6 Addressing of IPv4/IPv6 Translators
    // https://www.rfc-editor.org/rfc/rfc6052
    public sealed class Rfc6052Ipv4EmbeddedAddress
    {
        const string Ipv4Example = "192.0.2.33";

        [Theory]
        [InlineData(32, "2001:db8::/32", "2001:db8:c000:221::")]
        [InlineData(40, "2001:db8:100::/40", "2001:db8:1c0:2:21::")]
        [InlineData(48, "2001:db8:122::/48", "2001:db8:122:c000:2:2100::")]
        [InlineData(56, "2001:db8:122:300::/56", "2001:db8:122:3c0:0:221::")]
        [InlineData(64, "2001:db8:122:344::/64", "2001:db8:122:344:c0:2:2100::")]
        [InlineData(96, "2001:db8:122:344::/96", "2001:db8:122:344::c000:221")]
        [InlineData(96, "64:ff9b::/96", "64:ff9b::c000:221")]
        public void Section2EmbedsTheIpv4AddressAndLeavesTheReservedOctetZero(int prefixLength, string prefix, string expected)
        {
            IPAddress ipv4 = IPAddress.Parse(Ipv4Example);
            NetworkAddress ipv6Prefix = NetworkAddress.Parse(prefix);

            IPAddress embedded = ipv4.MapToIPv6(ipv6Prefix);

            Assert.Equal(IPAddress.Parse(expected), embedded);
            Assert.Equal(ipv4, embedded.MapToIPv4(prefixLength));

            //bits 64-71 are reserved for prefixes shorter than 96 and must be zero
            if (prefixLength < 96)
                Assert.Equal(0, embedded.GetAddressBytes()[8]);
        }

        [Fact]
        public void Section2RejectsAPrefixLengthThatCannotHoldAnIpv4Address()
        {
            IPAddress ipv4 = IPAddress.Parse(Ipv4Example);
            NetworkAddress prefix = NetworkAddress.Parse("2001:db8::/128");

            Assert.Throws<NotSupportedException>(() => ipv4.MapToIPv6(prefix));
        }

        [Theory]
        [InlineData("8.8.8.8")]
        [InlineData("11.0.0.1")]
        [InlineData("100.128.0.1")]
        [InlineData("172.15.255.255")]
        [InlineData("172.32.0.1")]
        [InlineData("192.0.3.1")]
        [InlineData("192.88.99.1")]
        [InlineData("223.255.255.255")]
        public void Section3WellKnownPrefixRepresentsGlobalUnicast(string address)
        {
            Assert.True(Dns64.App.MayEmbedIpv4(IPAddress.Parse(address), NetworkAddress.Parse("64:ff9b::/96")));
        }

        [Theory]
        [InlineData("0.0.0.0")]
        [InlineData("0.1.2.3")]
        [InlineData("10.1.2.3")]
        [InlineData("100.64.0.1")]
        [InlineData("100.127.255.255")]
        [InlineData("127.0.0.1")]
        [InlineData("169.254.169.254")]
        [InlineData("172.16.0.1")]
        [InlineData("172.31.255.255")]
        [InlineData("192.0.0.1")]
        [InlineData("192.0.2.33")]
        [InlineData("192.168.1.1")]
        [InlineData("198.18.0.1")]
        [InlineData("198.51.100.1")]
        [InlineData("203.0.113.1")]
        [InlineData("224.0.0.1")]
        [InlineData("240.0.0.1")]
        [InlineData("255.255.255.255")]
        public void Section3WellKnownPrefixDoesNotRepresentNonGlobalIpv4(string address)
        {
            //RFC 6052 section 3.1, using the special-purpose ranges in RFC 5735, RFC 6598, and RFC 6890
            Assert.False(Dns64.App.MayEmbedIpv4(IPAddress.Parse(address), NetworkAddress.Parse("64:ff9b::/96")));
        }

        [Fact]
        public void Section3NetworkSpecificPrefixMayRepresentNonGlobalIpv4()
        {
            NetworkAddress networkSpecific = NetworkAddress.Parse("2001:db8:64::/96");

            Assert.True(Dns64.App.MayEmbedIpv4(IPAddress.Parse("10.1.2.3"), networkSpecific));
            Assert.True(Dns64.App.MayEmbedIpv4(IPAddress.Parse("127.0.0.1"), networkSpecific));
            Assert.True(Dns64.App.MayEmbedIpv4(IPAddress.Parse("192.0.2.33"), networkSpecific));
        }
    }
}
