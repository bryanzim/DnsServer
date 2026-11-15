using System.Collections.Generic;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;
using Xunit;

namespace DnsServerCore.Tests
{
    public sealed class ForwarderProxyPassword
    {
        [Fact]
        public void PlaceholderKeepsTheStoredPassword()
        {
            Assert.Equal("************", DnsWebService.ForwarderProxyPasswordHidden);
            Assert.Equal("secret", DnsWebService.SelectForwarderProxyPassword(DnsWebService.ForwarderProxyPasswordHidden, "secret"));
        }

        [Fact]
        public void EmptyPasswordClearsTheStoredPassword()
        {
            Assert.Null(DnsWebService.SelectForwarderProxyPassword("", "secret"));
            Assert.Null(DnsWebService.SelectForwarderProxyPassword(null, "secret"));
        }

        [Fact]
        public void PlaceholderWithoutAStoredPasswordIsNotStored()
        {
            Assert.Null(DnsWebService.SelectForwarderProxyPassword(DnsWebService.ForwarderProxyPasswordHidden, null));
            Assert.Null(DnsWebService.SelectForwarderProxyPassword(DnsWebService.ForwarderProxyPasswordHidden, ""));
        }

        [Fact]
        public void PostedPasswordReplacesTheStoredPassword()
        {
            Assert.Equal("new-secret", DnsWebService.SelectForwarderProxyPassword("new-secret", "secret"));
        }

        [Fact]
        public void StoredPasswordIsSelectedByProtocolAndForwarder()
        {
            List<DnsResourceRecord> records =
            [
                Forwarder(DnsTransportProtocol.Udp, "192.0.2.8", "udp-secret"),
                Forwarder(DnsTransportProtocol.Https, "192.0.2.8", "https-secret"),
                Forwarder(DnsTransportProtocol.Udp, "192.0.2.9", "other-secret")
            ];

            Assert.Equal("https-secret", DnsWebService.FindForwarderProxyPassword(records, DnsTransportProtocol.Https, "192.0.2.8"));
            Assert.Equal("udp-secret", DnsWebService.FindForwarderProxyPassword(records, DnsTransportProtocol.Udp, "192.0.2.8"));
            Assert.Null(DnsWebService.FindForwarderProxyPassword(records, DnsTransportProtocol.Tcp, "192.0.2.8"));
            Assert.Null(DnsWebService.FindForwarderProxyPassword(null, DnsTransportProtocol.Udp, "192.0.2.8"));
        }

        static DnsResourceRecord Forwarder(DnsTransportProtocol protocol, string forwarder, string password)
        {
            DnsForwarderRecordData data = new DnsForwarderRecordData(protocol, forwarder, false, DnsForwarderRecordProxyType.Http, "192.0.2.1", 8080, "user", password, 0);
            return new DnsResourceRecord("example.com", DnsResourceRecordType.FWD, DnsClass.IN, 0, data);
        }
    }
}
