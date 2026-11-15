using System.Net;
using System.Threading.Tasks;
using TechnitiumLibrary.Net.Dns;
using DnsResponseCode = TechnitiumLibrary.Net.Dns.DnsResponseCode;
using TechnitiumLibrary.Net.Dns.ResourceRecords;
using Xunit;

namespace DnsServerCore.Tests
{
    // RFC 1996: A Mechanism for Prompt Notification of Zone Changes (DNS NOTIFY)
    // https://www.rfc-editor.org/rfc/rfc1996
    public sealed class Rfc1996Notify : IClassFixture<DnsServerFixture>
    {
        readonly DnsServerFixture _dns;

        public Rfc1996Notify(DnsServerFixture dns)
        {
            _dns = dns;
        }

        [Fact]
        public async Task NotifyIsAcceptedFromThePrimaryAndRefusedFromAnywhereElse()
        {
            const string zone = "notify.example";
            NameServerAddress primary = new NameServerAddress(new IPEndPoint(IPAddress.Loopback, 1), DnsTransportProtocol.Tcp);
            Assert.NotNull(await _dns.Server.AuthZoneManager.CreateSecondaryZoneAsync(zone, [primary], DnsTransportProtocol.Tcp, null, false, true));

            DnsDatagram notify = new DnsDatagram(1, false, DnsOpcode.Notify, false, false, false, false, false, false, DnsResponseCode.NoError, [new DnsQuestionRecord(zone, DnsResourceRecordType.SOA, DnsClass.IN)], [new DnsResourceRecord(zone, DnsResourceRecordType.SOA, DnsClass.IN, 0, new DnsSOARecordData("ns.example", "hostmaster.example", 1, 300, 60, 86400, 300))]);

            DnsDatagram refused = await _dns.Server.DirectQueryAsync(notify, new IPEndPoint(IPAddress.Parse("192.0.2.8"), 5353), 10000);
            DnsDatagram accepted = await _dns.Server.DirectQueryAsync(notify, new IPEndPoint(IPAddress.Loopback, 5353), 10000);

            Assert.Equal(DnsResponseCode.Refused, refused.RCODE);
            Assert.Equal(DnsOpcode.Notify, refused.OPCODE);
            Assert.Equal(DnsResponseCode.NoError, accepted.RCODE);
            Assert.Equal(DnsOpcode.Notify, accepted.OPCODE);
        }
    }
}
