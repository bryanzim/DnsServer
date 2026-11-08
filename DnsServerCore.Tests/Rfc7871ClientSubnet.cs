using System.Net;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.EDnsOptions;
using TechnitiumLibrary.Net.Dns.ResourceRecords;
using Xunit;

namespace DnsServerCore.Tests
{
    public sealed class Rfc7871ClientSubnet : IClassFixture<DnsServerFixture>
    {
        readonly DnsServerFixture _dns;

        public Rfc7871ClientSubnet(DnsServerFixture dns)
        {
            _dns = dns;
        }

        [Fact]
        public void CacheKeepsEachClientSubnetSeparate()
        {
            const string name = "www.ecs.example";
            Cache(name, "192.0.2.1", "192.0.2.10");
            Cache(name, "198.51.100.1", "198.51.100.10");

            AssertAddress(name, "192.0.2.50", "192.0.2.10");
            AssertAddress(name, "198.51.100.50", "198.51.100.10");
        }

        void Cache(string name, string client, string answer)
        {
            EDnsOption ecs = new EDnsOption(EDnsOptionCode.EDNS_CLIENT_SUBNET, new EDnsClientSubnetOptionData(24, 24, IPAddress.Parse(client)));
            DnsResourceRecord address = new DnsResourceRecord(name, DnsResourceRecordType.A, DnsClass.IN, 300, new DnsARecordData(IPAddress.Parse(answer)));
            DnsDatagram response = new DnsDatagram(0, true, DnsOpcode.StandardQuery, false, false, false, true, false, false, DnsResponseCode.NoError, [new DnsQuestionRecord(name, DnsResourceRecordType.A, DnsClass.IN)], [address], udpPayloadSize: 1232, options: [ecs]);
            _dns.Server.CacheZoneManager.CacheResponse(response);
        }

        void AssertAddress(string name, string client, string expected)
        {
            EDnsOption ecs = new EDnsOption(EDnsOptionCode.EDNS_CLIENT_SUBNET, new EDnsClientSubnetOptionData(24, 0, IPAddress.Parse(client)));
            DnsDatagram request = new DnsDatagram(0, false, DnsOpcode.StandardQuery, false, false, false, false, false, false, DnsResponseCode.NoError, [new DnsQuestionRecord(name, DnsResourceRecordType.A, DnsClass.IN)], udpPayloadSize: 1232, options: [ecs]);
            DnsDatagram cached = _dns.Server.CacheZoneManager.Query(request, false);

            Assert.NotNull(cached);
            DnsResourceRecord answer = DnsTest.Find(cached.Answer, DnsResourceRecordType.A, name);
            Assert.NotNull(answer);
            Assert.Equal(IPAddress.Parse(expected), ((DnsARecordData)answer.RDATA).Address);
        }
    }
}
