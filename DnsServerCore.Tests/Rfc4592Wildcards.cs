using System.Net;
using System.Threading.Tasks;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;
using Xunit;

namespace DnsServerCore.Tests
{
    public sealed class Rfc4592Wildcards : IClassFixture<DnsServerFixture>
    {
        readonly DnsServerFixture _dns;

        public Rfc4592Wildcards(DnsServerFixture dns)
        {
            _dns = dns;
        }

        [Fact]
        public async Task WildcardSynthesizesTheQueryName()
        {
            const string zone = "wild.example";
            _dns.CreateZone(zone);
            _dns.Add(zone, "*." + zone, DnsResourceRecordType.A, new DnsARecordData(IPAddress.Parse("192.0.2.20")));

            DnsDatagram response = await _dns.QueryAsync("www." + zone, DnsResourceRecordType.A);

            Assert.Equal(DnsResponseCode.NoError, response.RCODE);
            DnsResourceRecord answer = DnsTest.Find(response.Answer, DnsResourceRecordType.A, "www." + zone);
            Assert.NotNull(answer);
            Assert.Equal(IPAddress.Parse("192.0.2.20"), ((DnsARecordData)answer.RDATA).Address);
        }

        [Fact]
        public async Task LiteralAsteriskIsARealName()
        {
            const string zone = "star.example";
            _dns.CreateZone(zone);
            _dns.Add(zone, "*." + zone, DnsResourceRecordType.A, new DnsARecordData(IPAddress.Parse("192.0.2.21")));

            DnsDatagram response = await _dns.QueryAsync("*." + zone, DnsResourceRecordType.A);

            Assert.Equal(DnsResponseCode.NoError, response.RCODE);
            DnsResourceRecord answer = DnsTest.Find(response.Answer, DnsResourceRecordType.A, "*." + zone);
            Assert.NotNull(answer);
            Assert.Equal(IPAddress.Parse("192.0.2.21"), ((DnsARecordData)answer.RDATA).Address);
        }

        [Fact]
        public async Task ExistingNameBeatsTheWildcard()
        {
            const string zone = "exact-wild.example";
            _dns.CreateZone(zone);
            _dns.Add(zone, "*." + zone, DnsResourceRecordType.A, new DnsARecordData(IPAddress.Parse("192.0.2.22")));
            _dns.Add(zone, "www." + zone, DnsResourceRecordType.A, new DnsARecordData(IPAddress.Parse("192.0.2.23")));

            DnsDatagram response = await _dns.QueryAsync("www." + zone, DnsResourceRecordType.A);

            Assert.Equal(DnsResponseCode.NoError, response.RCODE);
            DnsResourceRecord answer = DnsTest.Find(response.Answer, DnsResourceRecordType.A, "www." + zone);
            Assert.NotNull(answer);
            Assert.Equal(IPAddress.Parse("192.0.2.23"), ((DnsARecordData)answer.RDATA).Address);
        }
    }
}
