using System.Net;
using System.Threading.Tasks;
using TechnitiumLibrary.Net.Dns;
using DnsResponseCode = TechnitiumLibrary.Net.Dns.DnsResponseCode;
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

        [Fact]
        public async Task WildcardSynthesizesAcrossMultipleLabels()
        {
            const string zone = "multi-wild.example";
            _dns.CreateZone(zone);
            _dns.Add(zone, "*." + zone, DnsResourceRecordType.A, new DnsARecordData(IPAddress.Parse("192.0.2.24")));

            DnsDatagram response = await _dns.QueryAsync("a.b." + zone, DnsResourceRecordType.A);

            Assert.Equal(DnsResponseCode.NoError, response.RCODE);
            Assert.True(response.AuthoritativeAnswer, DnsTest.Describe(response));
            DnsResourceRecord answer = DnsTest.Find(response.Answer, DnsResourceRecordType.A, "a.b." + zone);
            Assert.NotNull(answer);
            Assert.Equal(IPAddress.Parse("192.0.2.24"), ((DnsARecordData)answer.RDATA).Address);
        }

        [Fact]
        public async Task ExistingNameBlocksTheWildcardBelowIt()
        {
            const string zone = "ent-wild.example";
            _dns.CreateZone(zone);
            _dns.Add(zone, "*." + zone, DnsResourceRecordType.A, new DnsARecordData(IPAddress.Parse("192.0.2.25")));
            _dns.Add(zone, "mail." + zone, DnsResourceRecordType.TXT, new DnsTXTRecordData("mx"));

            DnsDatagram atTheName = await _dns.QueryAsync("mail." + zone, DnsResourceRecordType.A);
            Assert.Equal(DnsResponseCode.NoError, atTheName.RCODE);
            Assert.Null(DnsTest.Find(atTheName.Answer, DnsResourceRecordType.A));
            Assert.NotNull(DnsTest.Find(atTheName.Authority, DnsResourceRecordType.SOA, zone));

            DnsDatagram below = await _dns.QueryAsync("a.mail." + zone, DnsResourceRecordType.A);
            Assert.Equal(DnsResponseCode.NxDomain, below.RCODE);
            Assert.True(below.AuthoritativeAnswer, DnsTest.Describe(below));
            Assert.Empty(below.Answer);
        }

        [Fact]
        public async Task DelegationBlocksTheWildcard()
        {
            const string zone = "cut-wild.example";
            _dns.CreateZone(zone);
            _dns.Add(zone, "*." + zone, DnsResourceRecordType.A, new DnsARecordData(IPAddress.Parse("192.0.2.26")));
            _dns.Add(zone, "del." + zone, DnsResourceRecordType.NS, new DnsNSRecordData("ns1.example.net"));

            DnsDatagram response = await _dns.QueryAsync("host.del." + zone, DnsResourceRecordType.A);

            Assert.Equal(DnsResponseCode.NoError, response.RCODE);
            Assert.False(response.AuthoritativeAnswer, DnsTest.Describe(response));
            Assert.Empty(response.Answer);
            Assert.Null(DnsTest.Find(response.Answer, DnsResourceRecordType.A, "host.del." + zone));
            Assert.NotNull(DnsTest.Find(response.Authority, DnsResourceRecordType.NS, "del." + zone));
        }

        [Fact]
        public async Task MissingTypeAtAWildcardIsNodata()
        {
            const string zone = "type-wild.example";
            _dns.CreateZone(zone);
            _dns.Add(zone, "*." + zone, DnsResourceRecordType.A, new DnsARecordData(IPAddress.Parse("192.0.2.27")));

            DnsDatagram response = await _dns.QueryAsync("www." + zone, DnsResourceRecordType.AAAA);

            Assert.Equal(DnsResponseCode.NoError, response.RCODE);
            Assert.True(response.AuthoritativeAnswer, DnsTest.Describe(response));
            Assert.Empty(response.Answer);
            Assert.NotNull(DnsTest.Find(response.Authority, DnsResourceRecordType.SOA, zone));
        }
    }
}
