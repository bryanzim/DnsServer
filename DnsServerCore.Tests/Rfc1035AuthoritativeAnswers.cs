using System.Net;
using System.Threading.Tasks;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;
using Xunit;

namespace DnsServerCore.Tests
{
    public sealed class Rfc1035AuthoritativeAnswers : IClassFixture<DnsServerFixture>
    {
        readonly DnsServerFixture _dns;

        public Rfc1035AuthoritativeAnswers(DnsServerFixture dns)
        {
            _dns = dns;
        }

        [Fact]
        public async Task ExactNameReturnsTheAddress()
        {
            const string zone = "exact.example";
            _dns.CreateZone(zone);
            _dns.Add(zone, "www." + zone, DnsResourceRecordType.A, new DnsARecordData(IPAddress.Parse("192.0.2.1")));

            DnsDatagram response = await _dns.QueryAsync("www." + zone, DnsResourceRecordType.A);

            Assert.Equal(DnsResponseCode.NoError, response.RCODE);
            Assert.True(response.AuthoritativeAnswer, DnsTest.Describe(response));

            DnsResourceRecord answer = DnsTest.Find(response.Answer, DnsResourceRecordType.A, "www." + zone);
            Assert.NotNull(answer);
            Assert.Equal(IPAddress.Parse("192.0.2.1"), ((DnsARecordData)answer.RDATA).Address);
        }

        [Fact]
        public async Task CnameIsFollowedInsideTheZone()
        {
            const string zone = "cname.example";
            _dns.CreateZone(zone);
            _dns.Set(zone, "www." + zone, DnsResourceRecordType.CNAME, new DnsCNAMERecordData("target." + zone));
            _dns.Add(zone, "target." + zone, DnsResourceRecordType.A, new DnsARecordData(IPAddress.Parse("192.0.2.2")));

            DnsDatagram response = await _dns.QueryAsync("www." + zone, DnsResourceRecordType.A);

            Assert.Equal(DnsResponseCode.NoError, response.RCODE);
            Assert.True(response.AuthoritativeAnswer, DnsTest.Describe(response));

            DnsResourceRecord cname = DnsTest.Find(response.Answer, DnsResourceRecordType.CNAME, "www." + zone);
            Assert.NotNull(cname);
            Assert.Equal("target." + zone, ((DnsCNAMERecordData)cname.RDATA).Domain, ignoreCase: true);

            DnsResourceRecord address = DnsTest.Find(response.Answer, DnsResourceRecordType.A, "target." + zone);
            Assert.NotNull(address);
            Assert.Equal(IPAddress.Parse("192.0.2.2"), ((DnsARecordData)address.RDATA).Address);
        }

        [Fact]
        public async Task NameWithAnotherTypeIsNodata()
        {
            const string zone = "nodata.example";
            _dns.CreateZone(zone);
            _dns.Add(zone, "www." + zone, DnsResourceRecordType.AAAA, new DnsAAAARecordData(IPAddress.Parse("2001:db8::1")));

            DnsDatagram response = await _dns.QueryAsync("www." + zone, DnsResourceRecordType.A);

            Assert.Equal(DnsResponseCode.NoError, response.RCODE);
            Assert.True(response.AuthoritativeAnswer, DnsTest.Describe(response));
            Assert.Null(DnsTest.Find(response.Answer, DnsResourceRecordType.A));
            Assert.NotNull(DnsTest.Find(response.Authority, DnsResourceRecordType.SOA, zone));
        }

        [Fact]
        public async Task MissingNameIsNxDomain()
        {
            const string zone = "missing.example";
            _dns.CreateZone(zone);

            DnsDatagram response = await _dns.QueryAsync("gone." + zone, DnsResourceRecordType.A);

            Assert.Equal(DnsResponseCode.NxDomain, response.RCODE);
            Assert.True(response.AuthoritativeAnswer, DnsTest.Describe(response));
            Assert.Empty(response.Answer);
            Assert.NotNull(DnsTest.Find(response.Authority, DnsResourceRecordType.SOA, zone));
        }

        [Fact]
        public async Task EmptyNonTerminalIsNodata()
        {
            const string zone = "ent.example";
            _dns.CreateZone(zone);
            _dns.Add(zone, "a.b." + zone, DnsResourceRecordType.A, new DnsARecordData(IPAddress.Parse("192.0.2.3")));

            DnsDatagram response = await _dns.QueryAsync("b." + zone, DnsResourceRecordType.A);

            Assert.Equal(DnsResponseCode.NoError, response.RCODE);
            Assert.True(response.AuthoritativeAnswer, DnsTest.Describe(response));
            Assert.Null(DnsTest.Find(response.Answer, DnsResourceRecordType.A));
            Assert.NotNull(DnsTest.Find(response.Authority, DnsResourceRecordType.SOA, zone));
        }

        [Fact]
        public async Task NameBelowAnNsCutIsAReferral()
        {
            const string zone = "referral.example";
            _dns.CreateZone(zone);
            _dns.Add(zone, "delegated." + zone, DnsResourceRecordType.NS, new DnsNSRecordData("ns1.example.net"));

            DnsDatagram response = await _dns.QueryAsync("host.delegated." + zone, DnsResourceRecordType.A);

            Assert.Equal(DnsResponseCode.NoError, response.RCODE);
            Assert.False(response.AuthoritativeAnswer, DnsTest.Describe(response));
            Assert.Empty(response.Answer);

            DnsResourceRecord ns = DnsTest.Find(response.Authority, DnsResourceRecordType.NS, "delegated." + zone);
            Assert.NotNull(ns);
            Assert.Equal("ns1.example.net", ((DnsNSRecordData)ns.RDATA).NameServer, ignoreCase: true);
        }
    }
}
