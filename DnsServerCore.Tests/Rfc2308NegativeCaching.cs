using System.Net;
using System.Threading.Tasks;
using TechnitiumLibrary.Net.Dns;
using DnsResponseCode = TechnitiumLibrary.Net.Dns.DnsResponseCode;
using TechnitiumLibrary.Net.Dns.ResourceRecords;
using Xunit;

namespace DnsServerCore.Tests
{
    public sealed class Rfc2308NegativeCaching : IClassFixture<DnsServerFixture>
    {
        readonly DnsServerFixture _dns;

        public Rfc2308NegativeCaching(DnsServerFixture dns)
        {
            _dns = dns;
        }

        [Fact]
        public async Task NegativeSoaTtlIsTheMinimumOfTheRecordAndTheMinimumField()
        {
            const string zone = "negative-ttl.example";
            _dns.CreateZone(zone);
            SetSoa(zone, 7200, 60);
            _dns.Add(zone, "www." + zone, DnsResourceRecordType.A, new DnsARecordData(IPAddress.Parse("192.0.2.80")));

            DnsDatagram soa = await _dns.QueryAsync(zone, DnsResourceRecordType.SOA);
            Assert.Equal(7200u, DnsTest.Find(soa.Answer, DnsResourceRecordType.SOA, zone).TTL);

            DnsDatagram missing = await _dns.QueryAsync("gone." + zone, DnsResourceRecordType.A);
            Assert.Equal(DnsResponseCode.NxDomain, missing.RCODE);
            Assert.Equal(60u, DnsTest.Find(missing.Authority, DnsResourceRecordType.SOA, zone).TTL);

            DnsDatagram nodata = await _dns.QueryAsync("www." + zone, DnsResourceRecordType.AAAA);
            Assert.Equal(DnsResponseCode.NoError, nodata.RCODE);
            Assert.Empty(nodata.Answer);
            Assert.Equal(60u, DnsTest.Find(nodata.Authority, DnsResourceRecordType.SOA, zone).TTL);
        }

        [Fact]
        public async Task NegativeSoaTtlStaysAtTheRecordTtlWhenItIsLower()
        {
            const string zone = "negative-ttl-low.example";
            _dns.CreateZone(zone);
            SetSoa(zone, 30, 60);

            DnsDatagram missing = await _dns.QueryAsync("gone." + zone, DnsResourceRecordType.A);

            Assert.Equal(DnsResponseCode.NxDomain, missing.RCODE);
            Assert.Equal(30u, DnsTest.Find(missing.Authority, DnsResourceRecordType.SOA, zone).TTL);
        }

        void SetSoa(string zone, uint ttl, uint minimum)
        {
            DnsSOARecordData current = (DnsSOARecordData)_dns.Server.AuthZoneManager.GetRecords(zone, zone, DnsResourceRecordType.SOA)[0].RDATA;
            _dns.Set(zone, zone, DnsResourceRecordType.SOA, new DnsSOARecordData(current.PrimaryNameServer, current.ResponsiblePerson, current.Serial, current.Refresh, current.Retry, current.Expire, minimum), ttl);
        }
    }
}
