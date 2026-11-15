using System.Net;
using DnsServerCore.Dns.Zones;
using TechnitiumLibrary.Net.Dns;
using DnsResponseCode = TechnitiumLibrary.Net.Dns.DnsResponseCode;
using TechnitiumLibrary.Net.Dns.ResourceRecords;
using Xunit;

namespace DnsServerCore.Tests
{
    public sealed class ZoneQueryAccess : IClassFixture<DnsServerFixture>
    {
        readonly DnsServerFixture _dns;

        public ZoneQueryAccess(DnsServerFixture dns)
        {
            _dns = dns;
        }

        [Fact]
        public async System.Threading.Tasks.Task UnspecifiedAddressIsNotLoopback()
        {
            const string zone = "query-access.example";
            _dns.CreateZone(zone).QueryAccess = AuthZoneQueryAccess.Deny;
            _dns.Add(zone, "www." + zone, DnsResourceRecordType.A, new DnsARecordData(IPAddress.Parse("192.0.2.40")));

            DnsDatagram internalResponse = await _dns.QueryAsync("www." + zone, DnsResourceRecordType.A);
            Assert.Equal(DnsResponseCode.NoError, internalResponse.RCODE);
            Assert.NotNull(DnsTest.Find(internalResponse.Answer, DnsResourceRecordType.A, "www." + zone));

            DnsDatagram request = new DnsDatagram(1, false, DnsOpcode.StandardQuery, false, false, true, false, false, false, DnsResponseCode.NoError, [new DnsQuestionRecord("www." + zone, DnsResourceRecordType.A, DnsClass.IN)]);
            DnsDatagram unspecified = await _dns.Server.DirectQueryAsync(request, new IPEndPoint(IPAddress.Any, 53), 10000);
            Assert.Equal(DnsResponseCode.Refused, unspecified.RCODE);

            DnsDatagram remote = await _dns.Server.DirectQueryAsync(request, new IPEndPoint(IPAddress.Parse("203.0.113.9"), 53), 10000);
            Assert.Equal(DnsResponseCode.Refused, remote.RCODE);
        }
    }
}
