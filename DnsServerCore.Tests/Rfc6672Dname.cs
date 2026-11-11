using System.Net;
using System.Threading.Tasks;
using TechnitiumLibrary.Net.Dns;
using DnsResponseCode = TechnitiumLibrary.Net.Dns.DnsResponseCode;
using TechnitiumLibrary.Net.Dns.ResourceRecords;
using Xunit;

namespace DnsServerCore.Tests
{
    public sealed class Rfc6672Dname : IClassFixture<DnsServerFixture>
    {
        readonly DnsServerFixture _dns;

        public Rfc6672Dname(DnsServerFixture dns)
        {
            _dns = dns;
        }

        [Fact]
        public async Task DnameSynthesizesACname()
        {
            const string zone = "dname.example";
            _dns.CreateZone(zone);
            _dns.Set(zone, "src." + zone, DnsResourceRecordType.DNAME, new DnsDNAMERecordData("dst." + zone));
            _dns.Add(zone, "www.dst." + zone, DnsResourceRecordType.A, new DnsARecordData(IPAddress.Parse("192.0.2.70")));

            DnsDatagram response = await _dns.QueryAsync("www.src." + zone, DnsResourceRecordType.A);

            Assert.Equal(DnsResponseCode.NoError, response.RCODE);

            DnsResourceRecord dname = DnsTest.Find(response.Answer, DnsResourceRecordType.DNAME, "src." + zone);
            Assert.NotNull(dname);
            Assert.Equal("dst." + zone, ((DnsDNAMERecordData)dname.RDATA).Domain, ignoreCase: true);

            DnsResourceRecord cname = DnsTest.Find(response.Answer, DnsResourceRecordType.CNAME, "www.src." + zone);
            Assert.NotNull(cname);
            Assert.Equal("www.dst." + zone, ((DnsCNAMERecordData)cname.RDATA).Domain, ignoreCase: true);

            DnsResourceRecord address = DnsTest.Find(response.Answer, DnsResourceRecordType.A, "www.dst." + zone);
            Assert.NotNull(address);
            Assert.Equal(IPAddress.Parse("192.0.2.70"), ((DnsARecordData)address.RDATA).Address);
        }
    }
}
