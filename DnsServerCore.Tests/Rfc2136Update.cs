using DnsServerCore.Dns.Zones;
using System.Net;
using System.Threading.Tasks;
using TechnitiumLibrary.Net.Dns;
using DnsResponseCode = TechnitiumLibrary.Net.Dns.DnsResponseCode;
using TechnitiumLibrary.Net.Dns.ResourceRecords;
using Xunit;

namespace DnsServerCore.Tests
{
    public sealed class Rfc2136Update : IClassFixture<DnsServerFixture>
    {
        readonly DnsServerFixture _dns;

        public Rfc2136Update(DnsServerFixture dns)
        {
            _dns = dns;
        }

        [Fact]
        public async Task DeniedUpdateIsRefused()
        {
            const string zone = "deny-update.example";
            _dns.CreateZone(zone);

            DnsDatagram response = await _dns.QueryAsync(Update(zone, null, AddA("www." + zone, "192.0.2.30")));

            Assert.Equal(DnsResponseCode.Refused, response.RCODE);

            DnsDatagram lookup = await _dns.QueryAsync("www." + zone, DnsResourceRecordType.A);
            Assert.Equal(DnsResponseCode.NxDomain, lookup.RCODE);
        }

        [Fact]
        public async Task PrerequisiteMatchAddsTheRecord()
        {
            const string zone = "allow-update.example";
            _dns.CreateZone(zone).Update = AuthZoneUpdate.Allow;
            _dns.Add(zone, "www." + zone, DnsResourceRecordType.A, new DnsARecordData(IPAddress.Parse("192.0.2.31")));

            DnsResourceRecord prerequisite = DnsTest.Record("www." + zone, DnsResourceRecordType.ANY, DnsClass.ANY, 0, new DnsUnknownRecordData([]));
            DnsResourceRecord added = DnsTest.Record("www." + zone, DnsResourceRecordType.AAAA, DnsClass.IN, 300, new DnsAAAARecordData(IPAddress.Parse("2001:db8::31")));
            DnsDatagram response = await _dns.QueryAsync(Update(zone, prerequisite, added));

            Assert.Equal(DnsResponseCode.NoError, response.RCODE);

            DnsDatagram lookup = await _dns.QueryAsync("www." + zone, DnsResourceRecordType.AAAA);
            DnsResourceRecord answer = DnsTest.Find(lookup.Answer, DnsResourceRecordType.AAAA, "www." + zone);
            Assert.NotNull(answer);
            Assert.Equal(IPAddress.Parse("2001:db8::31"), ((DnsAAAARecordData)answer.RDATA).Address);
        }

        [Fact]
        public async Task MissingNamePrerequisiteRejectsTheUpdate()
        {
            const string zone = "prereq-update.example";
            _dns.CreateZone(zone).Update = AuthZoneUpdate.Allow;

            DnsResourceRecord prerequisite = DnsTest.Record("missing." + zone, DnsResourceRecordType.ANY, DnsClass.ANY, 0, new DnsUnknownRecordData([]));
            DnsDatagram response = await _dns.QueryAsync(Update(zone, prerequisite, AddA("missing." + zone, "192.0.2.32")));

            Assert.Equal(DnsResponseCode.NxDomain, response.RCODE);

            DnsDatagram lookup = await _dns.QueryAsync("missing." + zone, DnsResourceRecordType.A);
            Assert.Equal(DnsResponseCode.NxDomain, lookup.RCODE);
        }

        static DnsDatagram Update(string zone, DnsResourceRecord prerequisite, DnsResourceRecord update)
        {
            // RDLENGTH is filled in when the record is written. The update checks read that length.
            DnsDatagram message = new DnsDatagram(1, false, DnsOpcode.Update, false, false, false, false, false, false, DnsResponseCode.NoError, [new DnsQuestionRecord(zone, DnsResourceRecordType.SOA, DnsClass.IN)], prerequisite is null ? null : [prerequisite], [update]);
            return DnsTest.RoundTrip(message);
        }

        static DnsResourceRecord AddA(string name, string address)
        {
            return DnsTest.Record(name, DnsResourceRecordType.A, DnsClass.IN, 300, new DnsARecordData(IPAddress.Parse(address)));
        }
    }
}
