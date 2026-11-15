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

        [Fact]
        public async Task CnameBesideAnotherTypeIsYxRrSet()
        {
            const string zone = "yxrrset-update.example";
            const string name = "www." + zone;
            _dns.CreateZone(zone).Update = AuthZoneUpdate.Allow;
            _dns.Add(zone, name, DnsResourceRecordType.A, new DnsARecordData(IPAddress.Parse("192.0.2.33")));

            DnsResourceRecord cname = DnsTest.Record(name, DnsResourceRecordType.CNAME, DnsClass.IN, 300, new DnsCNAMERecordData("other.example"));
            DnsDatagram response = await _dns.QueryAsync(Update(zone, null, cname));

            Assert.Equal(DnsResponseCode.YXRRSet, response.RCODE);

            DnsDatagram lookup = await _dns.QueryAsync(name, DnsResourceRecordType.A);
            Assert.NotNull(DnsTest.Find(lookup.Answer, DnsResourceRecordType.A, name));
            Assert.Null(DnsTest.Find(lookup.Answer, DnsResourceRecordType.CNAME));
        }

        [Fact]
        public async Task MissingRrSetPrerequisiteIsNxRrSet()
        {
            const string zone = "nxrrset-update.example";
            const string name = "www." + zone;
            _dns.CreateZone(zone).Update = AuthZoneUpdate.Allow;
            _dns.Add(zone, name, DnsResourceRecordType.A, new DnsARecordData(IPAddress.Parse("192.0.2.34")));

            DnsResourceRecord prerequisite = DnsTest.Record(name, DnsResourceRecordType.AAAA, DnsClass.ANY, 0, new DnsUnknownRecordData([]));
            DnsDatagram response = await _dns.QueryAsync(Update(zone, prerequisite, AddA(name, "192.0.2.35")));

            DnsDatagram lookup = await _dns.QueryAsync(name, DnsResourceRecordType.A);
            Assert.Equal(IPAddress.Parse("192.0.2.34"), ((DnsARecordData)DnsTest.Find(lookup.Answer, DnsResourceRecordType.A, name).RDATA).Address);
        }

        [Fact]
        public async Task NameInUsePrerequisiteIsYxDomain()
        {
            const string zone = "yxdomain-update.example";
            const string name = "www." + zone;
            _dns.CreateZone(zone).Update = AuthZoneUpdate.Allow;
            _dns.Add(zone, name, DnsResourceRecordType.A, new DnsARecordData(IPAddress.Parse("192.0.2.36")));

            DnsResourceRecord prerequisite = DnsTest.Record(name, DnsResourceRecordType.ANY, DnsClass.NONE, 0, new DnsUnknownRecordData([]));
            DnsDatagram response = await _dns.QueryAsync(Update(zone, prerequisite, AddA("other." + zone, "192.0.2.37")));

            Assert.Equal(DnsResponseCode.YXDomain, response.RCODE);

            DnsDatagram lookup = await _dns.QueryAsync("other." + zone, DnsResourceRecordType.A);
            Assert.Equal(DnsResponseCode.NxDomain, lookup.RCODE);
        }

        [Fact]
        public async Task DeletingAnRrSetRemovesTheName()
        {
            const string zone = "delete-rrset.example";
            const string name = "www." + zone;
            _dns.CreateZone(zone).Update = AuthZoneUpdate.Allow;
            _dns.Add(zone, name, DnsResourceRecordType.A, new DnsARecordData(IPAddress.Parse("192.0.2.38")));

            DnsResourceRecord delete = DnsTest.Record(name, DnsResourceRecordType.A, DnsClass.ANY, 0, new DnsUnknownRecordData([]));
            DnsDatagram response = await _dns.QueryAsync(Update(zone, null, delete));

            Assert.Equal(DnsResponseCode.NoError, response.RCODE);

            DnsDatagram lookup = await _dns.QueryAsync(name, DnsResourceRecordType.A);
            Assert.Equal(DnsResponseCode.NxDomain, lookup.RCODE);
        }

        [Fact]
        public async Task DeletingTheOnlyApexNameServerIsIgnored()
        {
            const string zone = "keep-ns.example";
            _dns.CreateZone(zone).Update = AuthZoneUpdate.Allow;

            DnsDatagram before = await _dns.QueryAsync(zone, DnsResourceRecordType.NS);
            DnsResourceRecord ns = DnsTest.Find(before.Answer, DnsResourceRecordType.NS, zone);
            Assert.NotNull(ns);

            DnsResourceRecord delete = DnsTest.Record(zone, DnsResourceRecordType.NS, DnsClass.NONE, 0, ns.RDATA);
            DnsDatagram response = await _dns.QueryAsync(Update(zone, null, delete));

            Assert.Equal(DnsResponseCode.NoError, response.RCODE);

            DnsDatagram after = await _dns.QueryAsync(zone, DnsResourceRecordType.NS);
            Assert.NotNull(DnsTest.Find(after.Answer, DnsResourceRecordType.NS, zone));
        }

        [Fact]
        public async Task DeletingTheSoaIsIgnored()
        {
            const string zone = "keep-soa.example";
            _dns.CreateZone(zone).Update = AuthZoneUpdate.Allow;

            DnsDatagram before = await _dns.QueryAsync(zone, DnsResourceRecordType.SOA);
            DnsResourceRecord soa = DnsTest.Find(before.Answer, DnsResourceRecordType.SOA, zone);
            Assert.NotNull(soa);

            DnsResourceRecord delete = DnsTest.Record(zone, DnsResourceRecordType.SOA, DnsClass.NONE, 0, soa.RDATA);
            DnsDatagram response = await _dns.QueryAsync(Update(zone, null, delete));

            Assert.Equal(DnsResponseCode.NoError, response.RCODE);

            DnsDatagram after = await _dns.QueryAsync(zone, DnsResourceRecordType.SOA);
            Assert.NotNull(DnsTest.Find(after.Answer, DnsResourceRecordType.SOA, zone));
        }

        [Fact]
        public async Task DnameBesideANameServerIsYxRrSet()
        {
            const string zone = "dname-ns-update.example";
            const string name = "del." + zone;
            _dns.CreateZone(zone).Update = AuthZoneUpdate.Allow;
            _dns.Add(zone, name, DnsResourceRecordType.NS, new DnsNSRecordData("ns1.example.net"));

            DnsResourceRecord dname = DnsTest.Record(name, DnsResourceRecordType.DNAME, DnsClass.IN, 300, new DnsDNAMERecordData("dst.example.net"));
            DnsDatagram response = await _dns.QueryAsync(Update(zone, null, dname));

            Assert.Equal(DnsResponseCode.YXRRSet, response.RCODE);
            Assert.NotEmpty(_dns.Server.AuthZoneManager.GetRecords(zone, name, DnsResourceRecordType.NS));
            Assert.Empty(_dns.Server.AuthZoneManager.GetRecords(zone, name, DnsResourceRecordType.DNAME));
        }

        static DnsDatagram Update(string zone, DnsResourceRecord prerequisite, DnsResourceRecord update)
        {
            // RDLENGTH is filled in when the record is written. The update checks read that length.
            return DnsTest.RoundTrip(Message(zone, prerequisite, update));
        }

        static DnsDatagram Message(string zone, DnsResourceRecord prerequisite, DnsResourceRecord update)
        {
            return new DnsDatagram(1, false, DnsOpcode.Update, false, false, false, false, false, false, DnsResponseCode.NoError, [new DnsQuestionRecord(zone, DnsResourceRecordType.SOA, DnsClass.IN)], prerequisite is null ? null : [prerequisite], [update]);
        }

        static DnsResourceRecord AddA(string name, string address)
        {
            return DnsTest.Record(name, DnsResourceRecordType.A, DnsClass.IN, 300, new DnsARecordData(IPAddress.Parse(address)));
        }
    }
}
