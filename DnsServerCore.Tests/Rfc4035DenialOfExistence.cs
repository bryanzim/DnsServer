using DnsServerCore.Dns.Dnssec;
using System.Net;
using System.Threading.Tasks;
using TechnitiumLibrary.Net.Dns;
using DnsResponseCode = TechnitiumLibrary.Net.Dns.DnsResponseCode;
using TechnitiumLibrary.Net.Dns.ResourceRecords;
using Xunit;

namespace DnsServerCore.Tests
{
    public sealed class Rfc4035DenialOfExistence : IClassFixture<DnsServerFixture>
    {
        readonly DnsServerFixture _dns;

        public Rfc4035DenialOfExistence(DnsServerFixture dns)
        {
            _dns = dns;
        }

        [Fact]
        public async Task NsecProvesNxDomainNodataAndAnEmptyNonTerminal()
        {
            const string zone = "nsec.example";
            _dns.CreateZone(zone);
            _dns.Add(zone, "www." + zone, DnsResourceRecordType.A, new DnsARecordData(IPAddress.Parse("192.0.2.50")));
            _dns.Add(zone, "a.b." + zone, DnsResourceRecordType.A, new DnsARecordData(IPAddress.Parse("192.0.2.51")));
            Sign(zone, false);

            DnsDatagram missing = await _dns.QueryAsync("gone." + zone, DnsResourceRecordType.A, true);
            Assert.Equal(DnsResponseCode.NxDomain, missing.RCODE);
            Assert.True(DnsTest.ContainsType(missing.Authority, DnsResourceRecordType.NSEC), DnsTest.Describe(missing));

            DnsDatagram nodata = await _dns.QueryAsync("www." + zone, DnsResourceRecordType.AAAA, true);
            Assert.Equal(DnsResponseCode.NoError, nodata.RCODE);
            Assert.Null(DnsTest.Find(nodata.Answer, DnsResourceRecordType.AAAA));
            Assert.True(DnsTest.ContainsType(nodata.Authority, DnsResourceRecordType.NSEC), DnsTest.Describe(nodata));

            DnsDatagram empty = await _dns.QueryAsync("b." + zone, DnsResourceRecordType.A, true);
            Assert.Equal(DnsResponseCode.NoError, empty.RCODE);
            Assert.Null(DnsTest.Find(empty.Answer, DnsResourceRecordType.A));
            Assert.True(DnsTest.ContainsType(empty.Authority, DnsResourceRecordType.NSEC), DnsTest.Describe(empty));
        }

        [Fact]
        public async Task Nsec3ProvesNxDomainAndAnEmptyNonTerminal()
        {
            const string zone = "nsec3.example";
            _dns.CreateZone(zone);
            _dns.Add(zone, "www." + zone, DnsResourceRecordType.A, new DnsARecordData(IPAddress.Parse("192.0.2.52")));
            _dns.Add(zone, "a.b." + zone, DnsResourceRecordType.A, new DnsARecordData(IPAddress.Parse("192.0.2.53")));
            Sign(zone, true);

            DnsDatagram missing = await _dns.QueryAsync("gone." + zone, DnsResourceRecordType.A, true);
            Assert.Equal(DnsResponseCode.NxDomain, missing.RCODE);
            Assert.True(DnsTest.ContainsType(missing.Authority, DnsResourceRecordType.NSEC3), DnsTest.Describe(missing));

            DnsDatagram empty = await _dns.QueryAsync("b." + zone, DnsResourceRecordType.A, true);
            Assert.Equal(DnsResponseCode.NoError, empty.RCODE);
            Assert.Null(DnsTest.Find(empty.Answer, DnsResourceRecordType.A));
            Assert.True(DnsTest.ContainsType(empty.Authority, DnsResourceRecordType.NSEC3), DnsTest.Describe(empty));
        }

        [Fact]
        public async Task NameThatMovesToAChildZoneIsNotProvenByTheParent()
        {
            await AssertChildZoneDropsTheParentProof("parent-nsec.example", false);
            await AssertChildZoneDropsTheParentProof("parent-nsec3.example", true);
        }

        async Task AssertChildZoneDropsTheParentProof(string zone, bool nsec3)
        {
            _dns.CreateZone(zone);
            _dns.Add(zone, "www.child." + zone, DnsResourceRecordType.A, new DnsARecordData(IPAddress.Parse("192.0.2.54")));
            Sign(zone, nsec3);

            Assert.NotNull(_dns.CreateZone("child." + zone));

            DnsDatagram moved = await _dns.QueryAsync("www.child." + zone, DnsResourceRecordType.A, true);
            Assert.Equal(DnsResponseCode.NoError, moved.RCODE);
            DnsResourceRecord address = DnsTest.Find(moved.Answer, DnsResourceRecordType.A, "www.child." + zone);
            Assert.NotNull(address);
            Assert.Equal(IPAddress.Parse("192.0.2.54"), ((DnsARecordData)address.RDATA).Address);

            DnsDatagram gone = await _dns.QueryAsync("gone.child." + zone, DnsResourceRecordType.A, true);
            Assert.Equal(DnsResponseCode.NxDomain, gone.RCODE);
            Assert.NotNull(DnsTest.Find(gone.Authority, DnsResourceRecordType.SOA, "child." + zone));
            Assert.Null(DnsTest.Find(gone.Authority, DnsResourceRecordType.SOA, zone));
        }

        void Sign(string zone, bool nsec3)
        {
            DnssecPrivateKey ksk = DnssecPrivateKey.Create(DnssecAlgorithm.ED25519, DnssecPrivateKeyType.KeySigningKey);
            DnssecPrivateKey zsk = DnssecPrivateKey.Create(DnssecAlgorithm.ED25519, DnssecPrivateKeyType.ZoneSigningKey);
            _dns.Server.AuthZoneManager.SignPrimaryZone(zone, ksk, zsk, 3600, nsec3);
        }
    }
}
