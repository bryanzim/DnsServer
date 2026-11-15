using DnsServerCore.ApplicationCommon;
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

        [Fact]
        public async Task AnameNodataUsesTheNegativeSoaTtl()
        {
            const string zone = "negative-ttl-aname.example";
            _dns.CreateZone(zone);
            SetSoa(zone, 7200, 60);
            _dns.Set(zone, "www." + zone, DnsResourceRecordType.ANAME, new DnsANAMERecordData("gone." + zone));

            DnsDatagram address = await _dns.QueryAsync("www." + zone, DnsResourceRecordType.A);

            Assert.Equal(DnsResponseCode.NoError, address.RCODE);
            Assert.True(address.AuthoritativeAnswer);
            Assert.Empty(address.Answer);
            Assert.Equal(60u, DnsTest.Find(address.Authority, DnsResourceRecordType.SOA, zone).TTL);

            DnsDatagram soa = await _dns.QueryAsync(zone, DnsResourceRecordType.SOA);
            Assert.Equal(7200u, DnsTest.Find(soa.Answer, DnsResourceRecordType.SOA, zone).TTL);
        }

        [Fact]
        public async Task AliasNodataUsesTheNegativeSoaTtl()
        {
            const string zone = "negative-ttl-alias.example";
            _dns.CreateZone(zone);
            SetSoa(zone, 7200, 60);
            _dns.Set(zone, "www." + zone, DnsResourceRecordType.ALIAS, new DnsALIASRecordData(DnsResourceRecordType.A, "gone." + zone));

            DnsDatagram address = await _dns.QueryAsync("www." + zone, DnsResourceRecordType.A);

            Assert.Equal(DnsResponseCode.NoError, address.RCODE);
            Assert.True(address.AuthoritativeAnswer);
            Assert.Empty(address.Answer);
            Assert.Equal(60u, DnsTest.Find(address.Authority, DnsResourceRecordType.SOA, zone).TTL);
        }

        [Fact]
        public async Task BlockedAliasNodataUsesTheNegativeSoaTtl()
        {
            const string zone = "negative-ttl-blocked.example";
            string target = "gone." + zone;
            _dns.CreateZone(zone);
            SetSoa(zone, 7200, 60);
            _dns.Set(zone, "www." + zone, DnsResourceRecordType.ANAME, new DnsANAMERecordData(target));
            Assert.True(_dns.Server.BlockedZoneManager.BlockZone(target));

            try
            {
                DnsDatagram address = await _dns.QueryAsync("www." + zone, DnsResourceRecordType.A);

                Assert.Equal(DnsResponseCode.NoError, address.RCODE);
                Assert.False(address.AuthoritativeAnswer);
                Assert.True((address.Answer is null) || (address.Answer.Count == 0));
                Assert.Equal(60u, DnsTest.Find(address.Authority, DnsResourceRecordType.SOA, zone).TTL);
            }
            finally
            {
                _dns.Server.BlockedZoneManager.DeleteZone(target);
            }
        }

        [Fact]
        public async Task AppHandlerDeclineUsesTheNegativeSoaTtl()
        {
            const string zone = "negative-ttl-app.example";
            const string appName = "negative-ttl-app";
            NullAppRecordHandler handler = new NullAppRecordHandler();
            _dns.Server.DnsApplicationManager.InstallRecordHandlerForTests(appName, "NullHandler", handler);
            _dns.CreateZone(zone);
            SetSoa(zone, 7200, 60);
            _dns.Set(zone, "www." + zone, DnsResourceRecordType.APP, new DnsApplicationRecordData(appName, "NullHandler", ""));

            DnsDatagram nodata = await _dns.QueryAsync("www." + zone, DnsResourceRecordType.A);
            Assert.Equal(DnsResponseCode.NoError, nodata.RCODE);
            Assert.True(nodata.AuthoritativeAnswer);
            Assert.True((nodata.Answer is null) || (nodata.Answer.Count == 0));
            Assert.Equal(60u, DnsTest.Find(nodata.Authority, DnsResourceRecordType.SOA, zone).TTL);

            DnsDatagram missing = await _dns.QueryAsync("gone.www." + zone, DnsResourceRecordType.A);
            Assert.Equal(DnsResponseCode.NxDomain, missing.RCODE);
            Assert.True(missing.AuthoritativeAnswer);
            Assert.Equal(60u, DnsTest.Find(missing.Authority, DnsResourceRecordType.SOA, zone).TTL);
            Assert.Equal(2, handler.Calls);

            DnsDatagram soa = await _dns.QueryAsync(zone, DnsResourceRecordType.SOA);
            Assert.Equal(7200u, DnsTest.Find(soa.Answer, DnsResourceRecordType.SOA, zone).TTL);
        }

        [Fact]
        public async Task AppHandlerDeclineOnAForwarderStaysNonAuthoritative()
        {
            const string zone = "negative-ttl-fwd.example";
            const string appName = "negative-ttl-fwd-app";
            NullAppRecordHandler handler = new NullAppRecordHandler();
            _dns.Server.DnsApplicationManager.InstallRecordHandlerForTests(appName, "NullHandler", handler);
            Assert.NotNull(_dns.Server.AuthZoneManager.CreateForwarderZone(zone));
            _dns.Set(zone, "www." + zone, DnsResourceRecordType.APP, new DnsApplicationRecordData(appName, "NullHandler", ""));

            DnsDatagram response = await _dns.QueryAsync("www." + zone, DnsResourceRecordType.A);

            Assert.Equal(1, handler.Calls);
            Assert.Equal(DnsResponseCode.NoError, response.RCODE);
            Assert.False(response.AuthoritativeAnswer);
            Assert.Null(DnsTest.Find(response.Authority, DnsResourceRecordType.SOA));
        }

        void SetSoa(string zone, uint ttl, uint minimum)
        {
            DnsSOARecordData current = (DnsSOARecordData)_dns.Server.AuthZoneManager.GetRecords(zone, zone, DnsResourceRecordType.SOA)[0].RDATA;
            _dns.Set(zone, zone, DnsResourceRecordType.SOA, new DnsSOARecordData(current.PrimaryNameServer, current.ResponsiblePerson, current.Serial, current.Refresh, current.Retry, current.Expire, minimum), ttl);
        }
    }

    sealed class NullAppRecordHandler : IDnsAppRecordRequestHandler
    {
        public int Calls { get; private set; }

        public Task<DnsDatagram> ProcessRequestAsync(DnsDatagram request, IPEndPoint remoteEP, DnsTransportProtocol protocol, bool isRecursionAllowed, string zoneName, string appRecordName, uint appRecordTtl, string appRecordData)
        {
            Calls++;
            return Task.FromResult<DnsDatagram>(null);
        }

        public string ApplicationRecordDataTemplate
        { get { return null; } }
    }
}
