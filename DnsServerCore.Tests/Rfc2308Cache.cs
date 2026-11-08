using System.Collections.Generic;
using System.Net;
using System.Threading.Tasks;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;
using Xunit;

namespace DnsServerCore.Tests
{
    public sealed class Rfc2308Cache : IClassFixture<DnsServerFixture>
    {
        readonly DnsServerFixture _dns;

        public Rfc2308Cache(DnsServerFixture dns)
        {
            _dns = dns;
        }

        [Fact]
        public void NegativeAnswerIsServedFromCache()
        {
            const string name = "gone.negative.example";
            DnsResourceRecord soa = new DnsResourceRecord("negative.example", DnsResourceRecordType.SOA, DnsClass.IN, 60, new DnsSOARecordData("ns.example", "hostadmin.negative.example", 1, 900, 300, 86400, 60));
            DnsDatagram response = Response(name, DnsResourceRecordType.A, DnsResponseCode.NxDomain, null, [soa]);

            _dns.Server.CacheZoneManager.CacheResponse(response);

            DnsDatagram cached = _dns.Server.CacheZoneManager.Query(Question(name, DnsResourceRecordType.A), false);
            Assert.NotNull(cached);
            Assert.Equal(DnsResponseCode.NxDomain, cached.RCODE);
        }

        [Fact]
        public async Task StaleAnswerIsServedOnlyInsideTheWindow()
        {
            const string name = "www.stale.example";
            _dns.Server.CacheZoneManager.ServeStaleTtl = 3600;

            DnsResourceRecord address = new DnsResourceRecord(name, DnsResourceRecordType.A, DnsClass.IN, 30, new DnsARecordData(IPAddress.Parse("192.0.2.60")));
            _dns.Server.CacheZoneManager.CacheResponse(Response(name, DnsResourceRecordType.A, DnsResponseCode.NoError, [address], null));

            List<DnsResourceRecord> stored = new List<DnsResourceRecord>();
            _dns.Server.CacheZoneManager.ListAllRecords(name, stored);
            Assert.NotEmpty(stored);

            foreach (DnsResourceRecord record in stored)
                record.ResetExpiry(0);

            await Task.Delay(100);

            DnsDatagram fresh = _dns.Server.CacheZoneManager.Query(Question(name, DnsResourceRecordType.A), false);
            Assert.Null(fresh);

            DnsDatagram stale = _dns.Server.CacheZoneManager.Query(Question(name, DnsResourceRecordType.A), true);
            Assert.NotNull(stale);
            DnsResourceRecord answer = DnsTest.Find(stale.Answer, DnsResourceRecordType.A, name);
            Assert.NotNull(answer);
            Assert.Equal(IPAddress.Parse("192.0.2.60"), ((DnsARecordData)answer.RDATA).Address);
        }

        [Fact]
        public void FailureAnswerIsServedFromCache()
        {
            const string name = "broken.failure.example";
            _dns.Server.CacheZoneManager.CacheResponse(Response(name, DnsResourceRecordType.A, DnsResponseCode.ServerFailure, null, null));

            DnsDatagram cached = _dns.Server.CacheZoneManager.Query(Question(name, DnsResourceRecordType.A), false);
            Assert.NotNull(cached);
            Assert.Equal(DnsResponseCode.ServerFailure, cached.RCODE);
        }

        static DnsDatagram Question(string name, DnsResourceRecordType type)
        {
            return new DnsDatagram(0, false, DnsOpcode.StandardQuery, false, false, false, false, false, false, DnsResponseCode.NoError, [new DnsQuestionRecord(name, type, DnsClass.IN)]);
        }

        static DnsDatagram Response(string name, DnsResourceRecordType type, DnsResponseCode rcode, IReadOnlyList<DnsResourceRecord> answer, IReadOnlyList<DnsResourceRecord> authority)
        {
            return new DnsDatagram(0, true, DnsOpcode.StandardQuery, true, false, false, true, false, false, rcode, [new DnsQuestionRecord(name, type, DnsClass.IN)], answer, authority);
        }
    }
}
