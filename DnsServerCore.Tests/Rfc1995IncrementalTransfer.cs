using DnsServerCore.Dns.Zones;
using System.Collections.Generic;
using System.Net;
using System.Threading.Tasks;
using TechnitiumLibrary.Net.Dns;
using DnsResponseCode = TechnitiumLibrary.Net.Dns.DnsResponseCode;
using TechnitiumLibrary.Net.Dns.EDnsOptions;
using TechnitiumLibrary.Net.Dns.ResourceRecords;
using Xunit;

namespace DnsServerCore.Tests
{
    public sealed class Rfc1995IncrementalTransfer : IClassFixture<DnsServerFixture>
    {
        readonly DnsServerFixture _dns;

        public Rfc1995IncrementalTransfer(DnsServerFixture dns)
        {
            _dns = dns;
        }

        [Fact]
        public void SerialWrapUsesSequenceSpaceArithmetic()
        {
            Assert.True(DnsSOARecordData.IsZoneUpdateAvailable(0xfffffff0u, 0x10u));
            Assert.True(DnsSOARecordData.IsZoneUpdateAvailable(uint.MaxValue, 1u));
            Assert.True(DnsSOARecordData.IsZoneUpdateAvailable(10u, 11u));
            Assert.False(DnsSOARecordData.IsZoneUpdateAvailable(10u, 9u));
            Assert.False(DnsSOARecordData.IsZoneUpdateAvailable(1u, 1u));
            Assert.False(DnsSOARecordData.IsZoneUpdateAvailable(1u, (1u << 31) + 2u));
        }

        [Fact]
        public async Task IxfrReturnsTheDeltaAndThenOnlyTheCurrentSoa()
        {
            const string zone = "ixfr.example";
            AuthZoneInfo info = _dns.CreateZone(zone);
            info.ZoneTransfer = AuthZoneTransfer.Allow;

            DnsResourceRecord before = _dns.Server.AuthZoneManager.GetRecords(zone, zone, DnsResourceRecordType.SOA)[0];
            uint oldSerial = ((DnsSOARecordData)before.RDATA).Serial;
            DnsResourceRecord clientSoa = CopySoa(before);

            _dns.Add(zone, "www." + zone, DnsResourceRecordType.A, new DnsARecordData(IPAddress.Parse("192.0.2.40")));

            DnsResourceRecord after = _dns.Server.AuthZoneManager.GetRecords(zone, zone, DnsResourceRecordType.SOA)[0];
            uint newSerial = ((DnsSOARecordData)after.RDATA).Serial;
            Assert.True(DnsSOARecordData.IsZoneUpdateAvailable(oldSerial, newSerial));

            DnsDatagram delta = await _dns.QueryAsync(Ixfr(zone, clientSoa, true));
            Assert.Equal(DnsResponseCode.NoError, delta.RCODE);

            List<DnsResourceRecord> answers = DnsTest.AllAnswers(delta);
            Assert.NotNull(DnsTest.Find(answers, DnsResourceRecordType.A, "www." + zone));
            Assert.NotNull(FindSoa(answers, oldSerial));
            Assert.NotNull(FindSoa(answers, newSerial));

            EDnsExpireOptionData expire = FindExpire(delta);
            Assert.NotNull(expire);
            Assert.Equal(((DnsSOARecordData)after.RDATA).Expire, expire.Expire);

            DnsDatagram current = await _dns.QueryAsync(Ixfr(zone, CopySoa(after), false));
            List<DnsResourceRecord> currentAnswers = DnsTest.AllAnswers(current);
            Assert.Equal(DnsResponseCode.NoError, current.RCODE);
            Assert.Single(currentAnswers);
            Assert.Equal(newSerial, ((DnsSOARecordData)currentAnswers[0].RDATA).Serial);
        }

        static DnsDatagram Ixfr(string zone, DnsResourceRecord clientSoa, bool askExpire)
        {
            // A secondary refresh needs a peer. The primary still answers EXPIRE when the request asks.
            IReadOnlyList<EDnsOption> options = askExpire ? [new EDnsOption(EDnsOptionCode.EDNS_EXPIRE, new EDnsExpireOptionData((uint?)null))] : null;
            return new DnsDatagram(1, false, DnsOpcode.StandardQuery, false, false, false, false, false, false, DnsResponseCode.NoError, [new DnsQuestionRecord(zone, DnsResourceRecordType.IXFR, DnsClass.IN)], null, [clientSoa], udpPayloadSize: 1232, options: options);
        }

        static DnsResourceRecord CopySoa(DnsResourceRecord soa)
        {
            DnsSOARecordData data = (DnsSOARecordData)soa.RDATA;
            return new DnsResourceRecord(soa.Name, DnsResourceRecordType.SOA, DnsClass.IN, soa.TTL, new DnsSOARecordData(data.PrimaryNameServer, data.ResponsiblePerson, data.Serial, data.Refresh, data.Retry, data.Expire, data.Minimum));
        }

        static DnsResourceRecord FindSoa(IReadOnlyList<DnsResourceRecord> records, uint serial)
        {
            foreach (DnsResourceRecord record in records)
            {
                if ((record.Type == DnsResourceRecordType.SOA) && (((DnsSOARecordData)record.RDATA).Serial == serial))
                    return record;
            }

            return null;
        }

        static EDnsExpireOptionData FindExpire(DnsDatagram response)
        {
            if ((response.EDNS is null) || (response.EDNS.Options is null))
                return null;

            foreach (EDnsOption option in response.EDNS.Options)
            {
                if (option.Code == EDnsOptionCode.EDNS_EXPIRE)
                    return option.Data as EDnsExpireOptionData;
            }

            return null;
        }
    }
}
