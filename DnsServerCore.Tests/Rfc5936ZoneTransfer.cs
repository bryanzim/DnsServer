using DnsServerCore.Dns.ResourceRecords;
using DnsServerCore.Dns.Zones;
using System.Collections.Generic;
using System.Net;
using TechnitiumLibrary.Net.Dns;
using DnsResponseCode = TechnitiumLibrary.Net.Dns.DnsResponseCode;
using TechnitiumLibrary.Net.Dns.EDnsOptions;
using TechnitiumLibrary.Net.Dns.ResourceRecords;
using Xunit;

namespace DnsServerCore.Tests
{
    // RFC 5936: DNS Zone Transfer Protocol (AXFR)
    // https://www.rfc-editor.org/rfc/rfc5936
    public sealed class Rfc5936ZoneTransfer : IClassFixture<DnsServerFixture>
    {
        readonly DnsServerFixture _dns;

        public Rfc5936ZoneTransfer(DnsServerFixture dns)
        {
            _dns = dns;
        }

        [Fact]
        public async System.Threading.Tasks.Task AxfrBracketsTheZoneAndSendsEachAddressOnce()
        {
            const string zone = "axfr.example";
            AuthZoneInfo info = _dns.CreateZone(zone);
            info.ZoneTransfer = AuthZoneTransfer.Allow;

            string inZoneServer = "ns1." + zone;
            IPAddress inZoneAddress = IPAddress.Parse("192.0.2.10");
            _dns.Add(zone, zone, DnsResourceRecordType.NS, new DnsNSRecordData(inZoneServer));
            _dns.Add(zone, inZoneServer, DnsResourceRecordType.A, new DnsARecordData(inZoneAddress), 60);
            Glue(zone, zone, inZoneServer, "192.0.2.10");

            const string externalServer = "ns.example.net";
            IPAddress externalAddress = IPAddress.Parse("192.0.2.11");
            _dns.Add(zone, zone, DnsResourceRecordType.NS, new DnsNSRecordData(externalServer));
            Glue(zone, zone, externalServer, "192.0.2.11");

            DnsResourceRecord soa = _dns.Server.AuthZoneManager.GetRecords(zone, zone, DnsResourceRecordType.SOA)[0];
            DnsDatagram request = new DnsDatagram(1, false, DnsOpcode.StandardQuery, false, false, false, false, false, false, DnsResponseCode.NoError, [new DnsQuestionRecord(zone, DnsResourceRecordType.AXFR, DnsClass.IN)], udpPayloadSize: 1232, options: [new EDnsOption(EDnsOptionCode.EDNS_EXPIRE, new EDnsExpireOptionData((uint?)null))]);
            DnsDatagram response = await _dns.QueryAsync(request);

            Assert.Equal(DnsResponseCode.NoError, response.RCODE);

            List<DnsResourceRecord> answers = DnsTest.AllAnswers(response);
            Assert.Equal(DnsResourceRecordType.SOA, answers[0].Type);
            Assert.Equal(DnsResourceRecordType.SOA, answers[answers.Count - 1].Type);
            Assert.Equal(((DnsSOARecordData)soa.RDATA).Serial, ((DnsSOARecordData)answers[0].RDATA).Serial);
            Assert.Equal(((DnsSOARecordData)answers[0].RDATA).Serial, ((DnsSOARecordData)answers[answers.Count - 1].RDATA).Serial);

            DnsResourceRecord inZone = FindAddress(answers, inZoneServer, inZoneAddress);
            Assert.NotNull(inZone);
            Assert.Equal(60u, inZone.TTL);
            Assert.Equal(1, CountAddress(answers, inZoneServer, inZoneAddress));
            Assert.Equal(1, CountAddress(answers, externalServer, externalAddress));

            EDnsExpireOptionData expire = FindExpire(response);
            Assert.NotNull(expire);
            Assert.Equal(((DnsSOARecordData)soa.RDATA).Expire, expire.Expire);
        }

        [Fact]
        public async System.Threading.Tasks.Task GlueAddressDoesNotAuthorizeZoneTransfer()
        {
            const string zone = "glue-acl.example";
            _dns.CreateZone(zone);

            string nameServer = "ns2." + zone;
            _dns.Add(zone, zone, DnsResourceRecordType.NS, new DnsNSRecordData(nameServer));
            _dns.Add(zone, nameServer, DnsResourceRecordType.A, new DnsARecordData(IPAddress.Parse("192.0.2.51")));
            Glue(zone, zone, nameServer, "192.0.2.50");

            DnsDatagram request = new DnsDatagram(1, false, DnsOpcode.StandardQuery, false, false, false, false, false, false, DnsResponseCode.NoError, [new DnsQuestionRecord(zone, DnsResourceRecordType.AXFR, DnsClass.IN)]);

            DnsDatagram glueResponse = await _dns.Server.DirectQueryAsync(request, new IPEndPoint(IPAddress.Parse("192.0.2.50"), 53), 10000);
            Assert.Equal(DnsResponseCode.Refused, glueResponse.RCODE);

            DnsDatagram resolvedResponse = await _dns.Server.DirectQueryAsync(request, new IPEndPoint(IPAddress.Parse("192.0.2.51"), 53), 10000);
            Assert.Equal(DnsResponseCode.NoError, resolvedResponse.RCODE);
            Assert.Equal(DnsResourceRecordType.SOA, DnsTest.AllAnswers(resolvedResponse)[0].Type);
        }

        void Glue(string zone, string owner, string nameServer, string address)
        {
            foreach (DnsResourceRecord record in _dns.Server.AuthZoneManager.GetRecords(zone, owner, DnsResourceRecordType.NS))
            {
                if (((DnsNSRecordData)record.RDATA).NameServer.Equals(nameServer, System.StringComparison.OrdinalIgnoreCase))
                {
                    record.SetGlueRecords(address);
                    return;
                }
            }

            Assert.Fail("NS record was not stored: " + nameServer);
        }

        static int CountAddress(IReadOnlyList<DnsResourceRecord> records, string name, IPAddress address)
        {
            int count = 0;

            foreach (DnsResourceRecord record in records)
            {
                if (FindAddress([record], name, address) is not null)
                    count++;
            }

            return count;
        }

        static DnsResourceRecord FindAddress(IReadOnlyList<DnsResourceRecord> records, string name, IPAddress address)
        {
            foreach (DnsResourceRecord record in records)
            {
                if (!record.Name.Equals(name, System.StringComparison.OrdinalIgnoreCase))
                    continue;

                if ((record.Type == DnsResourceRecordType.A) && (record.RDATA is DnsARecordData ipv4) && ipv4.Address.Equals(address))
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
