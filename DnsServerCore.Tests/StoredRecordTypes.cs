using System;
using System.Collections.Generic;
using System.Net;
using System.Threading.Tasks;
using TechnitiumLibrary.Net;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;
using Xunit;

namespace DnsServerCore.Tests
{
    public sealed class StoredRecordTypes : IClassFixture<DnsServerFixture>
    {
        readonly DnsServerFixture _dns;

        public StoredRecordTypes(DnsServerFixture dns)
        {
            _dns = dns;
        }

        [Fact]
        public async Task EachStoredTypeIsReturned()
        {
            const string zone = "types.example";
            _dns.CreateZone(zone);

            await AssertAnswer(zone, "srv." + zone, DnsResourceRecordType.SRV, new DnsSRVRecordData(10, 20, 5060, "sip." + zone));
            await AssertAnswer(zone, "naptr." + zone, DnsResourceRecordType.NAPTR, new DnsNAPTRRecordData(100, 10, "s", "SIP+D2U", "", "sip." + zone));
            await AssertAnswer(zone, "caa." + zone, DnsResourceRecordType.CAA, new DnsCAARecordData(0, "issue", "letsencrypt.org"));
            await AssertAnswer(zone, "tlsa." + zone, DnsResourceRecordType.TLSA, new DnsTLSARecordData(DnsTLSACertificateUsage.DANE_EE, DnsTLSASelector.Cert, DnsTLSAMatchingType.SHA2_256, new byte[32]));
            await AssertAnswer(zone, "svcb." + zone, DnsResourceRecordType.SVCB, new DnsSVCBRecordData(1, "svc.example.net", new Dictionary<DnsSvcParamKey, DnsSvcParamValue>()));
            await AssertAnswer(zone, "https." + zone, DnsResourceRecordType.HTTPS, new DnsSVCBRecordData(1, "svc.example.net", new Dictionary<DnsSvcParamKey, DnsSvcParamValue>()));
            await AssertAnswer(zone, "sshfp." + zone, DnsResourceRecordType.SSHFP, new DnsSSHFPRecordData(DnsSSHFPAlgorithm.Ed25519, DnsSSHFPFingerprintType.SHA256, new byte[32]));
            await AssertAnswer(zone, "uri." + zone, DnsResourceRecordType.URI, new DnsURIRecordData(10, 1, new Uri("https://example.com/")));
            await AssertAnswer(zone, "apl." + zone, DnsResourceRecordType.APL, new DnsAPLRecordData([new DnsAPLRecordData.APItem(new NetworkAddress(IPAddress.Parse("192.0.2.0"), 24), false)]));
            await AssertAnswer(zone, "zonemd." + zone, DnsResourceRecordType.ZONEMD, new DnsZONEMDRecordData(1, ZoneMdScheme.Simple, ZoneMdHashAlgorithm.SHA384, new byte[48]));
        }

        async Task AssertAnswer(string zone, string name, DnsResourceRecordType type, DnsResourceRecordData data)
        {
            _dns.Add(zone, name, type, data);

            DnsDatagram response = await _dns.QueryAsync(name, type);

            Assert.Equal(DnsResponseCode.NoError, response.RCODE);
            Assert.True(response.AuthoritativeAnswer, DnsTest.Describe(response));
            Assert.NotNull(DnsTest.Find(response.Answer, type, name));
        }
    }
}
