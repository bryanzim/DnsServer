using System.Collections.Generic;
using System.IO;
using System.Net;
using TechnitiumLibrary.Net.Dns;
using DnsResponseCode = TechnitiumLibrary.Net.Dns.DnsResponseCode;
using TechnitiumLibrary.Net.Dns.ResourceRecords;
using Xunit;

namespace DnsServerCore.Tests
{
    // RFC 9460: Service Binding and Parameter Specification via the DNS (SVCB and HTTPS)
    // https://www.rfc-editor.org/rfc/rfc9460
    public sealed class Rfc9460ServiceBinding
    {
        [Fact]
        public void ServiceModeWithAMissingMandatoryKeyCannotBeWritten()
        {
            DnsSVCBRecordData data = new DnsSVCBRecordData(1, "svc.example.net", new Dictionary<DnsSvcParamKey, DnsSvcParamValue>
            {
                [DnsSvcParamKey.Mandatory] = new DnsSvcMandatoryParamValue([DnsSvcParamKey.IPv4Hint])
            });
            DnsResourceRecord record = new DnsResourceRecord("svc.example", DnsResourceRecordType.SVCB, DnsClass.IN, 300, data);

            using (MemoryStream stream = new MemoryStream())
            {
                DnsClientException ex = Assert.Throws<DnsClientException>(() => record.WriteTo(stream));
                Assert.Contains("mandatory", ex.Message);
            }
        }

        [Fact]
        public void ServiceModeWithItsMandatoryKeyRoundTrips()
        {
            IPAddress hint = IPAddress.Parse("192.0.2.1");
            DnsSVCBRecordData data = new DnsSVCBRecordData(1, "svc.example.net", new Dictionary<DnsSvcParamKey, DnsSvcParamValue>
            {
                [DnsSvcParamKey.Mandatory] = new DnsSvcMandatoryParamValue([DnsSvcParamKey.IPv4Hint]),
                [DnsSvcParamKey.IPv4Hint] = new DnsSvcIPv4HintParamValue([hint])
            });
            DnsResourceRecord record = new DnsResourceRecord("svc.example", DnsResourceRecordType.HTTPS, DnsClass.IN, 300, data);
            DnsDatagram message = new DnsDatagram(1, true, DnsOpcode.StandardQuery, true, false, false, false, false, false, DnsResponseCode.NoError, [new DnsQuestionRecord("svc.example", DnsResourceRecordType.HTTPS, DnsClass.IN)], [record]);

            DnsDatagram read = DnsTest.RoundTrip(message);
            DnsSVCBRecordData rdata = (DnsSVCBRecordData)read.Answer[0].RDATA;

            Assert.Equal(1, rdata.SvcPriority);
            Assert.Equal("svc.example.net", rdata.TargetName, ignoreCase: true);
            Assert.Contains(DnsSvcParamKey.IPv4Hint, ((DnsSvcMandatoryParamValue)rdata.SvcParams[DnsSvcParamKey.Mandatory]).Keys);
            Assert.Equal(hint, Assert.Single(((DnsSvcIPv4HintParamValue)rdata.SvcParams[DnsSvcParamKey.IPv4Hint]).Addresses));
        }

        [Fact]
        public void AliasModeSkipsTheMandatoryKeyCheck()
        {
            DnsSVCBRecordData data = new DnsSVCBRecordData(0, "alias.example.net", new Dictionary<DnsSvcParamKey, DnsSvcParamValue>
            {
                [DnsSvcParamKey.Mandatory] = new DnsSvcMandatoryParamValue([DnsSvcParamKey.IPv4Hint])
            });
            DnsResourceRecord record = new DnsResourceRecord("svc.example", DnsResourceRecordType.SVCB, DnsClass.IN, 300, data);

            using (MemoryStream stream = new MemoryStream())
            {
                record.WriteTo(stream);
                Assert.True(stream.Length > 0);
            }
        }
    }
}
