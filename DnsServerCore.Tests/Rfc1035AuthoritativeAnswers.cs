using DnsServerCore.Dns;
using DnsServerCore.Dns.Zones;
using System;
using System.Net;
using System.Threading.Tasks;
using TechnitiumLibrary.Net.Dns;
using DnsResponseCode = TechnitiumLibrary.Net.Dns.DnsResponseCode;
using TechnitiumLibrary.Net.Dns.ResourceRecords;
using Xunit;

namespace DnsServerCore.Tests
{
    public sealed class Rfc1035AuthoritativeAnswers : IClassFixture<DnsServerFixture>
    {
        readonly DnsServerFixture _dns;

        public Rfc1035AuthoritativeAnswers(DnsServerFixture dns)
        {
            _dns = dns;
        }

        [Fact]
        public async Task ExactNameReturnsTheAddress()
        {
            const string zone = "exact.example";
            _dns.CreateZone(zone);
            _dns.Add(zone, "www." + zone, DnsResourceRecordType.A, new DnsARecordData(IPAddress.Parse("192.0.2.1")));

            DnsDatagram response = await _dns.QueryAsync("www." + zone, DnsResourceRecordType.A);

            Assert.Equal(DnsResponseCode.NoError, response.RCODE);
            Assert.True(response.AuthoritativeAnswer, DnsTest.Describe(response));

            DnsResourceRecord answer = DnsTest.Find(response.Answer, DnsResourceRecordType.A, "www." + zone);
            Assert.NotNull(answer);
            Assert.Equal(IPAddress.Parse("192.0.2.1"), ((DnsARecordData)answer.RDATA).Address);
        }

        [Fact]
        public async Task CnameIsFollowedInsideTheZone()
        {
            const string zone = "cname.example";
            _dns.CreateZone(zone);
            _dns.Set(zone, "www." + zone, DnsResourceRecordType.CNAME, new DnsCNAMERecordData("target." + zone));
            _dns.Add(zone, "target." + zone, DnsResourceRecordType.A, new DnsARecordData(IPAddress.Parse("192.0.2.2")));

            DnsDatagram response = await _dns.QueryAsync("www." + zone, DnsResourceRecordType.A);

            Assert.Equal(DnsResponseCode.NoError, response.RCODE);
            Assert.True(response.AuthoritativeAnswer, DnsTest.Describe(response));

            DnsResourceRecord cname = DnsTest.Find(response.Answer, DnsResourceRecordType.CNAME, "www." + zone);
            Assert.NotNull(cname);
            Assert.Equal("target." + zone, ((DnsCNAMERecordData)cname.RDATA).Domain, ignoreCase: true);

            DnsResourceRecord address = DnsTest.Find(response.Answer, DnsResourceRecordType.A, "target." + zone);
            Assert.NotNull(address);
            Assert.Equal(IPAddress.Parse("192.0.2.2"), ((DnsARecordData)address.RDATA).Address);
        }

        [Fact]
        public async Task NameWithAnotherTypeIsNodata()
        {
            const string zone = "nodata.example";
            _dns.CreateZone(zone);
            _dns.Add(zone, "www." + zone, DnsResourceRecordType.AAAA, new DnsAAAARecordData(IPAddress.Parse("2001:db8::1")));

            DnsDatagram response = await _dns.QueryAsync("www." + zone, DnsResourceRecordType.A);

            Assert.Equal(DnsResponseCode.NoError, response.RCODE);
            Assert.True(response.AuthoritativeAnswer, DnsTest.Describe(response));
            Assert.Null(DnsTest.Find(response.Answer, DnsResourceRecordType.A));
            Assert.NotNull(DnsTest.Find(response.Authority, DnsResourceRecordType.SOA, zone));
        }

        [Fact]
        public async Task MissingNameIsNxDomain()
        {
            const string zone = "missing.example";
            _dns.CreateZone(zone);

            DnsDatagram response = await _dns.QueryAsync("gone." + zone, DnsResourceRecordType.A);

            Assert.Equal(DnsResponseCode.NxDomain, response.RCODE);
            Assert.True(response.AuthoritativeAnswer, DnsTest.Describe(response));
            Assert.Empty(response.Answer);
            Assert.NotNull(DnsTest.Find(response.Authority, DnsResourceRecordType.SOA, zone));
        }

        [Fact]
        public async Task EmptyNonTerminalIsNodata()
        {
            const string zone = "ent.example";
            _dns.CreateZone(zone);
            _dns.Add(zone, "a.b." + zone, DnsResourceRecordType.A, new DnsARecordData(IPAddress.Parse("192.0.2.3")));

            DnsDatagram response = await _dns.QueryAsync("b." + zone, DnsResourceRecordType.A);

            Assert.Equal(DnsResponseCode.NoError, response.RCODE);
            Assert.True(response.AuthoritativeAnswer, DnsTest.Describe(response));
            Assert.Null(DnsTest.Find(response.Answer, DnsResourceRecordType.A));
            Assert.NotNull(DnsTest.Find(response.Authority, DnsResourceRecordType.SOA, zone));
        }

        [Fact]
        public async Task NameBelowAnNsCutIsAReferral()
        {
            const string zone = "referral.example";
            _dns.CreateZone(zone);
            _dns.Add(zone, "delegated." + zone, DnsResourceRecordType.NS, new DnsNSRecordData("ns1.example.net"));

            DnsDatagram response = await _dns.QueryAsync("host.delegated." + zone, DnsResourceRecordType.A);

            Assert.Equal(DnsResponseCode.NoError, response.RCODE);
            Assert.False(response.AuthoritativeAnswer, DnsTest.Describe(response));
            Assert.Empty(response.Answer);

            DnsResourceRecord ns = DnsTest.Find(response.Authority, DnsResourceRecordType.NS, "delegated." + zone);
            Assert.NotNull(ns);
            Assert.Equal("ns1.example.net", ((DnsNSRecordData)ns.RDATA).NameServer, ignoreCase: true);
        }

        [Fact]
        public async Task MissingNameBelowAnEmptyNonTerminalIsNxDomain()
        {
            const string zone = "below-ent.example";
            _dns.CreateZone(zone);
            _dns.Add(zone, "a.b." + zone, DnsResourceRecordType.A, new DnsARecordData(IPAddress.Parse("192.0.2.4")));

            DnsDatagram response = await _dns.QueryAsync("c.b." + zone, DnsResourceRecordType.A);

            Assert.Equal(DnsResponseCode.NxDomain, response.RCODE);
            Assert.True(response.AuthoritativeAnswer, DnsTest.Describe(response));
            Assert.Empty(response.Answer);
            Assert.NotNull(DnsTest.Find(response.Authority, DnsResourceRecordType.SOA, zone));
        }

        [Fact]
        public async Task CnameCannotShareItsName()
        {
            const string zone = "cname-only.example";
            const string name = "www." + zone;
            _dns.CreateZone(zone);
            _dns.Add(zone, name, DnsResourceRecordType.A, new DnsARecordData(IPAddress.Parse("192.0.2.5")));

            Assert.Throws<InvalidOperationException>(() => _dns.Set(zone, name, DnsResourceRecordType.CNAME, new DnsCNAMERecordData("other.example")));

            DnsDatagram response = await _dns.QueryAsync(name, DnsResourceRecordType.A);
            Assert.NotNull(DnsTest.Find(response.Answer, DnsResourceRecordType.A, name));
        }

        [Fact]
        public void ZoneFileRefusesCnameBesideAnotherType()
        {
            const string zone = "cname-load.example";
            const string name = "www." + zone;
            AuthZoneInfo info = _dns.CreateZone(zone);

            DnsServerException error = Assert.Throws<DnsServerException>(() => _dns.Server.AuthZoneManager.LoadAndInitZone(info, new DnsResourceRecord[]
            {
                new DnsResourceRecord(name, DnsResourceRecordType.CNAME, DnsClass.IN, 300, new DnsCNAMERecordData("other.example")),
                new DnsResourceRecord(name, DnsResourceRecordType.A, DnsClass.IN, 300, new DnsARecordData(IPAddress.Parse("192.0.2.9")))
            }));

            Assert.Contains(name, error.Message);
            Assert.Empty(_dns.Server.AuthZoneManager.GetRecords(zone, name, DnsResourceRecordType.CNAME));
            Assert.Empty(_dns.Server.AuthZoneManager.GetRecords(zone, name, DnsResourceRecordType.A));
        }

        [Fact]
        public async Task ZoneFileLoadsACname()
        {
            const string zone = "cname-file.example";
            const string name = "www." + zone;
            AuthZoneInfo info = _dns.CreateZone(zone);

            _dns.Server.AuthZoneManager.LoadAndInitZone(info, new DnsResourceRecord[]
            {
                new DnsResourceRecord(name, DnsResourceRecordType.CNAME, DnsClass.IN, 300, new DnsCNAMERecordData("other.example"))
            });

            DnsDatagram response = await _dns.QueryAsync(name, DnsResourceRecordType.CNAME);
            Assert.Equal(DnsResponseCode.NoError, response.RCODE);
            Assert.NotNull(DnsTest.Find(response.Answer, DnsResourceRecordType.CNAME, name));
        }

        [Fact]
        public void ZoneTransferRefusesCnameBesideAnotherType()
        {
            const string zone = "cname-axfr.example";
            const string name = "www." + zone;
            _dns.CreateZone(zone);
            DnsResourceRecord soa = _dns.Server.AuthZoneManager.GetRecords(zone, zone, DnsResourceRecordType.SOA)[0];

            DnsServerException error = Assert.Throws<DnsServerException>(() => _dns.Server.AuthZoneManager.SyncZoneTransferRecords(zone, new DnsResourceRecord[]
            {
                soa,
                new DnsResourceRecord(name, DnsResourceRecordType.CNAME, DnsClass.IN, 300, new DnsCNAMERecordData("other.example")),
                new DnsResourceRecord(name, DnsResourceRecordType.A, DnsClass.IN, 300, new DnsARecordData(IPAddress.Parse("192.0.2.9"))),
                soa
            }));

            Assert.Contains(name, error.Message);
            Assert.Empty(_dns.Server.AuthZoneManager.GetRecords(zone, name, DnsResourceRecordType.CNAME));
            Assert.Empty(_dns.Server.AuthZoneManager.GetRecords(zone, name, DnsResourceRecordType.A));
        }

        [Fact]
        public void ZoneTransferLeavesExistingRecordsUnchangedWhenACnameIsIllegal()
        {
            const string zone = "cname-axfr-keep.example";
            const string stay = "stay." + zone;
            const string removed = "removed." + zone;
            const string name = "www." + zone;
            _dns.CreateZone(zone);
            _dns.Add(zone, stay, DnsResourceRecordType.A, new DnsARecordData(IPAddress.Parse("192.0.2.1")));
            _dns.Add(zone, removed, DnsResourceRecordType.A, new DnsARecordData(IPAddress.Parse("192.0.2.2")));

            DnsResourceRecord soa = _dns.Server.AuthZoneManager.GetRecords(zone, zone, DnsResourceRecordType.SOA)[0];
            DnsSOARecordData soaData = (DnsSOARecordData)soa.RDATA;
            DnsResourceRecord updated = new DnsResourceRecord(soa.Name, DnsResourceRecordType.SOA, soa.Class, soa.TTL, new DnsSOARecordData(soaData.PrimaryNameServer, soaData.ResponsiblePerson, soaData.Serial + 1, soaData.Refresh, soaData.Retry, soaData.Expire, soaData.Minimum));

            DnsServerException error = Assert.Throws<DnsServerException>(() => _dns.Server.AuthZoneManager.SyncZoneTransferRecords(zone, new DnsResourceRecord[]
            {
                updated,
                new DnsResourceRecord(stay, DnsResourceRecordType.A, DnsClass.IN, 300, new DnsARecordData(IPAddress.Parse("192.0.2.9"))),
                new DnsResourceRecord(name, DnsResourceRecordType.CNAME, DnsClass.IN, 300, new DnsCNAMERecordData("other.example")),
                new DnsResourceRecord(name, DnsResourceRecordType.A, DnsClass.IN, 300, new DnsARecordData(IPAddress.Parse("192.0.2.8"))),
                updated
            }));

            Assert.Contains(name, error.Message);
            Assert.Equal(soaData.Serial, ((DnsSOARecordData)_dns.Server.AuthZoneManager.GetRecords(zone, zone, DnsResourceRecordType.SOA)[0].RDATA).Serial);
            Assert.NotEmpty(_dns.Server.AuthZoneManager.GetRecords(zone, zone, DnsResourceRecordType.NS));
            Assert.Equal(IPAddress.Parse("192.0.2.1"), ((DnsARecordData)_dns.Server.AuthZoneManager.GetRecords(zone, stay, DnsResourceRecordType.A)[0].RDATA).Address);
            Assert.Equal(IPAddress.Parse("192.0.2.2"), ((DnsARecordData)_dns.Server.AuthZoneManager.GetRecords(zone, removed, DnsResourceRecordType.A)[0].RDATA).Address);
            Assert.Empty(_dns.Server.AuthZoneManager.GetRecords(zone, name, DnsResourceRecordType.CNAME));
            Assert.Empty(_dns.Server.AuthZoneManager.GetRecords(zone, name, DnsResourceRecordType.A));
        }

        [Fact]
        public async Task MailExchangeIncludesTheInZoneAddress()
        {
            const string zone = "mx.example";
            _dns.CreateZone(zone);
            _dns.Add(zone, "mail." + zone, DnsResourceRecordType.A, new DnsARecordData(IPAddress.Parse("192.0.2.6")));
            _dns.Add(zone, zone, DnsResourceRecordType.MX, new DnsMXRecordData(10, "mail." + zone));

            DnsDatagram response = await _dns.QueryAsync(zone, DnsResourceRecordType.MX);

            Assert.Equal(DnsResponseCode.NoError, response.RCODE);
            Assert.NotNull(DnsTest.Find(response.Answer, DnsResourceRecordType.MX, zone));
            DnsResourceRecord additional = DnsTest.Find(response.Additional, DnsResourceRecordType.A, "mail." + zone);
            Assert.NotNull(additional);
            Assert.Equal(IPAddress.Parse("192.0.2.6"), ((DnsARecordData)additional.RDATA).Address);
        }

        [Fact]
        public async Task OutOfZoneMailExchangeHasNoAddress()
        {
            const string zone = "mx-out.example";
            _dns.CreateZone(zone);
            _dns.Add(zone, zone, DnsResourceRecordType.MX, new DnsMXRecordData(10, "mail.example.net"));

            DnsDatagram response = await _dns.QueryAsync(zone, DnsResourceRecordType.MX);

            Assert.Equal(DnsResponseCode.NoError, response.RCODE);
            Assert.Null(DnsTest.Find(response.Additional, DnsResourceRecordType.A));
            Assert.Null(DnsTest.Find(response.Additional, DnsResourceRecordType.AAAA));
        }

        [Fact]
        public async Task NameServerAddressIsAdditionalWhenItIsInZone()
        {
            const string zone = "ns-glue.example";
            _dns.CreateZone(zone);
            _dns.Add(zone, "ns1." + zone, DnsResourceRecordType.A, new DnsARecordData(IPAddress.Parse("192.0.2.53")));
            _dns.Add(zone, zone, DnsResourceRecordType.NS, new DnsNSRecordData("ns1." + zone));

            DnsDatagram response = await _dns.QueryAsync(zone, DnsResourceRecordType.NS);

            Assert.Equal(DnsResponseCode.NoError, response.RCODE);
            DnsResourceRecord additional = DnsTest.Find(response.Additional, DnsResourceRecordType.A, "ns1." + zone);
            Assert.NotNull(additional);
            Assert.Equal(IPAddress.Parse("192.0.2.53"), ((DnsARecordData)additional.RDATA).Address);
        }

        [Fact]
        public async Task ServiceTargetIncludesTheInZoneAddress()
        {
            const string zone = "srv.example";
            _dns.CreateZone(zone);
            _dns.Add(zone, "sip." + zone, DnsResourceRecordType.A, new DnsARecordData(IPAddress.Parse("192.0.2.7")));
            _dns.Add(zone, "_sip._udp." + zone, DnsResourceRecordType.SRV, new DnsSRVRecordData(10, 20, 5060, "sip." + zone));

            DnsDatagram response = await _dns.QueryAsync("_sip._udp." + zone, DnsResourceRecordType.SRV);

            Assert.Equal(DnsResponseCode.NoError, response.RCODE);
            Assert.NotNull(DnsTest.Find(response.Answer, DnsResourceRecordType.SRV));
            DnsResourceRecord additional = DnsTest.Find(response.Additional, DnsResourceRecordType.A, "sip." + zone);
            Assert.NotNull(additional);
            Assert.Equal(IPAddress.Parse("192.0.2.7"), ((DnsARecordData)additional.RDATA).Address);
        }
    }
}
