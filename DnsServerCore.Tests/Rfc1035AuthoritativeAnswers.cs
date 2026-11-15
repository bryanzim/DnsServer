using DnsServerCore.Dns;
using DnsServerCore.Dns.Zones;
using System;
using System.Collections.Generic;
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

        [Fact]
        public void ImportAddsALegalRecord()
        {
            const string zone = "import-ok.example";
            const string name = "www." + zone;
            _dns.CreateZone(zone);

            _dns.Server.AuthZoneManager.ImportRecords(zone, new DnsResourceRecord[]
            {
                new DnsResourceRecord(name, DnsResourceRecordType.A, DnsClass.IN, 300, new DnsARecordData(IPAddress.Parse("192.0.2.30")))
            }, false, false, false);

            Assert.Equal(IPAddress.Parse("192.0.2.30"), ((DnsARecordData)_dns.Server.AuthZoneManager.GetRecords(zone, name, DnsResourceRecordType.A)[0].RDATA).Address);
        }

        [Fact]
        public void ImportLeavesExistingRecordsUnchangedWhenACnameIsIllegal()
        {
            const string zone = "import-cname-keep.example";
            const string stay = "stay." + zone;
            const string removed = "removed." + zone;
            const string name = "www." + zone;
            _dns.CreateZone(zone);
            _dns.Add(zone, stay, DnsResourceRecordType.A, new DnsARecordData(IPAddress.Parse("192.0.2.31")));
            _dns.Add(zone, removed, DnsResourceRecordType.A, new DnsARecordData(IPAddress.Parse("192.0.2.32")));

            uint serial = ((DnsSOARecordData)_dns.Server.AuthZoneManager.GetRecords(zone, zone, DnsResourceRecordType.SOA)[0].RDATA).Serial;

            DnsServerException error = Assert.Throws<DnsServerException>(() => _dns.Server.AuthZoneManager.ImportRecords(zone, new DnsResourceRecord[]
            {
                new DnsResourceRecord(stay, DnsResourceRecordType.A, DnsClass.IN, 300, new DnsARecordData(IPAddress.Parse("192.0.2.39"))),
                new DnsResourceRecord(name, DnsResourceRecordType.CNAME, DnsClass.IN, 300, new DnsCNAMERecordData("other.example")),
                new DnsResourceRecord(name, DnsResourceRecordType.A, DnsClass.IN, 300, new DnsARecordData(IPAddress.Parse("192.0.2.38")))
            }, true, true, false));

            Assert.Contains(name, error.Message);
            Assert.Equal(serial, ((DnsSOARecordData)_dns.Server.AuthZoneManager.GetRecords(zone, zone, DnsResourceRecordType.SOA)[0].RDATA).Serial);
            Assert.NotEmpty(_dns.Server.AuthZoneManager.GetRecords(zone, zone, DnsResourceRecordType.NS));
            Assert.Equal(IPAddress.Parse("192.0.2.31"), ((DnsARecordData)_dns.Server.AuthZoneManager.GetRecords(zone, stay, DnsResourceRecordType.A)[0].RDATA).Address);
            Assert.Equal(IPAddress.Parse("192.0.2.32"), ((DnsARecordData)_dns.Server.AuthZoneManager.GetRecords(zone, removed, DnsResourceRecordType.A)[0].RDATA).Address);
            Assert.Empty(_dns.Server.AuthZoneManager.GetRecords(zone, name, DnsResourceRecordType.CNAME));
            Assert.Empty(_dns.Server.AuthZoneManager.GetRecords(zone, name, DnsResourceRecordType.A));
        }

        [Fact]
        public void ImportLeavesEarlierNamesUnchangedWhenACnameSharesAnExistingName()
        {
            const string zone = "import-cname-merge.example";
            const string added = "added." + zone;
            const string name = "www." + zone;
            _dns.CreateZone(zone);
            _dns.Add(zone, name, DnsResourceRecordType.A, new DnsARecordData(IPAddress.Parse("192.0.2.33")));

            uint serial = ((DnsSOARecordData)_dns.Server.AuthZoneManager.GetRecords(zone, zone, DnsResourceRecordType.SOA)[0].RDATA).Serial;

            DnsServerException error = Assert.Throws<DnsServerException>(() => _dns.Server.AuthZoneManager.ImportRecords(zone, new DnsResourceRecord[]
            {
                new DnsResourceRecord(added, DnsResourceRecordType.A, DnsClass.IN, 300, new DnsARecordData(IPAddress.Parse("192.0.2.34"))),
                new DnsResourceRecord(name, DnsResourceRecordType.CNAME, DnsClass.IN, 300, new DnsCNAMERecordData("other.example"))
            }, false, false, false));

            Assert.Contains(name, error.Message);
            Assert.Equal(serial, ((DnsSOARecordData)_dns.Server.AuthZoneManager.GetRecords(zone, zone, DnsResourceRecordType.SOA)[0].RDATA).Serial);
            Assert.Equal(IPAddress.Parse("192.0.2.33"), ((DnsARecordData)_dns.Server.AuthZoneManager.GetRecords(zone, name, DnsResourceRecordType.A)[0].RDATA).Address);
            Assert.Empty(_dns.Server.AuthZoneManager.GetRecords(zone, name, DnsResourceRecordType.CNAME));
            Assert.Empty(_dns.Server.AuthZoneManager.GetRecords(zone, added, DnsResourceRecordType.A));
        }

        [Fact]
        public void FailedParentLoadDoesNotAdoptIntoTheChild()
        {
            const string zone = "adopt-keep.example";
            const string child = "child." + zone;
            const string adopted = "www." + child;
            const string name = "bad." + zone;
            _dns.CreateZone(child);
            AuthZoneInfo parent = _dns.CreateZone(zone);

            DnsServerException error = Assert.Throws<DnsServerException>(() => _dns.Server.AuthZoneManager.LoadAndInitZone(parent, new DnsResourceRecord[]
            {
                new DnsResourceRecord(adopted, DnsResourceRecordType.A, DnsClass.IN, 300, new DnsARecordData(IPAddress.Parse("192.0.2.35"))),
                new DnsResourceRecord(name, DnsResourceRecordType.CNAME, DnsClass.IN, 300, new DnsCNAMERecordData("other.example")),
                new DnsResourceRecord(name, DnsResourceRecordType.A, DnsClass.IN, 300, new DnsARecordData(IPAddress.Parse("192.0.2.36")))
            }));

            Assert.Contains(name, error.Message);
            Assert.Empty(_dns.Server.AuthZoneManager.GetRecords(child, adopted, DnsResourceRecordType.A));
            Assert.Empty(_dns.Server.AuthZoneManager.GetRecords(zone, name, DnsResourceRecordType.CNAME));
            Assert.Empty(_dns.Server.AuthZoneManager.GetRecords(zone, name, DnsResourceRecordType.A));
        }

        [Fact]
        public async Task ParentLoadAdoptsAChildNameWhenTheFileIsLegal()
        {
            const string zone = "adopt-ok.example";
            const string child = "child." + zone;
            const string adopted = "www." + child;
            const string name = "host." + zone;
            _dns.CreateZone(child);
            AuthZoneInfo parent = _dns.CreateZone(zone);

            _dns.Server.AuthZoneManager.LoadAndInitZone(parent, new DnsResourceRecord[]
            {
                new DnsResourceRecord(adopted, DnsResourceRecordType.A, DnsClass.IN, 300, new DnsARecordData(IPAddress.Parse("192.0.2.37"))),
                new DnsResourceRecord(name, DnsResourceRecordType.A, DnsClass.IN, 300, new DnsARecordData(IPAddress.Parse("192.0.2.40")))
            });

            Assert.Equal(IPAddress.Parse("192.0.2.37"), ((DnsARecordData)_dns.Server.AuthZoneManager.GetRecords(child, adopted, DnsResourceRecordType.A)[0].RDATA).Address);
            Assert.Equal(IPAddress.Parse("192.0.2.40"), ((DnsARecordData)_dns.Server.AuthZoneManager.GetRecords(zone, name, DnsResourceRecordType.A)[0].RDATA).Address);

            DnsDatagram response = await _dns.QueryAsync(adopted, DnsResourceRecordType.A);
            Assert.Equal(DnsResponseCode.NoError, response.RCODE);
            Assert.Equal(IPAddress.Parse("192.0.2.37"), ((DnsARecordData)DnsTest.Find(response.Answer, DnsResourceRecordType.A, adopted).RDATA).Address);
        }

        [Fact]
        public void ImportOverwriteReplacesTheZoneWhenTheFileIsLegal()
        {
            const string zone = "import-overwrite-ok.example";
            const string stay = "stay." + zone;
            const string removed = "removed." + zone;
            _dns.CreateZone(zone);
            _dns.Add(zone, stay, DnsResourceRecordType.A, new DnsARecordData(IPAddress.Parse("192.0.2.43")));
            _dns.Add(zone, removed, DnsResourceRecordType.A, new DnsARecordData(IPAddress.Parse("192.0.2.44")));
            DnsResourceRecord nameServer = _dns.Server.AuthZoneManager.GetRecords(zone, zone, DnsResourceRecordType.NS)[0];

            _dns.Server.AuthZoneManager.ImportRecords(zone, new DnsResourceRecord[]
            {
                nameServer,
                new DnsResourceRecord(stay, DnsResourceRecordType.A, DnsClass.IN, 300, new DnsARecordData(IPAddress.Parse("192.0.2.45")))
            }, true, true, false);

            Assert.Equal(IPAddress.Parse("192.0.2.45"), ((DnsARecordData)_dns.Server.AuthZoneManager.GetRecords(zone, stay, DnsResourceRecordType.A)[0].RDATA).Address);
            Assert.Empty(_dns.Server.AuthZoneManager.GetRecords(zone, removed, DnsResourceRecordType.A));
            Assert.NotEmpty(_dns.Server.AuthZoneManager.GetRecords(zone, zone, DnsResourceRecordType.NS));
        }

        [Fact]
        public void ImportLeavesExistingRecordsUnchangedWhenTheTtlExceedsExpire()
        {
            const string zone = "import-ttl-keep.example";
            const string stay = "stay." + zone;
            const string removed = "removed." + zone;
            const string added = "added." + zone;
            _dns.CreateZone(zone);
            _dns.Add(zone, stay, DnsResourceRecordType.A, new DnsARecordData(IPAddress.Parse("192.0.2.46")));
            _dns.Add(zone, removed, DnsResourceRecordType.A, new DnsARecordData(IPAddress.Parse("192.0.2.47")));

            DnsResourceRecord soa = _dns.Server.AuthZoneManager.GetRecords(zone, zone, DnsResourceRecordType.SOA)[0];
            uint serial = ((DnsSOARecordData)soa.RDATA).Serial;
            uint ttl = ((DnsSOARecordData)soa.RDATA).Expire + 1;

            DnsServerException error = Assert.Throws<DnsServerException>(() => _dns.Server.AuthZoneManager.ImportRecords(zone, new DnsResourceRecord[]
            {
                new DnsResourceRecord(added, DnsResourceRecordType.A, DnsClass.IN, 300, new DnsARecordData(IPAddress.Parse("192.0.2.48"))),
                new DnsResourceRecord(stay, DnsResourceRecordType.A, DnsClass.IN, ttl, new DnsARecordData(IPAddress.Parse("192.0.2.49")))
            }, true, true, false));

            Assert.Contains("EXPIRE", error.Message);
            Assert.Equal(serial, ((DnsSOARecordData)_dns.Server.AuthZoneManager.GetRecords(zone, zone, DnsResourceRecordType.SOA)[0].RDATA).Serial);
            Assert.NotEmpty(_dns.Server.AuthZoneManager.GetRecords(zone, zone, DnsResourceRecordType.NS));
            Assert.Equal(IPAddress.Parse("192.0.2.46"), ((DnsARecordData)_dns.Server.AuthZoneManager.GetRecords(zone, stay, DnsResourceRecordType.A)[0].RDATA).Address);
            Assert.Equal(IPAddress.Parse("192.0.2.47"), ((DnsARecordData)_dns.Server.AuthZoneManager.GetRecords(zone, removed, DnsResourceRecordType.A)[0].RDATA).Address);
            Assert.Empty(_dns.Server.AuthZoneManager.GetRecords(zone, added, DnsResourceRecordType.A));
        }

        [Fact]
        public void ImportLeavesEarlierNamesUnchangedWhenALaterTtlExceedsExpire()
        {
            const string zone = "import-ttl-merge.example";
            const string added = "added." + zone;
            _dns.CreateZone(zone);

            DnsResourceRecord soa = _dns.Server.AuthZoneManager.GetRecords(zone, zone, DnsResourceRecordType.SOA)[0];
            uint serial = ((DnsSOARecordData)soa.RDATA).Serial;
            uint ttl = ((DnsSOARecordData)soa.RDATA).Expire + 1;

            DnsServerException error = Assert.Throws<DnsServerException>(() => _dns.Server.AuthZoneManager.ImportRecords(zone, new DnsResourceRecord[]
            {
                new DnsResourceRecord(added, DnsResourceRecordType.A, DnsClass.IN, 300, new DnsARecordData(IPAddress.Parse("192.0.2.50"))),
                new DnsResourceRecord("late." + zone, DnsResourceRecordType.A, DnsClass.IN, ttl, new DnsARecordData(IPAddress.Parse("192.0.2.51")))
            }, false, false, false));

            Assert.Contains("EXPIRE", error.Message);
            Assert.Equal(serial, ((DnsSOARecordData)_dns.Server.AuthZoneManager.GetRecords(zone, zone, DnsResourceRecordType.SOA)[0].RDATA).Serial);
            Assert.Empty(_dns.Server.AuthZoneManager.GetRecords(zone, added, DnsResourceRecordType.A));
            Assert.Empty(_dns.Server.AuthZoneManager.GetRecords(zone, "late." + zone, DnsResourceRecordType.A));
        }

        [Fact]
        public void ImportLeavesExistingRecordsUnchangedWhenTheSoaRetryExceedsRefresh()
        {
            const string zone = "import-soa-keep.example";
            const string stay = "stay." + zone;
            const string added = "added." + zone;
            _dns.CreateZone(zone);
            _dns.Add(zone, stay, DnsResourceRecordType.A, new DnsARecordData(IPAddress.Parse("192.0.2.52")));

            DnsResourceRecord current = _dns.Server.AuthZoneManager.GetRecords(zone, zone, DnsResourceRecordType.SOA)[0];
            DnsSOARecordData soa = (DnsSOARecordData)current.RDATA;
            uint serial = soa.Serial;

            DnsServerException error = Assert.Throws<DnsServerException>(() => _dns.Server.AuthZoneManager.ImportRecords(zone, new DnsResourceRecord[]
            {
                new DnsResourceRecord(added, DnsResourceRecordType.A, DnsClass.IN, 300, new DnsARecordData(IPAddress.Parse("192.0.2.53"))),
                new DnsResourceRecord(zone, DnsResourceRecordType.SOA, DnsClass.IN, current.TTL, new DnsSOARecordData(soa.PrimaryNameServer, soa.ResponsiblePerson, soa.Serial, soa.Refresh, soa.Refresh + 1, soa.Expire, soa.Minimum))
            }, true, true, false));

            Assert.Contains("RETRY", error.Message);
            Assert.Equal(serial, ((DnsSOARecordData)_dns.Server.AuthZoneManager.GetRecords(zone, zone, DnsResourceRecordType.SOA)[0].RDATA).Serial);
            Assert.Equal(soa.Retry, ((DnsSOARecordData)_dns.Server.AuthZoneManager.GetRecords(zone, zone, DnsResourceRecordType.SOA)[0].RDATA).Retry);
            Assert.NotEmpty(_dns.Server.AuthZoneManager.GetRecords(zone, zone, DnsResourceRecordType.NS));
            Assert.Equal(IPAddress.Parse("192.0.2.52"), ((DnsARecordData)_dns.Server.AuthZoneManager.GetRecords(zone, stay, DnsResourceRecordType.A)[0].RDATA).Address);
            Assert.Empty(_dns.Server.AuthZoneManager.GetRecords(zone, added, DnsResourceRecordType.A));
        }

        [Fact]
        public void ImportLeavesExistingRecordsUnchangedWhenApexDsIsIllegal()
        {
            const string zone = "import-ds-keep.example";
            const string stay = "stay." + zone;
            const string added = "added." + zone;
            _dns.CreateZone(zone);
            _dns.Add(zone, stay, DnsResourceRecordType.A, new DnsARecordData(IPAddress.Parse("192.0.2.54")));

            uint serial = ((DnsSOARecordData)_dns.Server.AuthZoneManager.GetRecords(zone, zone, DnsResourceRecordType.SOA)[0].RDATA).Serial;

            InvalidOperationException error = Assert.Throws<InvalidOperationException>(() => _dns.Server.AuthZoneManager.ImportRecords(zone, new DnsResourceRecord[]
            {
                new DnsResourceRecord(added, DnsResourceRecordType.A, DnsClass.IN, 300, new DnsARecordData(IPAddress.Parse("192.0.2.55"))),
                new DnsResourceRecord(zone, DnsResourceRecordType.DS, DnsClass.IN, 300, new DnsDSRecordData(12345, DnssecAlgorithm.RSASHA256, DnssecDigestType.SHA256, new byte[32]))
            }, true, true, false));

            Assert.Contains("DS", error.Message);
            Assert.Equal(serial, ((DnsSOARecordData)_dns.Server.AuthZoneManager.GetRecords(zone, zone, DnsResourceRecordType.SOA)[0].RDATA).Serial);
            Assert.NotEmpty(_dns.Server.AuthZoneManager.GetRecords(zone, zone, DnsResourceRecordType.NS));
            Assert.Equal(IPAddress.Parse("192.0.2.54"), ((DnsARecordData)_dns.Server.AuthZoneManager.GetRecords(zone, stay, DnsResourceRecordType.A)[0].RDATA).Address);
            Assert.Empty(_dns.Server.AuthZoneManager.GetRecords(zone, added, DnsResourceRecordType.A));
            Assert.Empty(_dns.Server.AuthZoneManager.GetRecords(zone, zone, DnsResourceRecordType.DS));
        }

        [Fact]
        public void ImportAppliesACnameBesideADenialRecord()
        {
            const string zone = "import-nsec-cname.example";
            const string stay = "stay." + zone;
            const string name = "www." + zone;
            const string added = "added." + zone;
            _dns.CreateZone(zone);
            _dns.Add(zone, stay, DnsResourceRecordType.A, new DnsARecordData(IPAddress.Parse("192.0.2.56")));
            _dns.Add(zone, name, DnsResourceRecordType.A, new DnsARecordData(IPAddress.Parse("192.0.2.57")));
            _dns.Server.AuthZoneManager.GetAuthZone(zone, name).LoadRecords(DnsResourceRecordType.NSEC, new DnsResourceRecord[]
            {
                new DnsResourceRecord(name, DnsResourceRecordType.NSEC, DnsClass.IN, 300, new DnsNSECRecordData(zone, new DnsResourceRecordType[] { DnsResourceRecordType.A }))
            });

            _dns.Server.AuthZoneManager.ImportRecords(zone, new DnsResourceRecord[]
            {
                new DnsResourceRecord(name, DnsResourceRecordType.CNAME, DnsClass.IN, 300, new DnsCNAMERecordData("other.example")),
                new DnsResourceRecord(added, DnsResourceRecordType.A, DnsClass.IN, 300, new DnsARecordData(IPAddress.Parse("192.0.2.58")))
            }, true, true, false);

            Assert.Equal("other.example", ((DnsCNAMERecordData)_dns.Server.AuthZoneManager.GetRecords(zone, name, DnsResourceRecordType.CNAME)[0].RDATA).Domain, ignoreCase: true);
            Assert.NotEmpty(_dns.Server.AuthZoneManager.GetRecords(zone, name, DnsResourceRecordType.NSEC));
            Assert.Empty(_dns.Server.AuthZoneManager.GetRecords(zone, name, DnsResourceRecordType.A));
            Assert.Empty(_dns.Server.AuthZoneManager.GetRecords(zone, stay, DnsResourceRecordType.A));
            Assert.Equal(IPAddress.Parse("192.0.2.58"), ((DnsARecordData)_dns.Server.AuthZoneManager.GetRecords(zone, added, DnsResourceRecordType.A)[0].RDATA).Address);
        }

        [Fact]
        public void ImportAppliesAnApexApplicationRecordAndEarlierNames()
        {
            const string zone = "import-app.example";
            const string added = "added." + zone;
            _dns.CreateZone(zone);

            _dns.Server.AuthZoneManager.ImportRecords(zone, new DnsResourceRecord[]
            {
                new DnsResourceRecord(added, DnsResourceRecordType.A, DnsClass.IN, 300, new DnsARecordData(IPAddress.Parse("192.0.2.60"))),
                new DnsResourceRecord(zone, DnsResourceRecordType.APP, DnsClass.IN, 300, new DnsApplicationRecordData("TestApp", "Test.Class", ""))
            }, false, false, false);

            Assert.Equal("TestApp", ((DnsApplicationRecordData)_dns.Server.AuthZoneManager.GetRecords(zone, zone, DnsResourceRecordType.APP)[0].RDATA).AppName);
            Assert.Equal(IPAddress.Parse("192.0.2.60"), ((DnsARecordData)_dns.Server.AuthZoneManager.GetRecords(zone, added, DnsResourceRecordType.A)[0].RDATA).Address);
            Assert.NotEmpty(_dns.Server.AuthZoneManager.GetRecords(zone, zone, DnsResourceRecordType.NS));
        }

        [Fact]
        public void ImportLeavesEarlierNamesUnchangedWhenAnApexApplicationTtlExceedsExpire()
        {
            const string zone = "import-app-ttl.example";
            const string added = "added." + zone;
            _dns.CreateZone(zone);

            DnsResourceRecord soa = _dns.Server.AuthZoneManager.GetRecords(zone, zone, DnsResourceRecordType.SOA)[0];
            uint serial = ((DnsSOARecordData)soa.RDATA).Serial;
            uint ttl = ((DnsSOARecordData)soa.RDATA).Expire + 1;

            DnsServerException error = Assert.Throws<DnsServerException>(() => _dns.Server.AuthZoneManager.ImportRecords(zone, new DnsResourceRecord[]
            {
                new DnsResourceRecord(added, DnsResourceRecordType.A, DnsClass.IN, 300, new DnsARecordData(IPAddress.Parse("192.0.2.61"))),
                new DnsResourceRecord(zone, DnsResourceRecordType.APP, DnsClass.IN, ttl, new DnsApplicationRecordData("TestApp", "Test.Class", ""))
            }, false, false, false));

            Assert.Contains("EXPIRE", error.Message);
            Assert.Equal(serial, ((DnsSOARecordData)_dns.Server.AuthZoneManager.GetRecords(zone, zone, DnsResourceRecordType.SOA)[0].RDATA).Serial);
            Assert.Empty(_dns.Server.AuthZoneManager.GetRecords(zone, zone, DnsResourceRecordType.APP));
            Assert.Empty(_dns.Server.AuthZoneManager.GetRecords(zone, added, DnsResourceRecordType.A));
            Assert.NotEmpty(_dns.Server.AuthZoneManager.GetRecords(zone, zone, DnsResourceRecordType.NS));
        }

        [Fact]
        public void ImportLeavesTheGeneratedNameServerWhenTheFileIsIllegal()
        {
            const string zone = "import-ns-keep.example";
            const string added = "added." + zone;
            _dns.CreateZone(zone);

            string nameServer = ((DnsNSRecordData)_dns.Server.AuthZoneManager.GetRecords(zone, zone, DnsResourceRecordType.NS)[0].RDATA).NameServer;
            DnsResourceRecord soa = _dns.Server.AuthZoneManager.GetRecords(zone, zone, DnsResourceRecordType.SOA)[0];
            uint serial = ((DnsSOARecordData)soa.RDATA).Serial;
            uint ttl = ((DnsSOARecordData)soa.RDATA).Expire + 1;

            DnsServerException error = Assert.Throws<DnsServerException>(() => _dns.Server.AuthZoneManager.ImportRecords(zone, new DnsResourceRecord[]
            {
                new DnsResourceRecord(added, DnsResourceRecordType.A, DnsClass.IN, 300, new DnsARecordData(IPAddress.Parse("192.0.2.62"))),
                new DnsResourceRecord("late." + zone, DnsResourceRecordType.A, DnsClass.IN, ttl, new DnsARecordData(IPAddress.Parse("192.0.2.63")))
            }, false, false, false, DnsResourceRecordType.NS));

            Assert.Contains("EXPIRE", error.Message);
            Assert.Equal(serial, ((DnsSOARecordData)_dns.Server.AuthZoneManager.GetRecords(zone, zone, DnsResourceRecordType.SOA)[0].RDATA).Serial);
            Assert.Equal(nameServer, ((DnsNSRecordData)_dns.Server.AuthZoneManager.GetRecords(zone, zone, DnsResourceRecordType.NS)[0].RDATA).NameServer, ignoreCase: true);
            Assert.Empty(_dns.Server.AuthZoneManager.GetRecords(zone, added, DnsResourceRecordType.A));
        }

        [Fact]
        public void ImportReplacesTheGeneratedNameServerWhenTheFileIsLegal()
        {
            const string zone = "import-ns-replace.example";
            const string added = "added." + zone;
            _dns.CreateZone(zone);

            _dns.Server.AuthZoneManager.ImportRecords(zone, new DnsResourceRecord[]
            {
                new DnsResourceRecord(zone, DnsResourceRecordType.NS, DnsClass.IN, 300, new DnsNSRecordData("ns2.example")),
                new DnsResourceRecord(added, DnsResourceRecordType.A, DnsClass.IN, 300, new DnsARecordData(IPAddress.Parse("192.0.2.64")))
            }, false, false, false, DnsResourceRecordType.NS);

            IReadOnlyList<DnsResourceRecord> nameServers = _dns.Server.AuthZoneManager.GetRecords(zone, zone, DnsResourceRecordType.NS);
            Assert.Single(nameServers);
            Assert.Equal("ns2.example", ((DnsNSRecordData)nameServers[0].RDATA).NameServer, ignoreCase: true);
            Assert.Equal(IPAddress.Parse("192.0.2.64"), ((DnsARecordData)_dns.Server.AuthZoneManager.GetRecords(zone, added, DnsResourceRecordType.A)[0].RDATA).Address);
        }

        [Fact]
        public void ImportLeavesTheGeneratedForwarderWhenTheFileIsIllegal()
        {
            const string zone = "import-fwd-keep.example";
            Assert.NotNull(_dns.Server.AuthZoneManager.CreateForwarderZone(zone, DnsTransportProtocol.Udp, "192.0.2.65", false, DnsForwarderRecordProxyType.NoProxy, null, 0, null, null, null));

            DnsResourceRecord soa = _dns.Server.AuthZoneManager.GetRecords(zone, zone, DnsResourceRecordType.SOA)[0];
            uint serial = ((DnsSOARecordData)soa.RDATA).Serial;
            uint ttl = ((DnsSOARecordData)soa.RDATA).Expire + 1;

            DnsServerException error = Assert.Throws<DnsServerException>(() => _dns.Server.AuthZoneManager.ImportRecords(zone, new DnsResourceRecord[]
            {
                new DnsResourceRecord("late." + zone, DnsResourceRecordType.A, DnsClass.IN, ttl, new DnsARecordData(IPAddress.Parse("192.0.2.66")))
            }, false, false, false, DnsResourceRecordType.FWD));

            Assert.Contains("EXPIRE", error.Message);
            Assert.Equal(serial, ((DnsSOARecordData)_dns.Server.AuthZoneManager.GetRecords(zone, zone, DnsResourceRecordType.SOA)[0].RDATA).Serial);
            Assert.Equal("192.0.2.65", ((DnsForwarderRecordData)_dns.Server.AuthZoneManager.GetRecords(zone, zone, DnsResourceRecordType.FWD)[0].RDATA).Forwarder);
            Assert.Empty(_dns.Server.AuthZoneManager.GetRecords(zone, "late." + zone, DnsResourceRecordType.A));
        }

        [Fact]
        public void ImportReplacesTheGeneratedForwarderWhenTheFileIsLegal()
        {
            const string zone = "import-fwd-replace.example";
            Assert.NotNull(_dns.Server.AuthZoneManager.CreateForwarderZone(zone, DnsTransportProtocol.Udp, "192.0.2.67", false, DnsForwarderRecordProxyType.NoProxy, null, 0, null, null, null));

            _dns.Server.AuthZoneManager.ImportRecords(zone, new DnsResourceRecord[]
            {
                new DnsResourceRecord(zone, DnsResourceRecordType.FWD, DnsClass.IN, 0, new DnsForwarderRecordData(DnsTransportProtocol.Udp, "192.0.2.68", false, DnsForwarderRecordProxyType.NoProxy, null, 0, null, null, 0))
            }, false, false, false, DnsResourceRecordType.FWD);

            IReadOnlyList<DnsResourceRecord> forwarders = _dns.Server.AuthZoneManager.GetRecords(zone, zone, DnsResourceRecordType.FWD);
            Assert.Single(forwarders);
            Assert.Equal("192.0.2.68", ((DnsForwarderRecordData)forwarders[0].RDATA).Forwarder);
        }
    }
}
