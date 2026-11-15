using System;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using TechnitiumLibrary.Net.Dns;
using DnsResponseCode = TechnitiumLibrary.Net.Dns.DnsResponseCode;
using TechnitiumLibrary.Net.Dns.ResourceRecords;
using Xunit;

namespace DnsServerCore.Tests
{
    public sealed class Rfc6672Dname : IClassFixture<DnsServerFixture>
    {
        readonly DnsServerFixture _dns;

        public Rfc6672Dname(DnsServerFixture dns)
        {
            _dns = dns;
        }

        [Fact]
        public async Task DnameSynthesizesACname()
        {
            const string zone = "dname.example";
            _dns.CreateZone(zone);
            _dns.Set(zone, "src." + zone, DnsResourceRecordType.DNAME, new DnsDNAMERecordData("dst." + zone));
            _dns.Add(zone, "www.dst." + zone, DnsResourceRecordType.A, new DnsARecordData(IPAddress.Parse("192.0.2.70")));

            DnsDatagram response = await _dns.QueryAsync("www.src." + zone, DnsResourceRecordType.A);

            Assert.Equal(DnsResponseCode.NoError, response.RCODE);

            DnsResourceRecord dname = DnsTest.Find(response.Answer, DnsResourceRecordType.DNAME, "src." + zone);
            Assert.NotNull(dname);
            Assert.Equal("dst." + zone, ((DnsDNAMERecordData)dname.RDATA).Domain, ignoreCase: true);

            DnsResourceRecord cname = DnsTest.Find(response.Answer, DnsResourceRecordType.CNAME, "www.src." + zone);
            Assert.NotNull(cname);
            Assert.Equal("www.dst." + zone, ((DnsCNAMERecordData)cname.RDATA).Domain, ignoreCase: true);

            DnsResourceRecord address = DnsTest.Find(response.Answer, DnsResourceRecordType.A, "www.dst." + zone);
            Assert.NotNull(address);
            Assert.Equal(IPAddress.Parse("192.0.2.70"), ((DnsARecordData)address.RDATA).Address);
        }

        [Fact]
        public async Task OwnerNameIsNotRedirected()
        {
            const string zone = "dname-owner.example";
            const string owner = "src." + zone;
            _dns.CreateZone(zone);
            _dns.Set(zone, owner, DnsResourceRecordType.DNAME, new DnsDNAMERecordData("dst." + zone));

            DnsDatagram address = await _dns.QueryAsync(owner, DnsResourceRecordType.A);

            Assert.Equal(DnsResponseCode.NoError, address.RCODE);
            Assert.True(address.AuthoritativeAnswer, DnsTest.Describe(address));
            Assert.Empty(address.Answer);
            Assert.Null(DnsTest.Find(address.Answer, DnsResourceRecordType.CNAME));
            Assert.NotNull(DnsTest.Find(address.Authority, DnsResourceRecordType.SOA, zone));

            DnsDatagram dname = await _dns.QueryAsync(owner, DnsResourceRecordType.DNAME);

            Assert.Equal(DnsResponseCode.NoError, dname.RCODE);
            Assert.NotNull(DnsTest.Find(dname.Answer, DnsResourceRecordType.DNAME, owner));
            Assert.Null(DnsTest.Find(dname.Answer, DnsResourceRecordType.CNAME));
        }

        [Fact]
        public async Task DataBelowADnameIsOccluded()
        {
            const string zone = "dname-occlude.example";
            _dns.CreateZone(zone);
            _dns.Set(zone, "src." + zone, DnsResourceRecordType.DNAME, new DnsDNAMERecordData("dst." + zone));
            _dns.Add(zone, "www.dst." + zone, DnsResourceRecordType.A, new DnsARecordData(IPAddress.Parse("192.0.2.71")));
            _dns.Add(zone, "www.src." + zone, DnsResourceRecordType.A, new DnsARecordData(IPAddress.Parse("192.0.2.72")));

            DnsDatagram response = await _dns.QueryAsync("www.src." + zone, DnsResourceRecordType.A);

            Assert.Equal(DnsResponseCode.NoError, response.RCODE);
            Assert.NotNull(DnsTest.Find(response.Answer, DnsResourceRecordType.CNAME, "www.src." + zone));
            DnsResourceRecord address = DnsTest.Find(response.Answer, DnsResourceRecordType.A);
            Assert.NotNull(address);
            Assert.Equal(IPAddress.Parse("192.0.2.71"), ((DnsARecordData)address.RDATA).Address);
        }

        [Fact]
        public async Task CnameCannotShareTheDnameOwner()
        {
            const string zone = "dname-cname.example";
            _dns.CreateZone(zone);
            _dns.Set(zone, "src." + zone, DnsResourceRecordType.DNAME, new DnsDNAMERecordData("dst." + zone));

            Assert.Throws<InvalidOperationException>(() => _dns.Set(zone, "src." + zone, DnsResourceRecordType.CNAME, new DnsCNAMERecordData("other.example")));
        }

        [Fact]
        public async Task OverlongSubstitutionIsYxDomain()
        {
            const string zone = "dname-long.example";
            const string owner = "s." + zone;
            string target = new string('t', 63) + "." + zone;
            _dns.CreateZone(zone);
            _dns.Set(zone, owner, DnsResourceRecordType.DNAME, new DnsDNAMERecordData(target));

            string qname = Prefix(253 - (owner.Length + 1)) + "." + owner;
            Assert.True(DnsClient.IsDomainNameValid(qname));
            Assert.False(DnsClient.IsDomainNameValid(qname.Substring(0, qname.Length - owner.Length) + target));

            DnsDatagram response = await _dns.QueryAsync(qname, DnsResourceRecordType.A);

            Assert.Equal(DnsResponseCode.YXDomain, response.RCODE);
            Assert.Null(DnsTest.Find(response.Answer, DnsResourceRecordType.CNAME));
            Assert.NotNull(DnsTest.Find(response.Answer, DnsResourceRecordType.DNAME, owner));
        }

        [Fact]
        public async Task DnameAtTheApexKeepsTheNameServers()
        {
            const string zone = "dname-apex.example";
            _dns.CreateZone(zone);
            _dns.Set(zone, zone, DnsResourceRecordType.DNAME, new DnsDNAMERecordData("dst.example.net"));

            DnsDatagram dname = await _dns.QueryAsync(zone, DnsResourceRecordType.DNAME);
            Assert.Equal(DnsResponseCode.NoError, dname.RCODE);
            Assert.NotNull(DnsTest.Find(dname.Answer, DnsResourceRecordType.DNAME, zone));

            DnsDatagram nameServers = await _dns.QueryAsync(zone, DnsResourceRecordType.NS);
            Assert.NotNull(DnsTest.Find(nameServers.Answer, DnsResourceRecordType.NS, zone));

            DnsDatagram child = await _dns.QueryAsync("www." + zone, DnsResourceRecordType.A);
            Assert.Equal(DnsResponseCode.NoError, child.RCODE);
            DnsResourceRecord cname = DnsTest.Find(child.Answer, DnsResourceRecordType.CNAME, "www." + zone);
            Assert.NotNull(cname);
            Assert.Equal("www.dst.example.net", ((DnsCNAMERecordData)cname.RDATA).Domain, ignoreCase: true);
        }

        [Fact]
        public void DnameCannotShareADelegationName()
        {
            const string zone = "dname-ns.example";
            const string name = "del." + zone;
            _dns.CreateZone(zone);
            _dns.Add(zone, name, DnsResourceRecordType.NS, new DnsNSRecordData("ns1.example.net"));

            Assert.Throws<InvalidOperationException>(() => _dns.Set(zone, name, DnsResourceRecordType.DNAME, new DnsDNAMERecordData("dst.example.net")));
            Assert.NotEmpty(_dns.Server.AuthZoneManager.GetRecords(zone, name, DnsResourceRecordType.NS));
            Assert.Empty(_dns.Server.AuthZoneManager.GetRecords(zone, name, DnsResourceRecordType.DNAME));
        }

        [Fact]
        public void NameServerCannotShareADnameOwner()
        {
            const string zone = "ns-dname.example";
            const string name = "src." + zone;
            _dns.CreateZone(zone);
            _dns.Set(zone, name, DnsResourceRecordType.DNAME, new DnsDNAMERecordData("dst.example.net"));

            Assert.Throws<InvalidOperationException>(() => _dns.Add(zone, name, DnsResourceRecordType.NS, new DnsNSRecordData("ns1.example.net")));
            Assert.Empty(_dns.Server.AuthZoneManager.GetRecords(zone, name, DnsResourceRecordType.NS));
            Assert.NotEmpty(_dns.Server.AuthZoneManager.GetRecords(zone, name, DnsResourceRecordType.DNAME));
        }

        static string Prefix(int length)
        {
            StringBuilder name = new StringBuilder(length);

            while (name.Length < length)
            {
                int room = length - name.Length;
                if (name.Length > 0)
                {
                    name.Append('.');
                    room--;
                }

                name.Append('a', Math.Min(63, room));
            }

            return name.ToString();
        }
    }
}
