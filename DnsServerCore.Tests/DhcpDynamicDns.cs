using DnsServerCore.Auth;
using DnsServerCore.Dhcp;
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;
using Xunit;

namespace DnsServerCore.Tests
{
    public sealed class DhcpDynamicDns : IClassFixture<DnsServerFixture>, IDisposable
    {
        const string Zone = "dhcp.example";

        readonly DnsServerFixture _dns;
        readonly string _folder;
        readonly LogManager _log;
        readonly AuthManager _auth;
        readonly DhcpServer _dhcp;
        readonly Scope _scope;

        public DhcpDynamicDns(DnsServerFixture dns)
        {
            _dns = dns;
            _folder = Path.Combine(Path.GetTempPath(), "dhcp-dns-" + Guid.NewGuid().ToString("n"));
            Directory.CreateDirectory(_folder);
            Directory.CreateDirectory(Path.Combine(_folder, "scopes"));

            _log = new LogManager(true, _folder);
            _log.LoggingType = LoggingType.None;

            _auth = new AuthManager(null, _folder, _log);
            _dhcp = new DhcpServer(Path.Combine(_folder, "scopes"), _log);
            _dhcp.DnsServer = dns.Server;
            _dhcp.AuthManager = _auth;

            _scope = new Scope("Dynamic", true, IPAddress.Parse("192.0.2.1"), IPAddress.Parse("192.0.2.254"), IPAddress.Parse("255.255.255.0"), _log, _dhcp);
            _scope.DomainName = Zone;
            _scope.DnsUpdates = true;

            if (dns.Server.AuthZoneManager.GetAuthZoneInfo(Zone) is null)
                dns.CreateZone(Zone);
        }

        public void Dispose()
        {
            _dhcp.Dispose();
            _auth.Dispose();
            _log.DisposeAsync().AsTask().GetAwaiter().GetResult();

            if (Directory.Exists(_folder))
                Directory.Delete(_folder, true);
        }

        [Theory]
        [InlineData("*.example.com", "example.com", null)]
        [InlineData("*", "example.com", null)]
        [InlineData("foo.bar.example.com", "example.com", "foo.example.com")]
        [InlineData("laptop.example.com", "example.com", "laptop.example.com")]
        [InlineData("laptop", "example.com", "laptop.example.com")]
        [InlineData("my laptop", "example.com", "my-laptop.example.com")]
        [InlineData("", "example.com", null)]
        public void DynamicDnsNameIsOneHostLabel(string clientName, string scopeDomain, string expected)
        {
            Assert.Equal(expected, DhcpServer.GetDynamicDnsName(clientName, scopeDomain));
        }

        [Fact]
        public void WildcardLeaseIsNotPublished()
        {
            Publish("*.dhcp.example", "192.0.2.10");

            Assert.Empty(_dns.Server.AuthZoneManager.GetRecords(Zone, "*.dhcp.example", DnsResourceRecordType.A));
        }

        [Fact]
        public void ExtraLabelIsNotPublished()
        {
            Publish("foo.bar.dhcp.example", "192.0.2.11");

            Assert.Empty(_dns.Server.AuthZoneManager.GetRecords(Zone, "foo.bar.dhcp.example", DnsResourceRecordType.A));
            Assert.Empty(_dns.Server.AuthZoneManager.GetRecords(Zone, "foo.dhcp.example", DnsResourceRecordType.A));
        }

        [Fact]
        public void SingleLabelLeaseIsPublished()
        {
            Publish("laptop.dhcp.example", "192.0.2.12");

            IReadOnlyList<DnsResourceRecord> records = _dns.Server.AuthZoneManager.GetRecords(Zone, "laptop.dhcp.example", DnsResourceRecordType.A);

            Assert.Single(records);
            Assert.Equal(IPAddress.Parse("192.0.2.12"), (records[0].RDATA as DnsARecordData).Address);
        }

        [Fact]
        public void NameThatAlreadyHasANonAddressRecordIsNotClaimed()
        {
            _dns.Add(Zone, "www.dhcp.example", DnsResourceRecordType.TXT, new DnsTXTRecordData("taken"));

            Publish("www.dhcp.example", "192.0.2.13");

            Assert.Empty(_dns.Server.AuthZoneManager.GetRecords(Zone, "www.dhcp.example", DnsResourceRecordType.A));
            Assert.Single(_dns.Server.AuthZoneManager.GetRecords(Zone, "www.dhcp.example", DnsResourceRecordType.TXT));
        }

        [Fact]
        public void ReservedWildcardIsNotPublished()
        {
            Lease lease = new Lease(LeaseType.Reserved, "*.dhcp.example", DhcpMessageHardwareAddressType.Ethernet, "00-11-22-33-44-66", IPAddress.Parse("192.0.2.14"), null);

            _dhcp.AddDnsEntries(_scope, lease);

            Assert.Empty(_dns.Server.AuthZoneManager.GetRecords(Zone, "*.dhcp.example", DnsResourceRecordType.A));
        }

        void Publish(string hostName, string address)
        {
            Lease lease = new Lease(LeaseType.Dynamic, hostName, DhcpMessageHardwareAddressType.Ethernet, "00-11-22-33-44-55", IPAddress.Parse(address), null);
            _dhcp.AddDnsEntries(_scope, lease);
        }
    }
}
