using System.Net;
using DnsServerCore.Dns;
using DnsServerCore.Dns.Zones;
using TechnitiumLibrary.Net;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.EDnsOptions;
using TechnitiumLibrary.Net.Dns.ResourceRecords;
using DnsResponseCode = TechnitiumLibrary.Net.Dns.DnsResponseCode;
using Xunit;

namespace DnsServerCore.Tests
{
    public sealed class ForwardedClientIdentity
    {
        static readonly IPAddress Peer = IPAddress.Parse("192.168.1.40");

        [Fact]
        public void FullClientPrefixNamesTheClient()
        {
            IPAddress client = IPAddress.Parse("203.0.113.8");
            IPAddress ipv6 = IPAddress.Parse("2001:db8::8");

            Assert.Equal(client, DnsServer.SelectEcsClientAddress(Peer, new EDnsClientSubnetOptionData(32, 0, client)));
            Assert.Equal(ipv6, DnsServer.SelectEcsClientAddress(Peer, new EDnsClientSubnetOptionData(128, 0, ipv6)));
            Assert.Equal(client, DnsServer.SelectEcsClientAddress(IPAddress.Loopback, new EDnsClientSubnetOptionData(32, 0, client)));
        }

        [Fact]
        public void PrivilegedOrPartialPrefixStaysWithThePeer()
        {
            Assert.Equal(Peer, DnsServer.SelectEcsClientAddress(Peer, null));
            Assert.Equal(Peer, DnsServer.SelectEcsClientAddress(Peer, new EDnsClientSubnetOptionData(24, 0, IPAddress.Parse("203.0.113.0"))));
            Assert.Equal(Peer, DnsServer.SelectEcsClientAddress(Peer, new EDnsClientSubnetOptionData(32, 0, IPAddress.Loopback)));
            Assert.Equal(Peer, DnsServer.SelectEcsClientAddress(Peer, new EDnsClientSubnetOptionData(32, 0, IPAddress.Parse("127.0.0.2"))));
            Assert.Equal(Peer, DnsServer.SelectEcsClientAddress(Peer, new EDnsClientSubnetOptionData(32, 0, IPAddress.Any)));
            Assert.Equal(Peer, DnsServer.SelectEcsClientAddress(Peer, new EDnsClientSubnetOptionData(128, 0, IPAddress.IPv6Loopback)));
            Assert.Equal(Peer, DnsServer.SelectEcsClientAddress(Peer, new EDnsClientSubnetOptionData(128, 0, IPAddress.IPv6Any)));
            Assert.Equal(IPAddress.Parse("10.1.2.3"), DnsServer.SelectEcsClientAddress(IPAddress.Parse("::ffff:10.1.2.3"), new EDnsClientSubnetOptionData(32, 0, IPAddress.Loopback)));
            Assert.Equal(IPAddress.Loopback, DnsServer.SelectEcsClientAddress(IPAddress.Loopback, new EDnsClientSubnetOptionData(32, 0, IPAddress.Loopback)));
        }

        [Fact]
        public void QueryLogUsesTheForwardedAddressAndKeepsTheConnectionPort()
        {
            IPEndPoint connection = new IPEndPoint(Peer, 5353);
            IPAddress client = IPAddress.Parse("203.0.113.8");

            IPEndPoint logged = DnsServer.LoggedEndPoint(connection, client);

            Assert.Equal(client, logged.Address);
            Assert.Equal(5353, logged.Port);
            Assert.Same(connection, DnsServer.LoggedEndPoint(connection, Peer));
            Assert.Same(connection, DnsServer.LoggedEndPoint(connection, null));
        }

        [Fact]
        public void RecursionRequiresTheConnectionAndTheForwardedClient()
        {
            static bool IsPrivate(IPAddress address)
            {
                if (address.IsIPv4MappedToIPv6)
                    address = address.MapToIPv4();

                return NetUtilities.IsPrivateIP(address);
            }

            Assert.False(DnsServer.IsRecursionAllowedFor(IPAddress.Parse("203.0.113.5"), IPAddress.Parse("10.0.0.1"), IsPrivate));
            Assert.False(DnsServer.IsRecursionAllowedFor(Peer, IPAddress.Parse("203.0.113.8"), IsPrivate));
            Assert.True(DnsServer.IsRecursionAllowedFor(Peer, IPAddress.Parse("10.1.2.3"), IsPrivate));
            Assert.True(DnsServer.IsRecursionAllowedFor(Peer, null, IsPrivate));
            Assert.True(DnsServer.IsRecursionAllowedFor(Peer, IPAddress.Parse("::ffff:192.168.1.40"), IsPrivate));
        }
    }

    public sealed class ForwardedClientZoneAccess : IClassFixture<DnsServerFixture>
    {
        readonly DnsServerFixture _dns;

        public ForwardedClientZoneAccess(DnsServerFixture dns)
        {
            _dns = dns;
        }

        [Fact]
        public async System.Threading.Tasks.Task ForwardedAddressCannotWidenZoneAccess()
        {
            const string zone = "forwarded-access.example";
            _dns.CreateZone(zone).QueryAccess = AuthZoneQueryAccess.AllowOnlyPrivateNetworks;
            _dns.Add(zone, "www." + zone, DnsResourceRecordType.A, new DnsARecordData(IPAddress.Parse("192.0.2.40")));

            DnsDatagram request = Question("www." + zone);
            DnsDatagram internalRequest = Question("www." + zone);

            DnsServer.SetForwardedClient(internalRequest, IPAddress.Parse("203.0.113.50"));
            DnsDatagram internalResponse = await _dns.Server.DirectQueryAsync(internalRequest, new IPEndPoint(IPAddress.Loopback, 0), 10000);
            Assert.Equal(DnsResponseCode.NoError, internalResponse.RCODE);

            DnsServer.SetForwardedClient(request, IPAddress.Parse("203.0.113.50"));
            DnsDatagram privateConnection = await _dns.Server.DirectQueryAsync(request, new IPEndPoint(IPAddress.Parse("192.168.1.20"), 53), 10000);
            Assert.Equal(DnsResponseCode.Refused, privateConnection.RCODE);

            DnsDatagram allowedRequest = Question("www." + zone);
            DnsServer.SetForwardedClient(allowedRequest, IPAddress.Parse("10.9.8.7"));
            DnsDatagram allowed = await _dns.Server.DirectQueryAsync(allowedRequest, new IPEndPoint(IPAddress.Parse("192.168.1.20"), 53), 10000);
            Assert.Equal(DnsResponseCode.NoError, allowed.RCODE);
            Assert.NotNull(DnsTest.Find(allowed.Answer, DnsResourceRecordType.A, "www." + zone));
        }

        [Fact]
        public async System.Threading.Tasks.Task ForwardedNameServerCannotQueryOrTransfer()
        {
            const string zone = "forwarded-ns.example";
            _dns.CreateZone(zone).QueryAccess = AuthZoneQueryAccess.AllowOnlyZoneNameServers;

            string nameServer = "ns1." + zone;
            IPAddress nameServerAddress = IPAddress.Parse("192.0.2.51");
            _dns.Add(zone, zone, DnsResourceRecordType.NS, new DnsNSRecordData(nameServer));
            _dns.Add(zone, nameServer, DnsResourceRecordType.A, new DnsARecordData(nameServerAddress));
            _dns.Add(zone, "www." + zone, DnsResourceRecordType.A, new DnsARecordData(IPAddress.Parse("192.0.2.40")));

            DnsDatagram query = Question("www." + zone);
            DnsDatagram axfr = new DnsDatagram(1, false, DnsOpcode.StandardQuery, false, false, false, false, false, false, DnsResponseCode.NoError, [new DnsQuestionRecord(zone, DnsResourceRecordType.AXFR, DnsClass.IN)]);
            IPEndPoint other = new IPEndPoint(IPAddress.Parse("192.0.2.10"), 53);

            DnsServer.SetForwardedClient(query, nameServerAddress);
            DnsDatagram named = await _dns.Server.DirectQueryAsync(query, other, 10000);
            Assert.Equal(DnsResponseCode.Refused, named.RCODE);

            DnsServer.SetForwardedClient(axfr, nameServerAddress);
            DnsDatagram transfer = await _dns.Server.DirectQueryAsync(axfr, other, 10000);
            Assert.Equal(DnsResponseCode.Refused, transfer.RCODE);

            DnsDatagram server = await _dns.Server.DirectQueryAsync(query, new IPEndPoint(nameServerAddress, 53), 10000);
            Assert.Equal(DnsResponseCode.NoError, server.RCODE);
        }

        static DnsDatagram Question(string name)
        {
            return new DnsDatagram(1, false, DnsOpcode.StandardQuery, false, false, false, false, false, false, DnsResponseCode.NoError, [new DnsQuestionRecord(name, DnsResourceRecordType.A, DnsClass.IN)]);
        }
    }
}
