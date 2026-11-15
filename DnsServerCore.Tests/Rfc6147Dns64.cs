using DnsServerCore.ApplicationCommon;
using System;
using System.Net;
using System.Net.Mail;
using System.Threading;
using System.Threading.Tasks;
using TechnitiumLibrary.Net;
using TechnitiumLibrary.Net.Dns;
using DnsResponseCode = TechnitiumLibrary.Net.Dns.DnsResponseCode;
using TechnitiumLibrary.Net.Dns.ResourceRecords;
using TechnitiumLibrary.Net.Proxy;
using Xunit;

namespace DnsServerCore.Tests
{
    // RFC 6147: DNS Extensions for Network Address Translation from IPv6 Clients to IPv4 Servers
    // https://www.rfc-editor.org/rfc/rfc6147
    public sealed class Rfc6147Dns64 : IAsyncLifetime
    {
        const string Config = """
            {
              "enableDns64": true,
              "networkGroupMap": { "::/0": "everyone" },
              "groups": [
                {
                  "name": "everyone",
                  "enableDns64": true,
                  "dns64PrefixMap": { "0.0.0.0/0": "64:ff9b::/96" },
                  "excludedIpv6": [ "::ffff:0:0/96" ]
                }
              ]
            }
            """;

        static readonly IPEndPoint _client = new IPEndPoint(IPAddress.IPv6Loopback, 54321);

        ScriptedDnsServer _dns;
        Dns64.App _app;

        public async Task InitializeAsync()
        {
            _dns = new ScriptedDnsServer();
            _app = new Dns64.App();
            await _app.InitializeAsync(_dns, Config);
        }

        public Task DisposeAsync()
        {
            _app.Dispose();
            return Task.CompletedTask;
        }

        [Fact]
        public async Task EmptyAaaaIsSynthesizedFromAAndClearsTheAuthenticBit()
        {
            const string name = "www.example";
            IPAddress ipv4 = IPAddress.Parse("1.2.3.4");
            _dns.Answer = _ => Address(name, ipv4, 300);

            DnsDatagram response = await _app.PostProcessAsync(Question(name, false), _client, DnsTransportProtocol.Udp, Nodata(name, 9, authenticData: true, soaTtl: 100));

            Assert.Equal(DnsResponseCode.NoError, response.RCODE);
            Assert.False(response.AuthenticData);
            Assert.Equal(9, response.Identifier);

            DnsResourceRecord aaaa = DnsTest.Find(response.Answer, DnsResourceRecordType.AAAA, name);
            Assert.NotNull(aaaa);
            Assert.Equal(ipv4.MapToIPv6(WellKnownPrefix()), ((DnsAAAARecordData)aaaa.RDATA).Address);
            Assert.Equal(100u, aaaa.TTL);
            Assert.Null(DnsTest.Find(response.Answer, DnsResourceRecordType.A));
        }

        [Fact]
        public async Task ExistingAaaaSuppressesSynthesis()
        {
            const string name = "dual.example";
            IPAddress ipv6 = IPAddress.Parse("2001:db8::1");
            _dns.Answer = _ => throw new InvalidOperationException("An existing AAAA answer must not query for A.");

            DnsDatagram original = new DnsDatagram(3, true, DnsOpcode.StandardQuery, false, false, true, true, true, false, DnsResponseCode.NoError, [new DnsQuestionRecord(name, DnsResourceRecordType.AAAA, DnsClass.IN)], [new DnsResourceRecord(name, DnsResourceRecordType.AAAA, DnsClass.IN, 300, new DnsAAAARecordData(ipv6))]);
            DnsDatagram response = await _app.PostProcessAsync(Question(name, false), _client, DnsTransportProtocol.Udp, original);

            Assert.Equal(0, _dns.DirectQueries);
            Assert.True(response.AuthenticData);
            Assert.Equal(ipv6, ((DnsAAAARecordData)DnsTest.Find(response.Answer, DnsResourceRecordType.AAAA, name).RDATA).Address);
        }

        [Fact]
        public async Task DnssecOkSkipsSynthesis()
        {
            const string name = "signed.example";
            DnsDatagram original = Nodata(name, 4, authenticData: true, soaTtl: 300);
            _dns.Answer = _ => throw new InvalidOperationException("The DNSSEC OK bit must skip synthesis.");

            DnsDatagram response = await _app.PostProcessAsync(Question(name, true), _client, DnsTransportProtocol.Udp, original);

            Assert.Same(original, response);
            Assert.Equal(0, _dns.DirectQueries);
        }

        [Fact]
        public async Task NonNxDomainAaaaErrorStillSynthesizes()
        {
            const string name = "broken-aaaa.example";
            IPAddress ipv4 = IPAddress.Parse("8.8.8.8");
            _dns.Answer = _ => Address(name, ipv4, 120);

            DnsDatagram original = new DnsDatagram(5, true, DnsOpcode.StandardQuery, false, false, true, true, false, false, DnsResponseCode.ServerFailure, [new DnsQuestionRecord(name, DnsResourceRecordType.AAAA, DnsClass.IN)]);
            DnsDatagram response = await _app.PostProcessAsync(Question(name, false), _client, DnsTransportProtocol.Udp, original);

            Assert.Equal(DnsResponseCode.NoError, response.RCODE);
            Assert.False(response.AuthenticData);
            Assert.Equal(ipv4.MapToIPv6(WellKnownPrefix()), ((DnsAAAARecordData)DnsTest.Find(response.Answer, DnsResourceRecordType.AAAA, name).RDATA).Address);
        }

        [Fact]
        public async Task RefusedAaaaIsReturnedUnchanged()
        {
            const string name = "refused.example";
            _dns.Answer = _ => throw new InvalidOperationException("A local refusal must not query for A.");

            DnsDatagram original = new DnsDatagram(14, true, DnsOpcode.StandardQuery, false, false, true, false, false, false, DnsResponseCode.Refused, [new DnsQuestionRecord(name, DnsResourceRecordType.AAAA, DnsClass.IN)]);
            DnsDatagram response = await _app.PostProcessAsync(Question(name, false), _client, DnsTransportProtocol.Udp, original);

            Assert.Same(original, response);
            Assert.Equal(0, _dns.DirectQueries);
        }

        [Fact]
        public async Task NonRecursiveRefusedAaaaIsReturnedUnchanged()
        {
            const string name = "no-rd.example";
            _dns.Answer = _ => throw new InvalidOperationException("A refusal to a non-recursive query must not query for A.");

            DnsDatagram original = new DnsDatagram(15, true, DnsOpcode.StandardQuery, false, false, false, true, false, false, DnsResponseCode.Refused, [new DnsQuestionRecord(name, DnsResourceRecordType.AAAA, DnsClass.IN)]);
            DnsDatagram response = await _app.PostProcessAsync(Question(name, false), _client, DnsTransportProtocol.Udp, original);

            Assert.Same(original, response);
            Assert.Equal(0, _dns.DirectQueries);
        }

        [Fact]
        public async Task NxDomainAaaaIsReturnedUnchanged()
        {
            const string name = "missing.example";
            DnsDatagram original = new DnsDatagram(6, true, DnsOpcode.StandardQuery, true, false, true, true, false, false, DnsResponseCode.NxDomain, [new DnsQuestionRecord(name, DnsResourceRecordType.AAAA, DnsClass.IN)]);
            _dns.Answer = _ => throw new InvalidOperationException("NXDOMAIN must not query for A.");

            DnsDatagram response = await _app.PostProcessAsync(Question(name, false), _client, DnsTransportProtocol.Udp, original);

            Assert.Same(original, response);
            Assert.Equal(0, _dns.DirectQueries);
        }

        [Fact]
        public async Task AaaaFailureWithAnEmptyAddressAnswerReturnsThatEmptyAnswer()
        {
            const string name = "aaaa-down.example";
            _dns.Answer = _ => new DnsDatagram(0, true, DnsOpcode.StandardQuery, true, false, true, true, false, false, DnsResponseCode.NoError, [new DnsQuestionRecord(name, DnsResourceRecordType.A, DnsClass.IN)]);

            DnsDatagram original = new DnsDatagram(13, true, DnsOpcode.StandardQuery, false, false, true, true, false, false, DnsResponseCode.ServerFailure, [new DnsQuestionRecord(name, DnsResourceRecordType.AAAA, DnsClass.IN)]);
            DnsDatagram response = await _app.PostProcessAsync(Question(name, false), _client, DnsTransportProtocol.Udp, original);

            Assert.NotSame(original, response);
            Assert.Equal(DnsResponseCode.NoError, response.RCODE);
            Assert.Empty(response.Answer);
        }

        [Fact]
        public async Task AddressQueryErrorReplacesTheAaaaNodata()
        {
            const string name = "addr-error.example";
            _dns.Answer = _ => new DnsDatagram(0, true, DnsOpcode.StandardQuery, false, false, true, true, false, false, DnsResponseCode.ServerFailure, [new DnsQuestionRecord(name, DnsResourceRecordType.A, DnsClass.IN)]);

            DnsDatagram original = Nodata(name, 7, authenticData: true, soaTtl: 300);
            DnsDatagram response = await _app.PostProcessAsync(Question(name, false), _client, DnsTransportProtocol.Udp, original);

            Assert.NotSame(original, response);
            Assert.Equal(DnsResponseCode.ServerFailure, response.RCODE);
            Assert.False(response.AuthenticData);
            Assert.Empty(response.Answer);
        }

        [Fact]
        public async Task AddressQueryNameErrorReplacesTheAaaaNodata()
        {
            const string name = "addr-missing.example";
            _dns.Answer = _ => new DnsDatagram(0, true, DnsOpcode.StandardQuery, true, false, true, true, false, false, DnsResponseCode.NxDomain, [new DnsQuestionRecord(name, DnsResourceRecordType.A, DnsClass.IN)]);

            DnsDatagram response = await _app.PostProcessAsync(Question(name, false), _client, DnsTransportProtocol.Udp, Nodata(name, 8, authenticData: false, soaTtl: 300));

            Assert.Equal(DnsResponseCode.NxDomain, response.RCODE);
            Assert.Empty(response.Answer);
        }

        [Fact]
        public async Task WellKnownPrefixDoesNotSynthesizeANonGlobalAddress()
        {
            const string name = "private.example";
            DnsDatagram original = Nodata(name, 10, authenticData: false, soaTtl: 300);
            _dns.Answer = _ => Address(name, IPAddress.Parse("10.1.2.3"), 300);

            DnsDatagram response = await _app.PostProcessAsync(Question(name, false), _client, DnsTransportProtocol.Udp, original);

            Assert.Same(original, response);
        }

        [Fact]
        public async Task ExcludedIpv4MappedAaaaIsReplacedBySynthesis()
        {
            const string name = "mapped.example";
            IPAddress ipv4 = IPAddress.Parse("9.9.9.9");
            IPAddress mapped = IPAddress.Parse("::ffff:192.0.2.1");
            _dns.Answer = _ => Address(name, ipv4, 60);

            DnsDatagram original = new DnsDatagram(11, true, DnsOpcode.StandardQuery, false, false, true, true, true, false, DnsResponseCode.NoError, [new DnsQuestionRecord(name, DnsResourceRecordType.AAAA, DnsClass.IN)], [new DnsResourceRecord(name, DnsResourceRecordType.AAAA, DnsClass.IN, 60, new DnsAAAARecordData(mapped))]);
            DnsDatagram response = await _app.PostProcessAsync(Question(name, false), _client, DnsTransportProtocol.Udp, original);

            Assert.Equal(DnsResponseCode.NoError, response.RCODE);
            Assert.False(response.AuthenticData);

            foreach (DnsResourceRecord answer in response.Answer)
            {
                if (answer.RDATA is DnsAAAARecordData aaaa)
                    Assert.False(aaaa.Address.Equals(mapped));
            }

            Assert.Equal(ipv4.MapToIPv6(WellKnownPrefix()), ((DnsAAAARecordData)DnsTest.Find(response.Answer, DnsResourceRecordType.AAAA, name).RDATA).Address);
        }

        [Fact]
        public async Task ReverseNameUnderThePrefixIsACnameToTheIpv4ReverseName()
        {
            IPAddress ipv4 = IPAddress.Parse("1.2.3.4");
            IPAddress ipv6 = ipv4.MapToIPv6(WellKnownPrefix());
            DnsDatagram request = new DnsDatagram(12, false, DnsOpcode.StandardQuery, false, false, true, false, false, false, DnsResponseCode.NoError, [new DnsQuestionRecord(ipv6.GetReverseDomain(), DnsResourceRecordType.PTR, DnsClass.IN)]);

            DnsDatagram response = await _app.ProcessRequestAsync(request, _client, DnsTransportProtocol.Udp, true);

            Assert.NotNull(response);
            Assert.Equal(DnsResponseCode.NoError, response.RCODE);
            Assert.False(response.AuthenticData);

            DnsResourceRecord cname = DnsTest.Find(response.Answer, DnsResourceRecordType.CNAME, ipv6.GetReverseDomain());
            Assert.NotNull(cname);
            Assert.Equal(ipv4.GetReverseDomain(), ((DnsCNAMERecordData)cname.RDATA).Domain, ignoreCase: true);
        }

        static TechnitiumLibrary.Net.NetworkAddress WellKnownPrefix()
        {
            return TechnitiumLibrary.Net.NetworkAddress.Parse("64:ff9b::/96");
        }

        static DnsDatagram Question(string name, bool dnssecOk)
        {
            return new DnsDatagram(1, false, DnsOpcode.StandardQuery, false, false, true, false, false, false, DnsResponseCode.NoError, [new DnsQuestionRecord(name, DnsResourceRecordType.AAAA, DnsClass.IN)], udpPayloadSize: dnssecOk ? (ushort)1232 : ushort.MinValue, ednsFlags: dnssecOk ? EDnsHeaderFlags.DNSSEC_OK : EDnsHeaderFlags.None);
        }

        static DnsDatagram Nodata(string name, ushort id, bool authenticData, uint soaTtl)
        {
            DnsResourceRecord soa = new DnsResourceRecord("example", DnsResourceRecordType.SOA, DnsClass.IN, soaTtl, new DnsSOARecordData("ns.example", "hostmaster.example", 1, 300, 60, 86400, 300));
            return new DnsDatagram(id, true, DnsOpcode.StandardQuery, true, false, true, true, authenticData, false, DnsResponseCode.NoError, [new DnsQuestionRecord(name, DnsResourceRecordType.AAAA, DnsClass.IN)], null, [soa]);
        }

        static DnsDatagram Address(string name, IPAddress ipv4, uint ttl)
        {
            return new DnsDatagram(2, true, DnsOpcode.StandardQuery, false, false, true, true, false, false, DnsResponseCode.NoError, [new DnsQuestionRecord(name, DnsResourceRecordType.A, DnsClass.IN)], [new DnsResourceRecord(name, DnsResourceRecordType.A, DnsClass.IN, ttl, new DnsARecordData(ipv4))]);
        }

        sealed class ScriptedDnsServer : IDnsServer
        {
            public Func<DnsDatagram, DnsDatagram> Answer { get; set; }

            public int DirectQueries { get; private set; }

            public Task<DnsDatagram> DirectQueryAsync(DnsDatagram request, IPEndPoint remoteEP, int timeout = 4000, CancellationToken cancellationToken = default)
            {
                DirectQueries++;
                return Task.FromResult(Answer(request));
            }

            public Task<DnsDatagram> DirectQueryAsync(DnsDatagram request, int timeout = 4000, CancellationToken cancellationToken = default)
            {
                return DirectQueryAsync(request, null, timeout, cancellationToken);
            }

            public Task<DnsDatagram> DirectQueryAsync(DnsQuestionRecord question, int timeout = 4000, CancellationToken cancellationToken = default)
            {
                throw new NotSupportedException();
            }

            public Task<DnsDatagram> ResolveAsync(DnsQuestionRecord question, CancellationToken cancellationToken = default)
            {
                throw new NotSupportedException();
            }

            public bool IsLocallyServedZone(string domain)
            {
                return false;
            }

            public void WriteLog(string message)
            { }

            public void WriteLog(Exception ex)
            { }

            public void WriteLog(string message, Exception ex)
            { }

            public string ApplicationName
            { get { return "dns64-test"; } }

            public string ApplicationFolder
            { get { return ""; } }

            public string ServerDomain
            { get { return "ns.example"; } }

            public MailAddress ResponsiblePerson
            { get { return null; } }

            public IDnsCache DnsCache
            { get { return null; } }

            public NetProxy Proxy
            { get { return null; } }

            public IPv6Mode IPv6Mode
            { get { return IPv6Mode.Enabled; } }

            public ushort UdpPayloadSize
            { get { return 1232; } }
        }
    }
}
