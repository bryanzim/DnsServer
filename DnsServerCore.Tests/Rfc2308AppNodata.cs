using DnsServerCore.ApplicationCommon;
using System;
using System.IO;
using System.Net;
using System.Net.Mail;
using System.Text.Json;
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
    public sealed class Rfc2308AppNodata
    {
        [Fact]
        public async Task AutoPtrNodataUsesTheNegativeSoaTtl()
        {
            SoaServer dns = new SoaServer(7200, 60);
            AutoPtr.App app = new AutoPtr.App();
            await app.InitializeAsync(dns, "");

            DnsDatagram response = await app.ProcessRequestAsync(Question("1.2.3.4.ptr.nodata.example", DnsResourceRecordType.A), Endpoint(), DnsTransportProtocol.Udp, false, "nodata.example", "ptr.nodata.example", 30, "");

            Assert.Equal(DnsResponseCode.NoError, response.RCODE);
            Assert.True(response.AuthoritativeAnswer);
            Assert.True((response.Answer is null) || (response.Answer.Count == 0));
            Assert.Equal(60u, DnsTest.Find(response.Authority, DnsResourceRecordType.SOA, "nodata.example").TTL);
        }

        [Fact]
        public async Task AutoPtrKeepsASoaTtlThatIsAlreadyLower()
        {
            SoaServer dns = new SoaServer(30, 60);
            AutoPtr.App app = new AutoPtr.App();
            await app.InitializeAsync(dns, "");

            DnsDatagram response = await app.ProcessRequestAsync(Question("1.2.3.4.ptr.nodata.example", DnsResourceRecordType.A), Endpoint(), DnsTransportProtocol.Udp, false, "nodata.example", "ptr.nodata.example", 30, "");

            Assert.Equal(30u, DnsTest.Find(response.Authority, DnsResourceRecordType.SOA, "nodata.example").TTL);
        }

        [Fact]
        public async Task WildIpNodataUsesTheNegativeSoaTtl()
        {
            SoaServer dns = new SoaServer(7200, 60);
            WildIp.App app = new WildIp.App();
            await app.InitializeAsync(dns, "");

            DnsDatagram response = await app.ProcessRequestAsync(Question("192.0.2.1.ip.nodata.example", DnsResourceRecordType.AAAA), Endpoint(), DnsTransportProtocol.Udp, false, "nodata.example", "*.ip.nodata.example", 30, "");

            Assert.Equal(DnsResponseCode.NoError, response.RCODE);
            Assert.True(response.AuthoritativeAnswer);
            Assert.True((response.Answer is null) || (response.Answer.Count == 0));
            Assert.Equal(60u, DnsTest.Find(response.Authority, DnsResourceRecordType.SOA, "nodata.example").TTL);
        }

        [Fact]
        public async Task NoDataUsesTheNegativeSoaTtl()
        {
            SoaServer dns = new SoaServer(7200, 60);
            NoData.App app = new NoData.App();
            await app.InitializeAsync(dns, "");

            DnsDatagram response = await app.ProcessRequestAsync(Question("www.nodata.example", DnsResourceRecordType.A), Endpoint(), DnsTransportProtocol.Udp, false, "nodata.example", "www.nodata.example", 30, "{ \"blockedTypes\": [ \"A\" ] }");

            Assert.Equal(DnsResponseCode.NoError, response.RCODE);
            Assert.False(response.AuthoritativeAnswer);
            Assert.True((response.Answer is null) || (response.Answer.Count == 0));
            Assert.Equal(60u, DnsTest.Find(response.Authority, DnsResourceRecordType.SOA, "nodata.example").TTL);
        }

        [Fact]
        public async Task BlockListNodataUsesTheNegativeSoaTtl()
        {
            string folder = Path.Combine(Path.GetTempPath(), "dnsbl-nodata-" + Guid.NewGuid().ToString("n"));
            Directory.CreateDirectory(folder);
            string listFile = Path.Combine(folder, "list.txt");
            File.WriteAllText(listFile, "");

            SoaServer dns = new SoaServer(7200, 60);
            dns.ApplicationFolder = folder;
            DnsBlockList.App app = new DnsBlockList.App();

            try
            {
                await app.InitializeAsync(dns, "{ \"dnsBlockLists\": [ { \"name\": \"local\", \"type\": \"ip\", \"enabled\": true, \"blockListFile\": " + JsonSerializer.Serialize(listFile) + " } ] }");

                DnsDatagram response = null;

                for (int i = 0; (i < 50) && (response is null); i++)
                {
                    response = await app.ProcessRequestAsync(Question("2.0.0.127.bl.nodata.example", DnsResourceRecordType.AAAA), Endpoint(), DnsTransportProtocol.Udp, false, "nodata.example", "bl.nodata.example", 30, "{ \"dnsBlockLists\": [ \"local\" ] }");

                    if (response is null)
                        await Task.Delay(50);
                }

                Assert.NotNull(response);
                Assert.Equal(DnsResponseCode.NoError, response.RCODE);
                Assert.True(response.AuthoritativeAnswer);
                Assert.True((response.Answer is null) || (response.Answer.Count == 0));
                Assert.Equal(60u, DnsTest.Find(response.Authority, DnsResourceRecordType.SOA, "nodata.example").TTL);
            }
            finally
            {
                app.Dispose();

                if (Directory.Exists(folder))
                    Directory.Delete(folder, true);
            }
        }

        static DnsDatagram Question(string name, DnsResourceRecordType type)
        {
            return new DnsDatagram(7, false, DnsOpcode.StandardQuery, false, false, true, false, false, false, DnsResponseCode.NoError, [new DnsQuestionRecord(name, type, DnsClass.IN)]);
        }

        static IPEndPoint Endpoint()
        {
            return new IPEndPoint(IPAddress.Loopback, 1);
        }

        sealed class SoaServer : IDnsServer
        {
            readonly DnsResourceRecord _soa;

            public SoaServer(uint ttl, uint minimum)
            {
                _soa = new DnsResourceRecord("nodata.example", DnsResourceRecordType.SOA, DnsClass.IN, ttl, new DnsSOARecordData("ns.nodata.example", "hostmaster.nodata.example", 1, 3600, 600, 86400, minimum));
            }

            public Task<DnsDatagram> DirectQueryAsync(DnsQuestionRecord question, int timeout = 4000, CancellationToken cancellationToken = default)
            {
                return Task.FromResult(new DnsDatagram(0, true, DnsOpcode.StandardQuery, true, false, false, true, false, false, DnsResponseCode.NoError, [question], [_soa]));
            }

            public Task<DnsDatagram> DirectQueryAsync(DnsDatagram request, int timeout = 4000, CancellationToken cancellationToken = default)
            {
                throw new NotSupportedException();
            }

            public Task<DnsDatagram> DirectQueryAsync(DnsDatagram request, IPEndPoint remoteEP, int timeout = 4000, CancellationToken cancellationToken = default)
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
            { get { return "nodata-test"; } }

            public string ApplicationFolder { get; set; }

            public string ServerDomain
            { get { return "ns.nodata.example"; } }

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
