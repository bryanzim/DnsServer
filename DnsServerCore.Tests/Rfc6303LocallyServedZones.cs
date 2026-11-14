using System.Threading.Tasks;
using TechnitiumLibrary.Net.Dns;
using DnsResponseCode = TechnitiumLibrary.Net.Dns.DnsResponseCode;
using TechnitiumLibrary.Net.Dns.EDnsOptions;
using TechnitiumLibrary.Net.Dns.ResourceRecords;
using Xunit;

namespace DnsServerCore.Tests
{
    // RFC 6303 locally served zones, RFC 6761 special-use names, RFC 7793 shared address space,
    // RFC 8375 home.arpa, RFC 9462 resolver.arpa, and RFC 9665 service.arpa.
    public sealed class Rfc6303LocallyServedZones : IClassFixture<DnsServerFixture>
    {
        readonly DnsServerFixture _dns;

        public Rfc6303LocallyServedZones(DnsServerFixture dns)
        {
            _dns = dns;
        }

        [Fact]
        public async Task LocalhostResolvesToTheLoopbackAddresses()
        {
            DnsDatagram address = await Ask("localhost", DnsResourceRecordType.A);
            DnsDatagram address6 = await Ask("localhost", DnsResourceRecordType.AAAA);
            DnsDatagram pointer = await Ask("1.0.0.127.in-addr.arpa", DnsResourceRecordType.PTR);

            AssertAuthoritative(address, DnsResponseCode.NoError);
            Assert.Equal(System.Net.IPAddress.Loopback, ((DnsARecordData)DnsTest.Find(address.Answer, DnsResourceRecordType.A, "localhost").RDATA).Address);
            AssertSynthesized(address);

            AssertAuthoritative(address6, DnsResponseCode.NoError);
            Assert.Equal(System.Net.IPAddress.IPv6Loopback, ((DnsAAAARecordData)DnsTest.Find(address6.Answer, DnsResourceRecordType.AAAA, "localhost").RDATA).Address);

            AssertAuthoritative(pointer, DnsResponseCode.NoError);
            Assert.Equal("localhost", ((DnsPTRRecordData)DnsTest.Find(pointer.Answer, DnsResourceRecordType.PTR).RDATA).Domain, ignoreCase: true);
        }

        [Theory]
        [InlineData("1.2.3.10.in-addr.arpa")]
        [InlineData("1.0.64.100.in-addr.arpa")]
        [InlineData("1.0.127.100.in-addr.arpa")]
        [InlineData("www.home.arpa")]
        [InlineData("foo.localhost")]
        [InlineData("www.resolver.arpa")]
        [InlineData("www.service.arpa")]
        public async Task LocallyServedNameThatDoesNotExistIsNxDomain(string name)
        {
            DnsDatagram response = await Ask(name, DnsResourceRecordType.PTR);

            AssertAuthoritative(response, DnsResponseCode.NxDomain);
            Assert.Empty(response.Answer);
            Assert.NotNull(DnsTest.Find(response.Authority, DnsResourceRecordType.SOA));
            AssertSynthesized(response);
        }

        [Theory]
        [InlineData("invalid")]
        [InlineData("test")]
        [InlineData("local")]
        [InlineData("onion")]
        [InlineData("www.invalid")]
        public async Task SpecialUseNameIsNxDomain(string name)
        {
            DnsDatagram response = await Ask(name, DnsResourceRecordType.A);

            AssertAuthoritative(response, DnsResponseCode.NxDomain);
            Assert.Empty(response.Answer);
            Assert.NotNull(DnsTest.Find(response.Authority, DnsResourceRecordType.SOA));
            AssertSynthesized(response);
        }

        [Fact]
        public void DelegationSignerForASpecialUseNameIsLeftForTheParent()
        {
            DnsDatagram ds = new DnsDatagram(1, false, DnsOpcode.StandardQuery, false, false, true, false, false, false, DnsResponseCode.NoError, [new DnsQuestionRecord("invalid", DnsResourceRecordType.DS, DnsClass.IN)]);
            DnsDatagram address = new DnsDatagram(1, false, DnsOpcode.StandardQuery, false, false, true, false, false, false, DnsResponseCode.NoError, [new DnsQuestionRecord("invalid", DnsResourceRecordType.A, DnsClass.IN)]);

            Assert.Null(_dns.Server.SpecialZoneManager.Query(ds));
            Assert.NotNull(_dns.Server.SpecialZoneManager.Query(address));
        }

        Task<DnsDatagram> Ask(string name, DnsResourceRecordType type)
        {
            DnsDatagram request = new DnsDatagram(1, false, DnsOpcode.StandardQuery, false, false, true, false, false, false, DnsResponseCode.NoError, [new DnsQuestionRecord(name, type, DnsClass.IN)], udpPayloadSize: 1232);
            return _dns.Server.DirectQueryAsync(request, 10000);
        }

        static void AssertAuthoritative(DnsDatagram response, DnsResponseCode rcode)
        {
            Assert.Equal(rcode, response.RCODE);
            Assert.True(response.AuthoritativeAnswer, DnsTest.Describe(response));
        }

        static void AssertSynthesized(DnsDatagram response)
        {
            Assert.NotNull(response.EDNS);

            EDnsExtendedDnsErrorOptionData synthesized = null;

            foreach (EDnsOption option in response.EDNS.Options)
            {
                if ((option.Code == EDnsOptionCode.EXTENDED_DNS_ERROR) && (option.Data is EDnsExtendedDnsErrorOptionData ede) && (ede.InfoCode == EDnsExtendedDnsErrorCode.Synthesized))
                    synthesized = ede;
            }

            Assert.NotNull(synthesized);
            Assert.Contains("locally-served-dns-zones", synthesized.ExtraText);
        }
    }
}
