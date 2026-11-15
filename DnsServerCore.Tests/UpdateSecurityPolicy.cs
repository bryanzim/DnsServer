using System.Collections.Generic;
using System.Net;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;
using Xunit;

namespace DnsServerCore.Tests
{
    public sealed class UpdateSecurityPolicy
    {
        static readonly IReadOnlyDictionary<string, IReadOnlyList<DnsResourceRecordType>> Policy = new Dictionary<string, IReadOnlyList<DnsResourceRecordType>>
        {
            ["www.example.com"] = [DnsResourceRecordType.A],
            ["*.example.com"] = [DnsResourceRecordType.AAAA]
        };

        [Fact]
        public void ExactNameAndTypeArePermitted()
        {
            Assert.True(DnsServerCore.Dns.DnsServer.IsUpdatePolicyPermitted("www.example.com", DnsResourceRecordType.A, Policy));
            Assert.True(DnsServerCore.Dns.DnsServer.IsUpdatePolicyPermitted("WWW.EXAMPLE.COM", DnsResourceRecordType.A, Policy));
        }

        [Fact]
        public void OtherNamesAndTypesAreRefused()
        {
            Assert.False(DnsServerCore.Dns.DnsServer.IsUpdatePolicyPermitted("example.com", DnsResourceRecordType.A, Policy));
            Assert.False(DnsServerCore.Dns.DnsServer.IsUpdatePolicyPermitted("other.example.net", DnsResourceRecordType.A, Policy));
            Assert.False(DnsServerCore.Dns.DnsServer.IsUpdatePolicyPermitted("www.example.com", DnsResourceRecordType.TXT, Policy));
            Assert.False(DnsServerCore.Dns.DnsServer.IsUpdatePolicyPermitted("www.example.com", DnsResourceRecordType.ANY, Policy));
        }

        [Fact]
        public void WildcardCoversSubdomains()
        {
            Assert.True(DnsServerCore.Dns.DnsServer.IsUpdatePolicyPermitted("www.example.com", DnsResourceRecordType.AAAA, Policy));
            Assert.True(DnsServerCore.Dns.DnsServer.IsUpdatePolicyPermitted("a.b.example.com", DnsResourceRecordType.AAAA, Policy));
            Assert.False(DnsServerCore.Dns.DnsServer.IsUpdatePolicyPermitted("example.com", DnsResourceRecordType.AAAA, Policy));
            Assert.False(DnsServerCore.Dns.DnsServer.IsUpdatePolicyPermitted("example.com.evil", DnsResourceRecordType.AAAA, Policy));
        }

        [Fact]
        public void AnyTypeInThePolicyAllowsTheRecordType()
        {
            Dictionary<string, IReadOnlyList<DnsResourceRecordType>> policy = new Dictionary<string, IReadOnlyList<DnsResourceRecordType>>
            {
                ["www.example.com"] = [DnsResourceRecordType.ANY]
            };

            Assert.True(DnsServerCore.Dns.DnsServer.IsUpdatePolicyPermitted("www.example.com", DnsResourceRecordType.TXT, policy));
        }

        [Fact]
        public void PrerequisiteOutsideThePolicyRefusesTheUpdate()
        {
            DnsResourceRecord allowed = Address("www.example.com", DnsResourceRecordType.A);
            DnsResourceRecord probe = Address("secret.example.com", DnsResourceRecordType.A);
            DnsResourceRecord anyProbe = Address("www.example.com", DnsResourceRecordType.ANY);

            Assert.True(DnsServerCore.Dns.DnsServer.IsUpdateMessagePermitted(null, [allowed], Policy));
            Assert.True(DnsServerCore.Dns.DnsServer.IsUpdateMessagePermitted([allowed], [allowed], Policy));
            Assert.False(DnsServerCore.Dns.DnsServer.IsUpdateMessagePermitted([probe], [allowed], Policy));
            Assert.False(DnsServerCore.Dns.DnsServer.IsUpdateMessagePermitted([anyProbe], [allowed], Policy));
            Assert.False(DnsServerCore.Dns.DnsServer.IsUpdateMessagePermitted(null, [probe], Policy));
        }

        static DnsResourceRecord Address(string name, DnsResourceRecordType type)
        {
            return new DnsResourceRecord(name, type, DnsClass.IN, 300, new DnsARecordData(IPAddress.Parse("192.0.2.20")));
        }
    }
}
