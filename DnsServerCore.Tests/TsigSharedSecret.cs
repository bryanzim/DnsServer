using Xunit;

namespace DnsServerCore.Tests
{
    public sealed class TsigSharedSecret
    {
        [Fact]
        public void PlaceholderKeepsTheStoredSecret()
        {
            Assert.Equal("real-secret", DnsWebService.SelectTsigSharedSecret(DnsWebService.TsigSharedSecretHidden, "real-secret"));
        }

        [Fact]
        public void EmptySecretGeneratesAKey()
        {
            Assert.Null(DnsWebService.SelectTsigSharedSecret("", "real-secret"));
            Assert.Null(DnsWebService.SelectTsigSharedSecret(null, "real-secret"));
        }

        [Fact]
        public void PlaceholderWithoutAStoredSecretGeneratesAKey()
        {
            Assert.Null(DnsWebService.SelectTsigSharedSecret(DnsWebService.TsigSharedSecretHidden, null));
            Assert.Null(DnsWebService.SelectTsigSharedSecret(DnsWebService.TsigSharedSecretHidden, ""));
        }

        [Fact]
        public void PostedSecretReplacesTheStoredSecret()
        {
            Assert.Equal("new-secret", DnsWebService.SelectTsigSharedSecret("new-secret", "real-secret"));
        }
    }
}
