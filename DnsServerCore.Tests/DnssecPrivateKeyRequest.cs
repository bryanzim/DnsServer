using System.Collections.Generic;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Primitives;
using Xunit;

namespace DnsServerCore.Tests
{
    public sealed class DnssecPrivateKeyRequest
    {
        [Fact]
        public void QueryStringPrivateKeyIsIgnored()
        {
            DefaultHttpContext context = new DefaultHttpContext();
            context.Request.QueryString = new QueryString("?pemKskPrivateKey=from-query&pemZskPrivateKey=from-query");

            Assert.False(context.Request.TryFormOrJson("pemKskPrivateKey", out string ksk));
            Assert.False(context.Request.TryFormOrJson("pemZskPrivateKey", out string zsk));
            Assert.Null(DnsWebService.NormalizeOptionalPem(ksk));
            Assert.Null(DnsWebService.NormalizeOptionalPem(zsk));
        }

        [Fact]
        public void FormPrivateKeyIsKept()
        {
            const string pem = "-----BEGIN PRIVATE KEY-----\nbody\n-----END PRIVATE KEY-----";
            DefaultHttpContext context = new DefaultHttpContext();
            context.Request.QueryString = new QueryString("?pemKskPrivateKey=from-query");
            context.Request.ContentType = "application/x-www-form-urlencoded";
            context.Request.Form = new FormCollection(new Dictionary<string, StringValues>
            {
                ["pemKskPrivateKey"] = pem
            });

            Assert.True(context.Request.TryFormOrJson("pemKskPrivateKey", out string posted));
            Assert.Equal(pem, DnsWebService.NormalizeOptionalPem(posted));
        }

        [Fact]
        public void EmptyPrivateKeyGeneratesAKey()
        {
            DefaultHttpContext context = new DefaultHttpContext();
            context.Request.ContentType = "application/x-www-form-urlencoded";
            context.Request.Form = new FormCollection(new Dictionary<string, StringValues>
            {
                ["pemZskPrivateKey"] = "  "
            });

            Assert.True(context.Request.TryFormOrJson("pemZskPrivateKey", out string posted));
            Assert.Null(DnsWebService.NormalizeOptionalPem(posted));
            Assert.Null(DnsWebService.NormalizeOptionalPem(null));
        }

        [Fact]
        public void JsonPrivateKeyIsKept()
        {
            using JsonDocument json = JsonDocument.Parse("{\"pemZskPrivateKey\":\"json-key\"}");
            DefaultHttpContext context = new DefaultHttpContext();
            context.Request.QueryString = new QueryString("?pemZskPrivateKey=from-query");
            context.Items["jsonContent"] = json;

            Assert.True(context.Request.TryFormOrJson("pemZskPrivateKey", out string posted));
            Assert.Equal("json-key", posted);
        }
    }
}
