using DnsServerCore;
using DnsServerCore.Auth;
using System;
using System.IO;
using System.Net;
using System.Threading.Tasks;
using Xunit;

namespace DnsServerCore.Tests
{
    public sealed class LoginLockout : IDisposable
    {
        readonly string _folder;
        readonly LogManager _log;
        readonly AuthManager _auth;

        public LoginLockout()
        {
            _folder = Path.Combine(Path.GetTempPath(), "login-lockout-" + Guid.NewGuid().ToString("n"));
            Directory.CreateDirectory(_folder);

            _log = new LogManager(true, _folder);
            _log.LoggingType = LoggingType.None;
            _auth = new AuthManager(null, _folder, _log);
            _auth.CreateUser("Lockout", "lockout", "correct-password");
        }

        [Fact]
        public async Task FailedAttemptsBlockOnlyThatAddress()
        {
            IPAddress blocked = IPAddress.Parse("192.0.2.10");
            IPAddress other = IPAddress.Parse("192.0.2.11");

            for (int attempt = 0; attempt < 5; attempt++)
                await AssertFails(blocked, "Invalid username or password");

            await AssertFails(blocked, "attempts exceeded");
            await AssertFails(other, "Invalid username or password");

            UserSession session = await _auth.CreateSessionAsync(UserSessionType.Standard, null, "lockout", "correct-password", null, other, "test");
            Assert.NotNull(session);
            Assert.Equal(other, session.LastSeenRemoteAddress);
        }

        async Task AssertFails(IPAddress address, string message)
        {
            DnsWebServiceException error = await Assert.ThrowsAsync<DnsWebServiceException>(delegate
            {
                return _auth.CreateSessionAsync(UserSessionType.Standard, null, "lockout", "wrong-password", null, address, "test");
            });

            Assert.Contains(message, error.Message);
        }

        public void Dispose()
        {
            _auth.Dispose();
            _log.DisposeAsync().AsTask().GetAwaiter().GetResult();

            if (Directory.Exists(_folder))
                Directory.Delete(_folder, true);
        }
    }
}
