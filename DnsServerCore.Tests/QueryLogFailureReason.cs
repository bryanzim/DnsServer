using DnsServerCore;
using DnsServerCore.Dns;
using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;
using TechnitiumLibrary.Net.Dns;
using DnsResponseCode = TechnitiumLibrary.Net.Dns.DnsResponseCode;
using TechnitiumLibrary.Net.Dns.EDnsOptions;
using TechnitiumLibrary.Net.Dns.ResourceRecords;
using Xunit;

namespace DnsServerCore.Tests
{
    public sealed class QueryLogFailureReason : IClassFixture<DnsServerFixture>
    {
        readonly DnsServerFixture _dns;

        public QueryLogFailureReason(DnsServerFixture dns)
        {
            _dns = dns;
        }

        [Fact]
        public void ServerFailureReasonStaysOnTheLogLineWhenTheClientDidNotSendEdns()
        {
            DnsQuestionRecord question = new DnsQuestionRecord("us.pool.ntp.org", DnsResourceRecordType.A, DnsClass.IN);
            DnsDatagram request = new DnsDatagram(1, false, DnsOpcode.StandardQuery, false, false, true, false, false, false, DnsResponseCode.NoError, [question]);
            IReadOnlyList<EDnsOption> options = [new EDnsOption(EDnsOptionCode.EXTENDED_DNS_ERROR, new EDnsExtendedDnsErrorOptionData(EDnsExtendedDnsErrorCode.Other, "Waiting for resolver. Please try again."))];
            DnsDatagram response = new DnsDatagram(1, true, DnsOpcode.StandardQuery, false, false, true, true, false, false, DnsResponseCode.ServerFailure, [question], null, null, null, 512, EDnsHeaderFlags.None, options);

            DnsDatagram logged = DnsServer.WithoutEdnsKeepingFailureReason(response);
            string line = LogManager.FormatQueryLog(request, logged);

            Assert.Null(logged.EDNS);
            Assert.Contains("QNAME: us.pool.ntp.org; QTYPE: A; QCLASS: IN; RCODE: ServerFailure; ANSWER: []; EDE: Other: Waiting for resolver. Please try again.", line);
        }

        [Fact]
        public void ServerFailureReasonIsLoggedWhenTheResponseKeepsEdns()
        {
            DnsQuestionRecord question = new DnsQuestionRecord("time.nist.gov", DnsResourceRecordType.A, DnsClass.IN);
            DnsDatagram request = new DnsDatagram(1, false, DnsOpcode.StandardQuery, false, false, true, false, false, false, DnsResponseCode.NoError, [question], udpPayloadSize: 1232);
            IReadOnlyList<EDnsOption> options = [new EDnsOption(EDnsOptionCode.EXTENDED_DNS_ERROR, new EDnsExtendedDnsErrorOptionData(EDnsExtendedDnsErrorCode.Other, "line one\nline two"))];
            DnsDatagram response = new DnsDatagram(1, true, DnsOpcode.StandardQuery, false, false, true, true, false, false, DnsResponseCode.ServerFailure, [question], null, null, null, 1232, EDnsHeaderFlags.None, options);

            string line = LogManager.FormatQueryLog(request, response);

            Assert.Contains("RCODE: ServerFailure; ANSWER: []; EDE: Other: line one line two", line);
            Assert.DoesNotContain("\n", line);
        }

        [Fact]
        public void AnAnswerWithoutAnExtendedErrorKeepsTheExistingLogLine()
        {
            DnsQuestionRecord question = new DnsQuestionRecord("www.example", DnsResourceRecordType.A, DnsClass.IN);
            DnsDatagram request = new DnsDatagram(1, false, DnsOpcode.StandardQuery, false, false, true, false, false, false, DnsResponseCode.NoError, [question]);
            DnsResourceRecord address = new DnsResourceRecord(question.Name, DnsResourceRecordType.A, DnsClass.IN, 300, new DnsARecordData(IPAddress.Parse("192.0.2.50")));
            DnsDatagram response = new DnsDatagram(1, true, DnsOpcode.StandardQuery, false, false, true, true, false, false, DnsResponseCode.NoError, [question], [address]);

            string line = LogManager.FormatQueryLog(request, response);

            Assert.Equal("QNAME: www.example; QTYPE: A; QCLASS: IN; RCODE: NoError; ANSWER: [192.0.2.50]", line);
        }

        [Fact]
        public async Task AForwarderFailureNamesTheReasonOnTheQueryLog()
        {
            const string name = "no.answer.example";

            using UdpClient hole = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
            IReadOnlyList<NameServerAddress> forwarders = _dns.Server.Forwarders;
            int timeout = _dns.Server.ForwarderTimeout;
            int retries = _dns.Server.ForwarderRetries;
            bool dnssec = _dns.Server.DnssecValidation;

            try
            {
                _dns.Server.DnssecValidation = false;
                _dns.Server.ForwarderRetries = 1;
                _dns.Server.ForwarderTimeout = 1000;
                _dns.Server.Forwarders = [new NameServerAddress((IPEndPoint)hole.Client.LocalEndPoint)];

                DnsDatagram request = new DnsDatagram(0, false, DnsOpcode.StandardQuery, false, false, true, false, false, false, DnsResponseCode.NoError, [new DnsQuestionRecord(name, DnsResourceRecordType.A, DnsClass.IN)]);
                DnsDatagram response = await _dns.Server.DirectQueryAsync(request, 8000);

                Assert.Equal(DnsResponseCode.ServerFailure, response.RCODE);
                Assert.Null(response.EDNS);
                Assert.NotEmpty(response.DnsClientExtendedErrors);

                string reason = response.DnsClientExtendedErrors[0].ExtraText;
                Assert.Contains(name, reason, StringComparison.OrdinalIgnoreCase);

                string line = LogManager.FormatQueryLog(request, response);
                Assert.Contains("RCODE: ServerFailure; ANSWER: []", line);
                Assert.Contains(reason, line);
            }
            finally
            {
                _dns.Server.Forwarders = forwarders;
                _dns.Server.ForwarderTimeout = timeout;
                _dns.Server.ForwarderRetries = retries;
                _dns.Server.DnssecValidation = dnssec;
            }
        }
    }
}
