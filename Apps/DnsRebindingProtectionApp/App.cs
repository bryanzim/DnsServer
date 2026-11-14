/*
Technitium DNS Server
Copyright (C) 2026  Shreyas Zare (shreyas@technitium.com)

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

*/

using DnsServerCore.ApplicationCommon;
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Text.Json;
using System.Threading.Tasks;
using TechnitiumLibrary;
using TechnitiumLibrary.Net;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.EDnsOptions;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace DnsRebindingProtection
{
    public sealed class App : IDnsApplication, IDnsPostProcessor
    {
        #region variables

        readonly static JsonDocumentOptions _jsonParseOptions = new JsonDocumentOptions() { CommentHandling = JsonCommentHandling.Skip };

        bool _enableProtection;
        bool _enableEdeReport = true;
        NetworkAddress[] _bypassNetworks;
        HashSet<NetworkAddress> _privateNetworks;
        HashSet<string> _privateDomains;

        #endregion

        #region IDisposable

        public void Dispose()
        {
            // Nothing to dispose of.
        }

        #endregion

        #region private

        private static string GetParentZone(string domain)
        {
            int i = domain.IndexOf('.');
            if (i > -1)
                return domain[(i + 1)..];

            //dont return root zone
            return null;
        }

        private bool IsPrivateDomain(string domain)
        {
            domain = domain.ToLowerInvariant();

            do
            {
                if (_privateDomains.Contains(domain))
                    return true;

                domain = GetParentZone(domain);
            }
            while (domain is not null);

            return false;
        }

        private bool IsPrivateAddress(IPAddress address)
        {
            if (address is null)
                return false;

            if (address.IsIPv4MappedToIPv6)
                address = address.MapToIPv4();

            foreach (NetworkAddress networkAddress in _privateNetworks)
            {
                if (networkAddress.Contains(address))
                    return true;
            }

            return false;
        }

        private bool TryFilterAddresses(IReadOnlyList<IPAddress> addresses, out List<IPAddress> kept)
        {
            kept = null;

            if (addresses is null)
                return false;

            bool removed = false;
            List<IPAddress> publicAddresses = new List<IPAddress>(addresses.Count);

            foreach (IPAddress address in addresses)
            {
                if (IsPrivateAddress(address))
                    removed = true;
                else
                    publicAddresses.Add(address);
            }

            if (!removed)
                return false;

            kept = publicAddresses;
            return true;
        }

        private bool TryProtectRecord(DnsResourceRecord record, out DnsResourceRecord protectedRecord)
        {
            protectedRecord = null;

            if (record?.RDATA is null)
                return false;

            switch (record.Type)
            {
                case DnsResourceRecordType.A:
                    return (record.RDATA is DnsARecordData ipv4) && IsPrivateAddress(ipv4.Address);

                case DnsResourceRecordType.AAAA:
                    return (record.RDATA is DnsAAAARecordData ipv6) && IsPrivateAddress(ipv6.Address);

                case DnsResourceRecordType.SVCB:
                case DnsResourceRecordType.HTTPS:
                    return TryFilterServiceBinding(record, out protectedRecord);

                default:
                    return false;
            }
        }

        private bool TryFilterServiceBinding(DnsResourceRecord record, out DnsResourceRecord filteredRecord)
        {
            filteredRecord = null;

            if (record.RDATA is not DnsSVCBRecordData svcb || (svcb.SvcParams is null))
                return false;

            bool changed = false;
            Dictionary<DnsSvcParamKey, DnsSvcParamValue> filteredParams = new Dictionary<DnsSvcParamKey, DnsSvcParamValue>(svcb.SvcParams.Count);

            foreach (KeyValuePair<DnsSvcParamKey, DnsSvcParamValue> param in svcb.SvcParams)
            {
                if ((param.Key == DnsSvcParamKey.IPv4Hint) && (param.Value is DnsSvcIPv4HintParamValue ipv4) && TryFilterAddresses(ipv4.Addresses, out List<IPAddress> keptIpv4))
                {
                    changed = true;

                    if (keptIpv4.Count > 0)
                        filteredParams.Add(param.Key, new DnsSvcIPv4HintParamValue(keptIpv4));

                    continue;
                }

                if ((param.Key == DnsSvcParamKey.IPv6Hint) && (param.Value is DnsSvcIPv6HintParamValue ipv6) && TryFilterAddresses(ipv6.Addresses, out List<IPAddress> keptIpv6))
                {
                    changed = true;

                    if (keptIpv6.Count > 0)
                        filteredParams.Add(param.Key, new DnsSvcIPv6HintParamValue(keptIpv6));

                    continue;
                }

                filteredParams.Add(param.Key, param.Value);
            }

            if (!changed)
                return false;

            DnsSVCBRecordData filteredData = new DnsSVCBRecordData(svcb.SvcPriority, svcb.TargetName, filteredParams);
            filteredData.AutoIpv4Hint = svcb.AutoIpv4Hint;
            filteredData.AutoIpv6Hint = svcb.AutoIpv6Hint;
            filteredRecord = new DnsResourceRecord(record.Name, record.Type, record.Class, record.TTL, filteredData);
            return true;
        }

        private bool TryDetectRebinding(IReadOnlyList<DnsResourceRecord> answer, out List<DnsResourceRecord> protectedAnswer, out string domain)
        {
            List<DnsResourceRecord> filtered = null;
            domain = null;

            for (int i = 0; i < answer.Count; i++)
            {
                DnsResourceRecord record = answer[i];
                if (TryProtectRecord(record, out DnsResourceRecord protectedRecord))
                {
                    //rebinding attempt detected
                    if (filtered is null)
                    {
                        filtered = new List<DnsResourceRecord>(answer.Count);
                        domain = record.Name.ToLowerInvariant();

                        for (int j = 0; j < i; j++)
                            filtered.Add(answer[j]);
                    }

                    if (protectedRecord is not null)
                        filtered.Add(protectedRecord);
                }
                else if (filtered is not null)
                {
                    filtered.Add(record);
                }
            }

            protectedAnswer = filtered;
            return filtered is not null;
        }

        #endregion

        #region public

        public async Task InitializeAsync(IDnsServer dnsServer, string config)
        {
            using JsonDocument jsonDocument = JsonDocument.Parse(config, _jsonParseOptions);
            JsonElement jsonConfig = jsonDocument.RootElement;

            _enableProtection = jsonConfig.GetPropertyValue("enableProtection", true);
            _enableEdeReport = jsonConfig.GetPropertyValue("enableEdeReport", true);
            _privateNetworks = new HashSet<NetworkAddress>(jsonConfig.ReadArray("privateNetworks", NetworkAddress.Parse));
            _privateDomains = new HashSet<string>(jsonConfig.ReadArray("privateDomains"), StringComparer.OrdinalIgnoreCase);

            if (jsonConfig.TryReadArray("bypassNetworks", NetworkAddress.Parse, out NetworkAddress[] bypassNetworks))
            {
                _bypassNetworks = bypassNetworks;
            }
            else
            {
                _bypassNetworks = [];

                //update config for new feature
                config = config.Replace("\"privateNetworks\"", "\"bypassNetworks\": [\r\n  ],\r\n  \"privateNetworks\"");
                await File.WriteAllTextAsync(Path.Combine(dnsServer.ApplicationFolder, "dnsApp.config"), config);
            }

            if (!jsonConfig.TryGetProperty("enableEdeReport", out _))
            {
                //update config
                config = config.Replace("\"bypassNetworks\"", "\"enableEdeReport\": true,\r\n  \"bypassNetworks\"");
                await File.WriteAllTextAsync(Path.Combine(dnsServer.ApplicationFolder, "dnsApp.config"), config);
            }

            if (!jsonConfig.TryGetProperty("rebindingNetworkRevision", out _))
            {
                //unspecified addresses and IPv6 loopback are used for DNS rebinding
                NetworkAddress unspecified = NetworkAddress.Parse("0.0.0.0/8");
                NetworkAddress ipv6Loopback = NetworkAddress.Parse("::1/128");
                bool hasUnspecified = _privateNetworks.Contains(unspecified);
                bool hasIpv6Loopback = _privateNetworks.Contains(ipv6Loopback);

                if (!hasUnspecified)
                    _privateNetworks.Add(unspecified);

                if (!hasIpv6Loopback)
                    _privateNetworks.Add(ipv6Loopback);

                string updatedConfig = config;

                if (!hasUnspecified)
                    updatedConfig = updatedConfig.Replace("\"privateNetworks\": [", "\"privateNetworks\": [\r\n    \"0.0.0.0/8\",");

                if (!hasIpv6Loopback)
                    updatedConfig = updatedConfig.Replace("\"privateNetworks\": [", "\"privateNetworks\": [\r\n    \"::1/128\",");

                if (updatedConfig.Contains("\"0.0.0.0/8\"", StringComparison.Ordinal) && updatedConfig.Contains("\"::1/128\"", StringComparison.Ordinal))
                {
                    updatedConfig = updatedConfig.Replace("\"enableProtection\"", "\"rebindingNetworkRevision\": 1,\r\n  \"enableProtection\"");
                    await File.WriteAllTextAsync(Path.Combine(dnsServer.ApplicationFolder, "dnsApp.config"), updatedConfig);
                }
            }
        }

        public Task<DnsDatagram> PostProcessAsync(DnsDatagram request, IPEndPoint remoteEP, DnsTransportProtocol protocol, DnsDatagram response)
        {
            // Do not filter authoritative responses. Because in this case any rebinding is intentional.
            if (!_enableProtection || response.AuthoritativeAnswer)
                return Task.FromResult(response);

            if ((response.Tag is not null) && (response.Tag is DnsServerResponseType responseType) && (responseType == DnsServerResponseType.Blocked))
                return Task.FromResult(response); //allow blocked responses

            if ((request.Question.Count > 0) && IsPrivateDomain(request.Question[0].Name))
                return Task.FromResult(response); //the name that was queried is allowed to resolve privately

            IPAddress remoteIP = remoteEP.Address;

            foreach (NetworkAddress network in _bypassNetworks)
            {
                if (network.Contains(remoteIP))
                    return Task.FromResult(response);
            }

            bool answerChanged = TryDetectRebinding(response.Answer, out List<DnsResourceRecord> protectedAnswer, out string answerDomain);
            List<DnsResourceRecord> protectedAdditional = null;
            string additionalDomain = null;
            bool additionalChanged = (response.Additional is not null) && TryDetectRebinding(response.Additional, out protectedAdditional, out additionalDomain);

            if (answerChanged || additionalChanged)
            {
                DnsDatagram newResponse = response.Clone(answerChanged ? protectedAnswer : response.Answer, response.Authority, additionalChanged ? protectedAdditional : response.Additional);

                if (_enableEdeReport && (newResponse.EDNS is not null))
                {
                    string domain = answerChanged ? answerDomain : additionalDomain;
                    EDnsOption option = new EDnsOption(EDnsOptionCode.EXTENDED_DNS_ERROR, new EDnsExtendedDnsErrorOptionData(EDnsExtendedDnsErrorCode.Filtered, $"source=dns-rebinding-protection-app; domain={domain};"));

                    List<EDnsOption> options;

                    if (newResponse.EDNS.Options.Count == 0)
                        options = [option];
                    else
                        options = [.. newResponse.EDNS.Options, option];

                    newResponse = newResponse.CloneWithEDnsOptions(options);
                }

                return Task.FromResult(newResponse);
            }

            return Task.FromResult(response);
        }

        #endregion

        #region properties

        public string Description
        { get { return "Protects from DNS rebinding attacks using configured private domains and networks."; } }

        #endregion
    }
}
