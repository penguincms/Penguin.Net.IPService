using Penguin.Extensions.Strings;
using Penguin.Net.IPServices.Registrations;
using Penguin.Net.Whois;
using Penguin.Net.Whois.Objects;
using Penguin.Services.Core;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Text.RegularExpressions;

namespace Penguin.Net.IPServices
{
    /// <summary>
    /// A service intended for use with managing IP based connections to a server
    /// </summary>
    public class IPService : Service
    {
        /// <summary>
        /// The default timeout in MS between (static) connections to the Whois host
        /// </summary>
        public double QueryTimeout = 200;

        /// <summary>
        /// An accessor for the cached IP information for use in debugging
        /// </summary>
        public List<IPAnalysis> DiscoveredRanges
        {
            get
            {
                return _DiscoveredRanges.ToList();
            }
        }

        /// <summary>
        /// The last time the Cache was persisted to disk
        /// </summary>
        public DateTime LastSave { get; set; }

        /// <summary>
        /// An optional dely in MS between persisting the cache to the disk, to avoid too much time spend serializing data
        /// </summary>
        public int PersistDelayMS { get; set; }

        /// <summary>
        /// Constructs a new instance of the IP service
        /// </summary>
        /// <param name="loadBlacklist">A function returning the contents of the blacklist to use when banning IPs</param>
        /// <param name="saveFunction">A function accepting a list of IP analysis, for the user to define the way the cache is persisted</param>
        /// <param name="loadFunction">A function returning a list of IP analysis, for the user to define the way the cache is loaded</param>
        public IPService(Func<string> loadBlacklist, Action<List<IPAnalysis>> saveFunction, Func<List<IPAnalysis>> loadFunction) : this(loadBlacklist.Invoke(), saveFunction, loadFunction)
        {
        }

        /// <summary>
        /// Constructs a new instance of the IP service
        /// </summary>
        /// <param name="blackList">The string contents of a blacklist file</param>
        /// <param name="saveFunction">A function accepting a list of IP analysis, for the user to define the way the cache is persisted</param>
        /// <param name="loadFunction">A function returning a list of IP analysis, for the user to define the way the cache is loaded</param>
        public IPService(string blackList, Action<List<IPAnalysis>> saveFunction, Func<List<IPAnalysis>> loadFunction)
        {
            blacklistedRegex = new Dictionary<string, List<string>>();

            _DiscoveredRanges = loadFunction?.Invoke() ?? new List<IPAnalysis>();

            SaveFunction = saveFunction;
            LoadFunction = loadFunction;

            if (!string.IsNullOrWhiteSpace(blackList))
            {
                string[] BlacklistLines = blackList.Split('\n').Select(s => s.Trim()).ToArray();

                IPRegistrations = new List<IIPRegistration>();

                foreach (string line in BlacklistLines)
                {
                    if (line.Trim().StartsWith("#"))
                    {
                        continue;
                    }

                    if (line.Contains("/"))
                    {
                        IPRegistrations.Add(new CIDRRegistration(line));
                    }
                    else if (line.Contains("-"))
                    {
                        IPRegistrations.Add(new RangeRegistration(line));
                    }
                    else if (!line.Contains(":"))
                    {
                        IPRegistrations.Add(new SingleIPRegistration(line));
                    }
                    else
                    {
                        string propertyName = line.Split(":", false)[0];
                        string Regex = line.Split(":", false)[1];

                        if (!blacklistedRegex.ContainsKey(propertyName))
                        {
                            blacklistedRegex.Add(propertyName, new List<string>());
                        }

                        blacklistedRegex[propertyName].Add(Regex);
                    }
                }
            }
        }

        /// <summary>
        /// Returns a bool representing whether or not any of the fields of the IP analysis match the blacklist
        /// </summary>
        /// <param name="Ip">The IP to check</param>
        /// <returns>Whether or not the IP is blacklisted</returns>
        public bool IsBlacklisted(string Ip)
        {
            if (IPRegistrations != null)
            {
                foreach (IIPRegistration iPRegistration in IPRegistrations)
                {
                    if (iPRegistration.IsMatch(Ip))
                    {
                        return true;
                    }
                }
            }

            IEnumerable<IPAnalysis> analyzeIPs = QueryIP(Ip);

            foreach (IPAnalysis analyzeIP in analyzeIPs)
            {
                foreach (PropertyInfo thisprop in typeof(IPAnalysis).GetProperties())
                {
                    if (blacklistedRegex.ContainsKey(thisprop.Name))
                    {
                        List<string> regex = blacklistedRegex[thisprop.Name];

                        string thisVal = thisprop.GetValue(analyzeIP)?.ToString() ?? string.Empty;

                        if (string.IsNullOrWhiteSpace(thisVal))
                        {
                            continue;
                        }

                        foreach (string reg in regex)
                        {
                            if (string.Equals(thisVal, reg, StringComparison.OrdinalIgnoreCase) || Regex.IsMatch(thisVal, reg))
                            {
                                return true;
                            }
                        }
                    }
                }
            }

            return false;
        }

        /// <summary>
        /// Force calls the function for loading the analysis from disk
        /// </summary>
        public void LoadAnalysis()
        {
            _DiscoveredRanges = LoadFunction?.Invoke();
        }

        /// <summary>
        /// Returns a number of IP analysis that contain the specified IP in their CIDR range, or - range
        /// </summary>
        /// <param name="Ip">The IP to search for</param>
        /// <returns>a number of IP analysis that contain the specified IP in their CIDR range, or - range</returns>
        public IEnumerable<IPAnalysis> QueryIP(string Ip)
        {
            IPAnalysis? nanalysis = null;

            lock (QueryLock)
            {
                TryLoadAnalysis();

                foreach (IPAnalysis discoveredAnalysis in _DiscoveredRanges)
                {
                    if (discoveredAnalysis.IsMatch(Ip))
                    {
                        nanalysis = discoveredAnalysis;
                        break;
                    }
                }

                if (!nanalysis.HasValue)
                {
                    if (LastQuery != DateTime.MinValue && (DateTime.Now - LastQuery).TotalMilliseconds < QueryTimeout)
                    {
                        System.Threading.Thread.Sleep((int)(QueryTimeout - (DateTime.Now - LastQuery).TotalMilliseconds));
                    }

                    WhoisClient client = new WhoisClient();

                    client.CopyInterfaceFrom(this);

                    QueryResponse queryResponse = client.Query($"{Ip}");

                    if (queryResponse.WhoisResponses.Count == 0)
                    {
                        Info?.Invoke($"No responses for {Ip}");

                        foreach (ServerResponse s in queryResponse.ServerResponses)
                        {
                            Debug?.Invoke($"{s.Server}> {s.Request}\r\n{s.Response}");
                        }
                    }

                    List<IPAnalysis> toReturn = new List<IPAnalysis>();

                    foreach (WhoisResponse response in queryResponse.WhoisResponses)
                    {
                        IPAnalysis analysis = new IPAnalysis()
                        {
                            DiscoveryDate = DateTime.Now
                        };

                        analysis.WhoisSource = queryResponse.ServerResponses.Last().Server;
                        analysis.CIDR = response.CIDR?.Split(",", false)?.Select(s => s.Trim())?.Where(s => !string.IsNullOrWhiteSpace(s))?.ToArray();
                        analysis.NetworkName = response.NetName;
                        analysis.OwnerName = response.OrgName;
                        analysis.FromIp = response.IPFrom;
                        analysis.ToIp = response.IPTo;

                        LastQuery = DateTime.Now;

                        AddAnalysis(analysis);
                    }

                    SaveAnalysis();

                    foreach (IPAnalysis iPAnalysis in toReturn)
                    {
                        yield return iPAnalysis;
                    }
                }
                else
                {
                    yield return nanalysis.Value;
                }
            }
        }

        /// <summary>
        /// Calls the Save function for the IP analysis cache. Will not save if a timeout is set and the timeout has not yet elapsed
        /// </summary>
        /// <returns></returns>
        public bool SaveAnalysis()
        {
            if ((DateTime.Now - LastSave).TotalMilliseconds > PersistDelayMS)
            {
                LastSave = DateTime.Now;

                System.Console.WriteLine("Saving data...");

                SaveFunction?.Invoke(DiscoveredRanges);

                return true;
            }

            return false;
        }

        internal void AddAnalysis(IPAnalysis analysis)
        {
            _DiscoveredRanges.Add(analysis);
        }

        //This is going to get really slow, really fast. This should be Async and incremental
        /// <summary>
        /// A function accepting a list of IP analysis, for the user to define the way the cache is loaded
        /// </summary>
        protected Func<List<IPAnalysis>> LoadFunction { get; set; }

        /// <summary>
        /// A function accepting a list of IP analysis, for the user to define the way the cache is persisted
        /// </summary>
        protected Action<List<IPAnalysis>> SaveFunction { get; set; }

        private static List<IPAnalysis> _DiscoveredRanges { get; set; }
        private static Object QueryLock { get; set; } = new object();
        private Dictionary<string, List<string>> blacklistedRegex { get; set; }
        private List<IIPRegistration> IPRegistrations { get; set; }
        private DateTime LastQuery { get; set; }

        /// <summary>
        /// Attempts to load the IP cache, but ONLY if the in-memory Cache is empty
        /// </summary>
        private void TryLoadAnalysis()
        {
            if (_DiscoveredRanges is null)
            {
                LoadAnalysis();
            }
        }
    }
}