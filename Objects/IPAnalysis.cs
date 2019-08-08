using Penguin.Net.IPServices.Registrations;
using System;
using System.Collections.Generic;

namespace Penguin.Net.IPServices
{
    /// <summary>
    /// A common denominator of IP information used by the IP service
    /// </summary>
    public struct IPAnalysis : IIPRegistration
    {
        #region Properties

        /// <summary>
        /// A CIDR range representing where this IP falls
        /// </summary>
        public string[] CIDR { get; set; }

        /// <summary>
        /// The Country this IP is registered to
        /// </summary>
        public string Country { get; set; }

        /// <summary>
        /// The first time this IP was checked against whois for information
        /// </summary>
        public DateTime DiscoveryDate { get; set; }

        /// <summary>
        /// an IP representing the start of the range that this IP falls into
        /// </summary>
        public string FromIp { get; set; }

        /// <summary>
        /// The WHOIS name for this particular block of IP addresses
        /// </summary>
        public string NetworkName { get; set; }

        /// <summary>
        /// The orginization that this IP is registered to
        /// </summary>
        public string OwnerName { get; set; }

        /// <summary>
        /// The end of a range of IP's that this address falls into
        /// </summary>
        public string ToIp { get; set; }

        /// <summary>
        /// The WHOIS server that claimed the information for this analysis
        /// </summary>
        public string WhoisSource { get; set; }

        #endregion Properties

        #region Methods

        /// <summary>
        /// Checks if a given IP falls into either the CIDR or From-To range
        /// </summary>
        /// <param name="IPAddress">The IP address to check</param>
        /// <returns>True if the given IP is part of the same range as this one</returns>
        public bool IsMatch(string IPAddress)
        {
            if (Registrations is null)
            {
                Registrations = new List<IIPRegistration>();

                if (CIDR != null)
                {
                    foreach (string cidr in CIDR)
                    {
                        if (!string.IsNullOrWhiteSpace(cidr))
                        {
                            Registrations.Add(new CIDRRegistration(cidr));
                        }
                    }
                }

                if (!string.IsNullOrWhiteSpace(FromIp) && !string.IsNullOrWhiteSpace(ToIp))
                {
                    Registrations.Add(new RangeRegistration($"{FromIp}-{ToIp}"));
                }
            }

            foreach (IIPRegistration registration in Registrations)
            {
                if (registration.IsMatch(IPAddress)) { return true; }
            }

            return false;
        }

        #endregion Methods

        #region Fields

        [NonSerialized]
        private List<IIPRegistration> Registrations;

        #endregion Fields
    }
}