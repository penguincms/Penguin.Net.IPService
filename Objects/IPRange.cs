using System;
using System.Collections.Generic;
using System.Net;

namespace Penguin.Net.IPServices
{
    /// <summary>
    /// A class used for retrieving a range of IP addresses based on CIDR notation or from-to notation
    /// </summary>
    public class IPRange
    {
        #region Constructors

        /// <summary>
        /// Creates a new instance of the parsed information
        /// </summary>
        /// <param name="ipRange">The IP range string to be used when generating the information contained in this object</param>
        public IPRange(string ipRange)
        {
            if (ipRange == null)
            {
                throw new ArgumentNullException();
            }

            if (!this.TryParseCIDRNotation(ipRange) && !this.TryParseSimpleRange(ipRange))
            {
                throw new ArgumentException();
            }
        }

        #endregion Constructors

        #region Methods

        /// <summary>
        /// Gets a list of .net IPAddresses representing all IP's that fall in this range
        /// </summary>
        /// <returns>a list of .net IPAddresses representing all IP's that fall in this range</returns>
        public IEnumerable<IPAddress> GetAllIP()
        {
            int capacity = 1;
            for (int i = 0; i < 4; i++)
            {
                capacity *= this.endIP[i] - this.beginIP[i] + 1;
            }

            List<IPAddress> ips = new List<IPAddress>(capacity);
            for (int i0 = this.beginIP[0]; i0 <= this.endIP[0]; i0++)
            {
                for (int i1 = this.beginIP[1]; i1 <= this.endIP[1]; i1++)
                {
                    for (int i2 = this.beginIP[2]; i2 <= this.endIP[2]; i2++)
                    {
                        for (int i3 = this.beginIP[3]; i3 <= this.endIP[3]; i3++)
                        {
                            ips.Add(new IPAddress(new byte[] { (byte)i0, (byte)i1, (byte)i2, (byte)i3 }));
                        }
                    }
                }
            }

            return ips;
        }

        #endregion Methods

        #region Fields

        private byte[] beginIP;

        private byte[] endIP;

        #endregion Fields

        /// <summary>
        /// Parse IP-range string in CIDR notation.
        /// For example "12.15.0.0/16".
        /// </summary>
        /// <param name="ipRange"></param>
        /// <returns></returns>
        private bool TryParseCIDRNotation(string ipRange)
        {
            string[] x = ipRange.Split('/');

            if (x.Length != 2)
            {
                return false;
            }

            byte bits = byte.Parse(x[1]);
            uint ip = 0;
            string[] ipParts0 = x[0].Split('.');
            for (int i = 0; i < 4; i++)
            {
                ip = ip << 8;
                ip += uint.Parse(ipParts0[i]);
            }

            byte shiftBits = (byte)(32 - bits);
            uint ip1 = (ip >> shiftBits) << shiftBits;

            if (ip1 != ip) // Check correct subnet address
            {
                return false;
            }

            uint ip2 = ip1 >> shiftBits;
            for (int k = 0; k < shiftBits; k++)
            {
                ip2 = (ip2 << 1) + 1;
            }

            this.beginIP = new byte[4];
            this.endIP = new byte[4];

            for (int i = 0; i < 4; i++)
            {
                this.beginIP[i] = (byte)((ip1 >> (3 - i) * 8) & 255);
                this.endIP[i] = (byte)((ip2 >> (3 - i) * 8) & 255);
            }

            return true;
        }

        /// <summary>
        /// Parse IP-range string "12.15-16.1-30.10-255"
        /// </summary>
        /// <param name="ipRange"></param>
        /// <returns></returns>
        private bool TryParseSimpleRange(string ipRange)
        {
            string[] ipParts = ipRange.Split('.');

            this.beginIP = new byte[4];
            this.endIP = new byte[4];
            for (int i = 0; i < 4; i++)
            {
                string[] rangeParts = ipParts[i].Split('-');

                if (rangeParts.Length < 1 || rangeParts.Length > 2)
                {
                    return false;
                }

                this.beginIP[i] = byte.Parse(rangeParts[0]);
                this.endIP[i] = (rangeParts.Length == 1) ? this.beginIP[i] : byte.Parse(rangeParts[1]);
            }

            return true;
        }
    }
}