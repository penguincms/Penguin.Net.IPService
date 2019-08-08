using System;
using System.Net;

namespace Penguin.Net.IPServices.Registrations
{
    internal class CIDRRegistration : IPRegistration
    {
        #region Constructors

        public CIDRRegistration(string CIDR)
        {
            Source = CIDR;

            if (string.IsNullOrEmpty(CIDR))
            {
                throw new ArgumentException("Input string must not be null", CIDR);
            }

            string[] parts = CIDR.Split('/');

            CidrAddress = IPAddress.Parse(parts[0]);

            if (parts.Length != 2)
            {
                throw new FormatException($"cidrMask was not in the correct format:\nExpected: a.b.c.d/n\nActual: {CIDR}");
            }

            if (!int.TryParse(parts[1], out int netmaskBitCount))
            {
                throw new FormatException($"Unable to parse netmask bit count from {CIDR}");
            }

            if (0 > netmaskBitCount || netmaskBitCount > 32)
            {
                throw new ArgumentOutOfRangeException($"Netmask bit count value of {netmaskBitCount} is invalid, must be in range 0-32");
            }

            CidrAddressBytes = BitConverter.ToInt32(CidrAddress.GetAddressBytes(), 0);

            CidrMaskBytes = IPAddress.HostToNetworkOrder(-1 << (32 - netmaskBitCount));
        }

        #endregion Constructors

        #region Methods

        public override bool IsMatch(string IPAddress)
        {
            int ipAddressBytes = BitConverter.ToInt32(System.Net.IPAddress.Parse(IPAddress).GetAddressBytes(), 0);

            return (ipAddressBytes & CidrMaskBytes) == (CidrAddressBytes & CidrMaskBytes);
        }

        #endregion Methods

        #region Properties

        private IPAddress CidrAddress { get; set; }

        private int CidrAddressBytes { get; set; }

        private int CidrMaskBytes { get; set; }

        #endregion Properties
    }
}