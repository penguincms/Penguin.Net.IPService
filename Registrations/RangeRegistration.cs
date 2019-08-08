using System;
using System.Linq;

namespace Penguin.Net.IPServices.Registrations
{
    internal class RangeRegistration : IPRegistration
    {
        #region Properties

        public ulong From { get; set; }

        public ulong To { get; set; }

        #endregion Properties

        #region Constructors

        public RangeRegistration(string Range)
        {
            Source = Range;

            string start = Range.Split('-')[0];
            string end = Range.Split('-')[1];

            From = IpToInt(start);
            To = IpToInt(end);
        }

        #endregion Constructors

        #region Methods

        public override bool IsMatch(string IPAddress)
        {
            ulong toCheck = IpToInt(IPAddress);

            return toCheck >= From && toCheck <= To;
        }

        protected ulong IpToInt(string address)
        {
            byte[] ips = address.Split('.').Select(s => byte.Parse(s)).ToArray();

            byte[] ip = new byte[8];

            for (int i = ips.Length - 1; i >= 0; i--)
            {
                ip[3 - i] = ips[i];
            }

            ulong num = BitConverter.ToUInt64(ip, 0);

            return num;
        }

        #endregion Methods
    }
}