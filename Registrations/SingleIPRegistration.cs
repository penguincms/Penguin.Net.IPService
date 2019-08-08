namespace Penguin.Net.IPServices.Registrations
{
    internal class SingleIPRegistration : IPRegistration
    {
        #region Constructors

        public SingleIPRegistration(string IP)
        {
            Source = IP;
        }

        #endregion Constructors

        #region Methods

        public override bool IsMatch(string IPAddress)
        {
            return Source == IPAddress;
        }

        #endregion Methods
    }
}