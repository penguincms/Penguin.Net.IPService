namespace Penguin.Net.IPService.Registrations
{
    internal abstract class IPRegistration : IIPRegistration
    {
        #region Properties

        public string Source { get; set; }

        #endregion Properties

        #region Methods

        public abstract bool IsMatch(string IPAddress);

        #endregion Methods
    }
}