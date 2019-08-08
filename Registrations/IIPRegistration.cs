namespace Penguin.Net.IPServices.Registrations
{
    internal interface IIPRegistration
    {
        #region Methods

        bool IsMatch(string IPAddress);

        #endregion Methods
    }
}