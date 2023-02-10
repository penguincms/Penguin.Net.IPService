namespace Penguin.Net.IPService.Registrations
{
    internal interface IIPRegistration
    {
        #region Methods

        bool IsMatch(string IPAddress);

        #endregion Methods
    }
}