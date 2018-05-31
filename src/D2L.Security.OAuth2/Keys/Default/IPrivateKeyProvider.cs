using System.Threading.Tasks;

namespace D2L.Security.OAuth2.Keys.Default {
	internal interface IPrivateKeyProvider {
		Task<D2LSecurityKey> GetSigningCredentialsAsync();
	}
}
