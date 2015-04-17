using System.Threading.Tasks;

namespace D2L.Security.OAuth2.Keys.Local {
	internal interface IPrivateKeyProvider {
		Task<D2LSigningCredentials> GetSigningCredentialsAsync();
	}
}
