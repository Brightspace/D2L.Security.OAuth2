using System.Threading.Tasks;

namespace D2L.Security.BrowserAuthTokens {
	
	public interface IAuthTokenProvider {

		Task<IAccessToken> ProvisionAccessTokenAsync( ProvisioningParameters provisioningParams );
		IAccessToken ProvisionAccessToken( ProvisioningParameters provisioningParams );
	}
}