using System.Threading.Tasks;

namespace D2L.Security.BrowserAuthTokens {
	
	public interface IAuthTokenProvider {
		Task<string> GetTokenForUserAsync( ProvisioningParameters provisioningParams );

		// no xsrf
		//Task<string> GetTokenForUserAsync( string tenantId, long userId );

		// no user id, no xsrf (application to service)
		//Task<string> GetTokenForApplicationAsync( string tenantId );
	}
}