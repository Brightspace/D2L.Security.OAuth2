using System.Threading.Tasks;

namespace D2L.Security.AuthTokenProvisioning.Invocation {
	
	/// <summary>
	/// Makes invocations on the Auth Service to provision access tokens
	/// </summary>
	interface IAuthServiceInvoker {

		Task<string> ProvisionAccessTokenAsync( InvocationParameters invocationParams );
		string ProvisionAccessToken( InvocationParameters invocationParams );
	}
}
