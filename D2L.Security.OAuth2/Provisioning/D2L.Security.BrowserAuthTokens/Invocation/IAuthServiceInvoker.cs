using System.Threading.Tasks;

namespace D2L.Security.BrowserAuthTokens.Invocation {
	
	/// <summary>
	/// Makes invocations on the Auth Service to provision access token
	/// </summary>
	interface IAuthServiceInvoker {

		Task<string> ProvisionAccessToken( InvocationParameters invocationParams );
	}
}
