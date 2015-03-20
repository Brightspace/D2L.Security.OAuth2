using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace D2L.Security.AuthTokenProvisioning {
	
	/// <summary>
	/// Makes invocations on the Auth Service to provision access tokens
	/// </summary>
	public interface IAuthServiceClient : IDisposable {

		Task<IAccessToken> ProvisionAccessTokenAsync(
			string assertion,
			IEnumerable<Scope> scopes
		);
	}
}
