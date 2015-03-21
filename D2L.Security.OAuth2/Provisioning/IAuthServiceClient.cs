using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using D2L.Security.OAuth2.Scopes;

namespace D2L.Security.OAuth2.Provisioning {
	
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
