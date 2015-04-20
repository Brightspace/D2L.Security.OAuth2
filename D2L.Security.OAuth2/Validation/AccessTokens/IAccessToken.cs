using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using D2L.Security.OAuth2.Scopes;

namespace D2L.Security.OAuth2.Validation.AccessTokens {
	public interface IAccessToken {

		string Id { get; }

		/// <summary>
		/// The raw, signed access token.  Sensitive information since it is all that is needed for authentication.
		/// </summary>
		string SensitiveRawAccessToken { get; }
		
		IEnumerable<Scope> Scopes { get; }
		IEnumerable<Claim> Claims { get; }

		/// <summary>
		/// Expiry in UTC standard time
		/// </summary>
		DateTime Expiry { get; }

	}
}
