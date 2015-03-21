using System;
using System.Collections.Generic;
using System.Security.Claims;

namespace D2L.Security.OAuth2.Validation.Token {
	
	/// <summary>
	/// A token which can be trusted to have been validated
	/// </summary>
	public interface IValidatedToken {
		IEnumerable<Claim> Claims { get; }

		/// <summary>
		/// Expiry in UTC standard time
		/// </summary>
		DateTime Expiry { get; }
	}
}
