using System.Collections.Generic;
using System.Security.Claims;
using System.Security.Principal;

namespace D2L.Security.AuthTokenValidation.TokenValidation {

	/// <summary>
	/// Exposes methods of a ClaimsPrincipal via an interface
	/// </summary>
	internal sealed class ClaimsPrincipalToIClaimsPrincipalAdapter : IClaimsPrincipal {
		
		private readonly ClaimsPrincipal m_inner;
		
		internal ClaimsPrincipalToIClaimsPrincipalAdapter( ClaimsPrincipal inner ) {
			m_inner = inner;
		}

		IIdentity IPrincipal.Identity {
			get { return m_inner.Identity; }
		}

		bool IPrincipal.IsInRole( string role ) {
			return m_inner.IsInRole( role );
		}

		IEnumerable<Claim> IClaimsPrincipal.Claims {
			get { return m_inner.Claims; }
		}
	}
}
