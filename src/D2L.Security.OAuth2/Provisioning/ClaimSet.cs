using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Linq;

namespace D2L.Security.OAuth2.Provisioning {

	/// <summary>
	/// A structured holder of JWT claims
	/// </summary>
	public sealed class ClaimSet {

		private readonly IList<Claim> m_claims;

		/// <summary>
		/// Constructs a new <see cref="ClaimSet"/>
		/// </summary>
		public ClaimSet(
			string issuer,
			Guid? tenantId = null,
			string user = null,
			string xsrfToken = null
		) {
			m_claims = new List<Claim>();

			if( string.IsNullOrWhiteSpace( issuer ) ) {
				throw new ArgumentException( "Must pass a valid issuer", "issuer" );
			}

			m_claims.Add( new Claim( Constants.Claims.ISSUER, issuer ) );

			if( tenantId.HasValue ) {
				m_claims.Add( new Claim( Constants.Claims.TENANT_ID, tenantId.Value.ToString() ) );
			}
			
			if( !string.IsNullOrWhiteSpace( user ) ) {
				m_claims.Add( new Claim( Constants.Claims.USER_ID, user ) );
			}

			if( !string.IsNullOrWhiteSpace( xsrfToken ) ) {
				m_claims.Add( new Claim( Constants.Claims.XSRF_TOKEN, xsrfToken ) );
			}
		}

		/// <summary>
		/// Converts the <see cref="ClaimSet"/> to an <see cref="IEnumerable{Claim}"/>
		/// </summary>
		/// <returns>Claims as an <see cref="IEnumerable{Claim}"/></returns>
		public IEnumerable<Claim> ToClaims() {
			return m_claims.ToArray();
		}

	}
}
