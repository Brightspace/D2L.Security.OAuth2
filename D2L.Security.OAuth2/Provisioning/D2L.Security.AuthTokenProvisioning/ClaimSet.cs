using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace D2L.Security.AuthTokenProvisioning {
	public class ClaimSet {

		private readonly IList<Claim> m_claims;

		public ClaimSet(
			string issuer,
			string tenantId = null,
			Uri tenantUrl = null,
			string user = null,
			string xsrfToken = null
		) {
			m_claims = new List<Claim>();

			if( string.IsNullOrWhiteSpace( issuer ) ) {
				throw new ArgumentException( "Must pass a valid issuer", "issuer" );
			}

			m_claims.Add( new Claim( Constants.Claims.ISSUER, issuer ) );

			if( !string.IsNullOrWhiteSpace( tenantId ) ) {
				m_claims.Add( new Claim( Constants.Claims.TENANT_ID, tenantId ) );
			}

			if( tenantUrl != null ) {
				m_claims.Add( new Claim( Constants.Claims.TENANT_URL, tenantUrl.AbsoluteUri ) );
			}

			if( !string.IsNullOrWhiteSpace( user ) ) {
				m_claims.Add( new Claim( Constants.Claims.USER, user ) );
			}

			if( !string.IsNullOrWhiteSpace( xsrfToken ) ) {
				m_claims.Add( new Claim( Constants.Claims.XSRF_TOKEN, xsrfToken ) );
			}
		}

		public IEnumerable<Claim> ToClaims() {
			return m_claims.ToArray();
		}

	}
}
