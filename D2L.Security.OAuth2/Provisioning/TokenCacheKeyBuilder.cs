using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Web.Script.Serialization;
using D2L.Security.OAuth2.Scopes;

namespace D2L.Security.OAuth2.Provisioning {

	internal static class TokenCacheKeyBuilder {

		private static readonly JavaScriptSerializer m_serializer = new JavaScriptSerializer();

		internal static string BuildKey(
			IEnumerable<Claim> claims,
			IEnumerable<Scope> scopes
			) {

			IOrderedEnumerable<Claim> sortedClaims = claims.OrderBy( c => c.Type );
			IOrderedEnumerable<Scope> sortedScopes = scopes.OrderBy( s => s.ToString() );

			var keyObject = new {
				claims = sortedClaims.Select( c => new { name = c.Type, value = c.Value } ),
				scopes = sortedScopes.Select( s => s.ToString() )
			};

			return m_serializer.Serialize( keyObject );
		}
	}
}
