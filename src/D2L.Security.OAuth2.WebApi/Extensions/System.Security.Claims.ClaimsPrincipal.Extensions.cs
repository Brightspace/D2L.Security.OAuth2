using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using D2L.Security.OAuth2.Scopes;

namespace D2L.Security.OAuth2 {
	internal static partial class WebApiExtensionMethods {
		internal static IEnumerable<Scope> GetGrantedScopes( this ClaimsPrincipal principal ) {

			IEnumerable<Scope> grantedScopes = principal.FindAll( Constants.Claims.SCOPE )
				.SelectMany( c => c.Value.Split( ' ' ) )
				.Select( scopeString => {
					if( Scope.TryParse( scopeString, out Scope scope ) ) {
						return scope;
					}

					return null;
				} )
				.Where( s => s != null );

			return grantedScopes;
		}
	}
}