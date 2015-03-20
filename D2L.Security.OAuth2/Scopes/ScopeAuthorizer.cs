using System;
using System.Collections.Generic;
using System.Linq;

namespace D2L.Security.ScopeAuthorization {

	internal static class ScopeAuthorizer {

		public static bool IsAuthorized( IEnumerable<Scope> grantedScopes, Scope requiredScope ) {

			if( grantedScopes == null ) {
				throw new ArgumentNullException( "grantedScopes" );
			}
			if( requiredScope == null ) {
				throw new ArgumentNullException( "requiredScope" );
			}

			var groupScopes = grantedScopes
				.Where( s => IsMatch( s.Group, requiredScope.Group ) );

			var resourceScopes = groupScopes
				.Where( s => IsMatch( s.Resource, requiredScope.Resource ) );

			var permissionScopes = resourceScopes
				.Where( s => s.Permissions.Any(
					p => IsMatch( p, requiredScope.Permissions[0] )
				) );

			return permissionScopes.Any();
		}

		private static bool IsMatch( string pattern, string actual ) {
			return pattern == "*" || String.Equals( pattern, actual, StringComparison.OrdinalIgnoreCase );
		}

	}

}
