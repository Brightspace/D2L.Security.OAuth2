using System;
using System.Collections.Generic;
using System.Linq;

namespace D2L.Security.OAuth2.Scopes {

	/// <summary>
	/// Helper for comparing scopes
	/// </summary>
	public static class ScopeAuthorizer {

		/// <summary>
		/// Determines if granted scopes satisfy all required scopes
		/// </summary>
		/// <param name="grantedScopes">Scopes from the auth token</param>
		/// <param name="requiredScope">Scopes that are required in order to access a resource</param>
		/// <returns>True if granted scopes satisfy all required scopes, otherwise false</returns>
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

			var authorized = requiredScope.Permissions
				.All( rp => resourceScopes.Any( r => r.Permissions.Any( p => IsMatch( p, rp )) ) );

			return authorized;
		}

		private static bool IsMatch( string pattern, string actual ) {
			return pattern == "*" || String.Equals( pattern, actual, StringComparison.OrdinalIgnoreCase );
		}

	}

}
