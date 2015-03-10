using System;
using System.Linq;

namespace D2L.Security.ScopeAuthorization {

	internal static class ScopeExtensions {

		private const string SCOPE_PATTERN = "group:resource:permission[,permission]*";

		/// <param name="scopePattern">The scope pattern in the form of
		/// "group:resource:permission[,permission]*.</param>
		/// <example>
		/// groupA:*:*                  => Full access to all groupA resources
		/// groupA:resourceX:*          => Full access to resourceX in groupA
		/// groupA:resourceX:read       => Read only for resourceX in groupA
		/// groupA:*:read               => Read only for all resources in groupA
		/// groupA:*:create             => Create only for all resources in groupA
		/// groupA:*:read,create,update => Read, create, or update for all resources in groupA
		/// *:*:*                       => Full access to all resources in all groups
		/// *:*:read                    => Read only for all resources in all groups
		/// </example>>
		public static Scope ToScope( this string scopePattern ) {

			if( String.IsNullOrWhiteSpace( scopePattern ) ) {
				throw new ArgumentException( "scopePattern cannot be null or empty.", "scopePattern" );
			}

			string[] scopeParts = scopePattern.Split( ":".ToCharArray(), StringSplitOptions.RemoveEmptyEntries );
			if( scopeParts.Length != 3 || scopeParts.Any( String.IsNullOrWhiteSpace ) ) {
				throw new ArgumentException(
					String.Format( "scopePattern '{0}' format is invalid." +
						" Expected format is '" + SCOPE_PATTERN + "'.", scopePattern ),
					"scopePattern" );
			}

			string[] permissionParts = scopeParts[2].Split( ",".ToCharArray(), StringSplitOptions.RemoveEmptyEntries );
			if( permissionParts.Length < 1 ) {
				throw new ArgumentException(
					String.Format( "scopePattern '{0}' has invalid permission format." +
						" Expected format is '" + SCOPE_PATTERN + "'.", scopePattern ),
					"scopePattern" );
			}

			var scope = new Scope( scopeParts[0], scopeParts[1], permissionParts );

			return scope;
		}

	}

}
