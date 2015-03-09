using System;
using System.Linq;

namespace D2L.Security.ScopeAuthorization {

	internal static class ScopeExtensions {

		private const string SCOPE_PATTERN = "group:resource:permission[,permission]*";

		/// <param name="scopePattern">The scope pattern in the form of
		/// "group:resource:permission[,permission]*.</param>
		/// <example>
		/// lores:*:*                  => Full access to all lores resources
		/// lores:objective:*          => Full access to objectives resources in lores
		/// lores:objective:read       => Read only for objectives in lores
		/// lores:*:read               => Read only for all resources in lores
		/// lores:*:create             => Create only for all resources in lores
		/// lores:*:read,create,update => Read, create, or update for all resources in lores
		/// insights:events:read       => Read raw events in Insights
		/// insights:aggregates:read   => Read aggregates in Insights
		/// insights:*:read            => Read all data in insights
		/// *:*:*                      => Full access to all services
		/// *:*:read                   => Read only for all services
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
