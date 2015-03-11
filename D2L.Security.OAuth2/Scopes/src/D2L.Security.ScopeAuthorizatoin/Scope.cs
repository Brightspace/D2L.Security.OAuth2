using System;
using System.Linq;

namespace D2L.Security.ScopeAuthorization {

	internal sealed class Scope {

		private readonly string m_group;
		private readonly string m_resource;
		private readonly string[] m_permissions;

		public Scope( string group, string resource, string permission )
			: this( group, resource, new[] { permission } ) {
		}

		public Scope( string group, string resource, string[] permissions ) {
			m_group = group;
			m_resource = resource;
			m_permissions = permissions;
		}

		public string Group {
			get { return m_group; }
		}

		public string Resource {
			get { return m_resource; }
		}

		public string[] Permissions {
			get { return m_permissions; }
		}

		/// <summary>
		/// Converts a scope pattern to a <see cref="Scope"/> object.
		/// </summary>
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
		/// </example>
		public static Scope FromString( string scopePattern ) {

			const string SCOPE_PATTERN = "group:resource:permission[,permission]*";

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
