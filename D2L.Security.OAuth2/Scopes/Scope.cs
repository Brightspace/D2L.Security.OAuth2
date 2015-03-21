using System;
using System.Linq;

namespace D2L.Security.OAuth2.Scopes {

	public sealed class Scope {

		private readonly string m_group;
		private readonly string m_resource;
		private readonly string[] m_permissions;

		public Scope( string group, string resource, string permission )
			: this( group, resource, new[] { permission } ) {
		}

		public Scope( string group, string resource, string[] permissions ) {
			m_group = group;
			m_resource = resource;
			m_permissions = permissions.OrderBy( x => x ).ToArray();
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

		public override string ToString() {
			var permissionsString = string.Join( ",", m_permissions );
			var result = string.Join( ":", m_group, m_resource, permissionsString );
			return result;
		}

		public override bool Equals( object obj ) {
			if( ReferenceEquals( this, obj ) ) {
				return true;
			}

			var otherScope = obj as Scope;
			if( otherScope == null ) {
				return false;
			}

			return this.GetHashCode() == otherScope.GetHashCode();
		}

		public override int GetHashCode() {
			return this.ToString().GetHashCode();
		}

		/// <summary>
		/// Tries to parse a scope pattern into a <see cref="Scope"/> object.
		/// </summary>
		/// <param name="scopePattern">The scope pattern in the form of
		/// "group:resource:permission[,permission]*.</param>
		/// <param name="scope">The <see cref="Scope"/> object</param>
		/// <returns><see langword="true"/> if the scope pattern was properly
		/// parsed; <see langword="false"/> otherwise.</returns>
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
		public static bool TryParse( string scopePattern, out Scope scope ) {

			scope = null;

			if( String.IsNullOrWhiteSpace( scopePattern ) ) {
				return false;
			}

			string[] scopeParts = scopePattern.Split( ":".ToCharArray(), StringSplitOptions.RemoveEmptyEntries );
			if( scopeParts.Length != 3 || scopeParts.Any( String.IsNullOrWhiteSpace ) ) {
				return false;
			}

			string[] permissionParts = scopeParts[2].Split( ",".ToCharArray(), StringSplitOptions.RemoveEmptyEntries );
			if( permissionParts.Length < 1 ) {
				return false;
			}

			scope = new Scope( scopeParts[0], scopeParts[1], permissionParts );

			return true;
		}

		/// <summary>
		/// Parses a scope pattern into a <see cref="Scope"/> object.
		/// </summary>
		/// <param name="scopePattern">The scope pattern in the form of
		/// "group:resource:permission[,permission]*.</param>
		/// <returns>If the scope is properly parsed, returns the <see cref="Scope"/> object;
		/// otherwise <see langword="null"/>.</returns>
		public static Scope Parse( string scopePattern ) {
			Scope scope = null;
			TryParse( scopePattern, out scope );
			return scope;
		}

	}

}
