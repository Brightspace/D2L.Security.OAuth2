using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace D2L.Security.AuthTokenProvisioning {
	public class Scope {

		private readonly string m_group;
		private readonly string m_resource;
		private readonly string[] m_permissions;

		public Scope(
			string group,
			string resource,
			string permission
		)
			: this( group, resource, new string[] { permission } ) { }

		public Scope( string group, string resource, string[] permissions ) {
			m_group = group;
			m_resource = resource;
			m_permissions = permissions.OrderBy( x => x ).ToArray();
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

		public static bool TryParse( string input, out Scope scope ) {
			string[] parts = input.Split( ':' );
			if( parts.Length != 3 ) {
				scope = null;
				return false;
			}

			string group = parts[0];
			string resource = parts[1];
			string[] permissions = parts[2].Split( ',' );

			scope = new Scope( group, resource, permissions );
			return true;
		}

	}
}
