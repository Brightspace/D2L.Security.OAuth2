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
			m_permissions = permissions;
		}

		public override string ToString() {
			var permissionsString = string.Join( ",", m_permissions );
			var result = string.Join( ":", m_group, m_resource, permissionsString );
			return result;
		}

	}
}
