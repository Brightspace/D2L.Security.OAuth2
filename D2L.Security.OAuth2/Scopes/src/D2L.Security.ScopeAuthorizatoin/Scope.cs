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

	}

}
