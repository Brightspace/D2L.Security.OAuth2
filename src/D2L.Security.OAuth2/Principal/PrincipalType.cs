namespace D2L.Security.OAuth2.Principal {

	/// <summary>
	/// Principal types
	/// </summary>
	public enum PrincipalType {

		/// <summary>
		/// Principal represents a user. Applies when the sub claim is set on the principal
		/// </summary>
		User,
		
		/// <summary>
		/// Principal represents a service. Applies when the sub claim is not set on the principal
		/// </summary>
		Service,

		/// <summary>
		/// No principal
		/// </summary>
		Anonymous
	}
}
