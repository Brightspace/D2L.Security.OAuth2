using System;
namespace D2L.Security.OAuth2 {

	/// <summary>
	/// Principal types
	/// </summary>
	[Flags]
	public enum PrincipalType {

		/// <summary>
		/// Principal represents a user. Applies when the sub claim is set on the principal
		/// </summary>
		User = 1,
		
		/// <summary>
		/// Principal represents a service. Applies when the sub claim is not set on the principal
		/// </summary>
		Service = 2,

		/// <summary>
		/// No principal
		/// </summary>
		Anonymous = 4
	}
}
