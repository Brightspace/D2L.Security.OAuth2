using System;

namespace D2L.Security.WebApiAuthFilter.Principal {
	
	/// <summary>
	/// Exception for the case where properties on the principal object were accessed before the principal was assigned.
	/// </summary>
	[Serializable]
	public sealed class PrincipalNotAssignedException : Exception {

		public PrincipalNotAssignedException( string message )
			: base( message ) {
		}
	}
}
