using System;

namespace D2L.Security.WebApiAuthFilter.Exceptions {
	
	[Serializable]
	public class PrincipalNotAssignedException : Exception {

		public PrincipalNotAssignedException( string message )
			: base( message ) {
		}
	}
}
