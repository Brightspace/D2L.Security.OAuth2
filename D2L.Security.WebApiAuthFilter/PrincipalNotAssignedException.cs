using System;

namespace D2L.Security.WebApiAuthFilter {
	
	[Serializable]
	public class PrincipalNotAssignedException : Exception {

		public PrincipalNotAssignedException( string message, Exception innerException )
			: base( message, innerException ) {
		}

		public PrincipalNotAssignedException( string message )
			: base( message ) {
		}
	}
}
