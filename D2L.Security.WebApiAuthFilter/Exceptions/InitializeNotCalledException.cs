using System;

namespace D2L.Security.WebApiAuthFilter.Exceptions {

	[Serializable]
	public class InitializeNotCalledException : Exception {

		public InitializeNotCalledException( string message )
			: base( message ) {
		}
	}
}
