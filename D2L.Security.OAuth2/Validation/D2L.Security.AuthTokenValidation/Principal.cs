using System;
using System.Collections.Generic;

namespace D2L.Security.AuthTokenValidation {

	public abstract class Principal {

		public bool HasScope( string scope ) {
			return Scopes.Contains( "*" ) || Scopes.Contains( scope );
		}

		public void AssertScope( string scope ) {
			if( !HasScope( scope ) ) {
				throw new AuthorizationException( string.Format( "Not authorized for scope '{0}'", scope ) );
			}
		}

		public HashSet<string> Scopes { get; set; }
	}
}