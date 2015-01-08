using System;
using System.Web;

namespace D2L.Security.AuthTokenValidation.Default {

	public sealed class AuthTokenChecker : IAuthTokenChecker {

		public Principal VerifyAndDecode( HttpRequest request ) {
			throw new NotImplementedException();
		}

		public Principal VerifyAndDecode( string jwt ) {
			throw new NotImplementedException();
		}
	}
}