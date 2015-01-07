using System.Web;

namespace D2L.Security.AuthTokenValidation.Default {

	public sealed class AuthTokenChecker : IAuthTokenChecker {

		public Principal VerifyAndDecode( HttpRequest request ) {
			
		}

		public Principal VerifyAndDecode( string jwt ) {
		}
	}
}