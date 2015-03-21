using D2L.Security.OAuth2.Validation.Token;
using D2L.Security.OAuth2.Validation.Request.Core.Default;

namespace D2L.Security.OAuth2.Validation.Request.Core {
	internal static class CoreAuthenticatorFactory {

		internal static ICoreAuthenticator Create( IAuthTokenValidator tokenValidator, bool mustValidateXsrf ) {
			return new CoreAuthenticator( tokenValidator, mustValidateXsrf );
		}
	}
}
