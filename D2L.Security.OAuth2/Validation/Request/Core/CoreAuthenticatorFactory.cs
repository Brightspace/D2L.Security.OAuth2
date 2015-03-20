using D2L.Security.AuthTokenValidation;
using D2L.Security.RequestAuthentication.Core.Default;

namespace D2L.Security.RequestAuthentication.Core {
	internal static class CoreAuthenticatorFactory {

		internal static ICoreAuthenticator Create( IAuthTokenValidator tokenValidator, bool mustValidateXsrf ) {
			return new CoreAuthenticator( tokenValidator, mustValidateXsrf );
		}
	}
}
