using Owin;
using Thinktecture.IdentityServer.v3.AccessTokenValidation;

namespace D2L.Security.AuthTokenValidation {

	public static class IdentityServerAccessTokenValidationAppBuilderExtensions {

		public static IAppBuilder UseBearerTokenAuthentication(
			this IAppBuilder appBuilder,
			string authenticationEndpoint
			) {

			IdentityServerBearerTokenAuthenticationOptions authOptions =
				new IdentityServerBearerTokenAuthenticationOptions {
					ValidationMode = ValidationMode.Local,
					Authority = authenticationEndpoint
				};

			// TODO: Somehow register a way to specify the principal that gets returned

			appBuilder.UseIdentityServerBearerTokenAuthentication( authOptions );
			return appBuilder;
		}
	}
}
