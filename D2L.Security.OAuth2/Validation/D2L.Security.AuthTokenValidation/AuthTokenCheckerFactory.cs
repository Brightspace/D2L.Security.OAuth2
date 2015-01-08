using D2L.Security.AuthTokenValidation.Default;

namespace D2L.Security.AuthTokenValidation {

	public sealed class AuthTokenCheckerFactory : IAuthTokenCheckerFactory {

		public IAuthTokenChecker Create() {
			return new AuthTokenChecker(
				new AuthServerPublicKeyProvider()
				);
		}
	}
}
