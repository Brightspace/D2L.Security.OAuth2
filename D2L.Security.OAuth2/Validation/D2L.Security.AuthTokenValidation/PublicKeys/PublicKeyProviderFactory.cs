using D2L.Security.AuthTokenValidation.PublicKeys.Default;

namespace D2L.Security.AuthTokenValidation.PublicKeys {
	internal static class PublicKeyProviderFactory {

		private const string AUTHORITY = "https://phwinsl01.proddev.d2l:44333/core/";
		private static readonly IPublicKeyProvider Instance = new PublicKeyProvider( AUTHORITY );

		internal static IPublicKeyProvider Create() {
			return Instance;
		}
	}
}
