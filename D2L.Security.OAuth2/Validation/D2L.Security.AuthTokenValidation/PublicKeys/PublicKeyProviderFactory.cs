using D2L.Security.AuthTokenValidation.PublicKeys.Default;

namespace D2L.Security.AuthTokenValidation.PublicKeys {
	internal static class PublicKeyProviderFactory {

		private static object Lock = new object();
		private static IPublicKeyProvider Instance;

		internal static IPublicKeyProvider Create( string authority ) {
			if( Instance == null ) {
				lock( Lock ) {
					if( Instance == null ) {
						Instance = new PublicKeyProvider( authority );
					}
				}
			}
			return Instance;
		}
	}
}
