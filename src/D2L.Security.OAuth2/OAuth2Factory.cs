using D2L.Security.OAuth2.Keys;
using D2L.Security.OAuth2.Keys.Default;
using D2L.Security.OAuth2.Utilities;

namespace D2L.Security.OAuth2 {
	public static class OAuth2Factory {
		/// <summary>
		/// Create an IKeyManagmentService and ITokenSigner given key storage
		/// and configuration.
		/// </summary>
		public static void Create(
			IPublicKeyDataProvider publicKeyDataProvider,
			IPrivateKeyDataProvider privateKeyDataProvider,

			out IKeyManagementService keyManagementService,
			out ITokenSigner tokenSigner,

			OAuth2Configuration config = null
		) {
			config = config ?? new OAuth2Configuration();

			config.CheckSanity();

			var clock = new DateTimeProvider();

			keyManagementService = new KeyManagementService(
				publicKeyDataProvider,
				privateKeyDataProvider,
				clock,
				config
			);

			tokenSigner = new TokenSigner(
				keyManagementService as IPrivateKeyProvider
			);
		}
	}
}
