using System;

using D2L.Security.OAuth2.Keys.Local.Data;
using D2L.Security.OAuth2.Keys.Local.Default;

namespace D2L.Security.OAuth2.Keys.Local {
	public static class KeyManagerFactory {
		private static readonly TimeSpan DEFAULT_KEY_LIFETIME = TimeSpan.FromHours( 1 );
		private static readonly TimeSpan DEFAULT_KEY_ROTATION_PERIOD = TimeSpan.FromMinutes( 10 );

		public static IKeyManager Create(
			string issuer,
			IPublicKeyDataProvider publicKeyDataProvider
		) {
			return Create(
				issuer,
				publicKeyDataProvider,
				keyLifetime: DEFAULT_KEY_LIFETIME,
				keyRotationPeriod: DEFAULT_KEY_ROTATION_PERIOD );
		}

		public static IKeyManager Create(
			string issuer,
			IPublicKeyDataProvider publicKeyDataProvider,
			TimeSpan keyLifetime,
			TimeSpan keyRotationPeriod
		) {
			IPublicKeyProvider publicKeyProvider = new PublicKeyProvider(
				publicKeyDataProvider,
				keyLifetime: keyLifetime );

			IPrivateKeyProvider privateKeyProvider = new PrivateKeyProvider(
				publicKeyDataProvider,
				keyLifetime: keyLifetime,
				keyRotationPeriod: keyRotationPeriod );

			return new KeyManager( issuer, publicKeyProvider, privateKeyProvider );
		}
	}
}
