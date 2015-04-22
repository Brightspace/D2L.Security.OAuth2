using System;

using D2L.Security.OAuth2.Keys.Local.Data;
using D2L.Security.OAuth2.Keys.Local.Default;
using D2L.Security.OAuth2.Utilities;

namespace D2L.Security.OAuth2.Keys.Local {
	public static class KeyManagerFactory {
		private static readonly TimeSpan DEFAULT_KEY_LIFETIME = TimeSpan.FromHours( 1 );
		private static readonly TimeSpan DEFAULT_KEY_ROTATION_PERIOD = TimeSpan.FromMinutes( 10 );

		public static IKeyManager Create(
			IPublicKeyDataProvider publicKeyDataProvider
		) {
			return Create(
				publicKeyDataProvider,
				keyLifetime: DEFAULT_KEY_LIFETIME,
				keyRotationPeriod: DEFAULT_KEY_ROTATION_PERIOD );
		}

		public static IKeyManager Create(
			IPublicKeyDataProvider publicKeyDataProvider,
			TimeSpan keyLifetime,
			TimeSpan keyRotationPeriod
		) {

			IDateTimeProvider dateTimeProvider = new DateTimeProvider();

			IPublicKeyProvider publicKeyProvider = new PublicKeyProvider(
				publicKeyDataProvider,
				keyLifetime: keyLifetime );

			IPrivateKeyProvider privateKeyProvider = new PrivateKeyProvider(
				publicKeyDataProvider,
				dateTimeProvider,
				keyLifetime: keyLifetime,
				keyRotationPeriod: keyRotationPeriod );

			return new KeyManager( publicKeyProvider, privateKeyProvider );
		}
	}
}
