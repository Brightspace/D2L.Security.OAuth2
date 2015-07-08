using System;

using D2L.Security.OAuth2.Keys.Local.Data;
using D2L.Security.OAuth2.Keys.Local.Default;
using D2L.Security.OAuth2.Utilities;

namespace D2L.Security.OAuth2.Keys.Local {

	/// <summary>
	/// A factory for creating new <see cref="IKeyManager"/> instances
	/// </summary>
	public static class KeyManagerFactory {
		private static readonly TimeSpan DEFAULT_KEY_LIFETIME = TimeSpan.FromHours( 1 );
		private static readonly TimeSpan DEFAULT_KEY_ROTATION_PERIOD = TimeSpan.FromMinutes( 10 );

		/// <summary>
		/// Creates a new <see cref="IKeyManager"/>
		/// </summary>
		/// <param name="publicKeyDataProvider">The data layer for key management</param>
		/// <returns>A new <see cref="IKeyManager"/></returns>
		public static IKeyManager Create(
			IPublicKeyDataProvider publicKeyDataProvider
		) {
			return Create(
				publicKeyDataProvider,
				keyLifetime: DEFAULT_KEY_LIFETIME,
				keyRotationPeriod: DEFAULT_KEY_ROTATION_PERIOD );
		}

		/// <summary>
		/// Creates a new <see cref="IKeyManager"/>
		/// </summary>
		/// <param name="publicKeyDataProvider">The data layer for key management</param>
		/// <param name="keyLifetime">How long provisioned keys will be valid for</param>
		/// <param name="keyRotationPeriod">How close to key expiry a fresh key should be provisioned. Must be smaller than <paramref name="keyLifetime"/></param>
		/// <returns>A new <see cref="IKeyManager"/></returns>
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
				keyRotationPeriod: keyRotationPeriod
				);

			return new KeyManager( publicKeyProvider, privateKeyProvider );
		}
	}
}
