using System;
using D2L.Security.OAuth2.Keys.Default;
using D2L.Security.OAuth2.Utilities;

namespace D2L.Security.OAuth2.Keys {

	/// <summary>
	/// A factory for creating <see cref="ITokenSigner"/> instances.
	/// </summary>
	public static class TokenSignerFactory {

		/// <summary>
		/// Creates an <see cref="ITokenSigner"/> instance which saves public keys to the provided <see cref="IPublicKeyDataProvider"/>
		/// </summary>
		/// <param name="publicKeyDataProvider">The <see cref="IPublicKeyDataProvider"/> for the local service</param>
		/// <returns>A new <see cref="ITokenSigner"/></returns>
		public static ITokenSigner Create(
			IPublicKeyDataProvider publicKeyDataProvider
		) {
			return Create(
				publicKeyDataProvider,
				keyLifetime: Constants.DEFAULT_KEY_LIFETIME,
				keyRotationPeriod: Constants.DEFAULT_KEY_ROTATION_PERIOD
			);
		}

		/// <summary>
		/// Creates an <see cref="ITokenSigner"/> instance which saves public keys to the provided <see cref="IPublicKeyDataProvider"/>
		/// </summary>
		/// <param name="publicKeyDataProvider">The <see cref="IPublicKeyDataProvider"/> for the local service</param>
		/// <param name="keyLifetime">The max time a private key and its tokens may be used for</param>
		/// <param name="keyRotationPeriod">How often to switch to signing with a new private key. The difference between this and <paramref name="keyLifetime"/> is the maximum token lifetime.</param>
		/// <returns>A new <see cref="ITokenSigner"/></returns>
		public static ITokenSigner Create(
			IPublicKeyDataProvider publicKeyDataProvider,
			TimeSpan keyLifetime,
			TimeSpan keyRotationPeriod
		) {
			var privateKeyProvider = new PrivateKeyProvider(
				PublicKeyDataProviderFactory.CreateInternal( publicKeyDataProvider ),
				new DateTimeProvider(),
				keyLifetime: keyLifetime,
				keyRotationPeriod: keyRotationPeriod
			);
			var tokenSigner = new TokenSigner( privateKeyProvider );
			return tokenSigner;
		}

	}
}
