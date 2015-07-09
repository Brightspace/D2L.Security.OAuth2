using System;
using System.Security.Cryptography;
using D2L.Security.OAuth2.Keys.Default;
using D2L.Security.OAuth2.Utilities;

namespace D2L.Security.OAuth2.Keys {

	/// <summary>
	/// A factory for creating new <see cref="ITokenSigner"/> instances that use ECDSA keys
	/// </summary>
	public static class EcDsaTokenSignerFactory {

		/// <summary>
		/// ECDSA curves that can be used to generate keys
		/// </summary>
		public enum Curve {
			/// <summary>
			/// NIST Curve P256
			/// </summary>
			P256 = 1,
			/// <summary>
			/// NIST Curve P384
			/// </summary>
			P384 = 2,
			/// <summary>
			/// NIST Curve P521
			/// </summary>
			P521 = 3
		};


		/// <summary>
		/// Creates an <see cref="ITokenSigner"/> instance which saves public keys to the provided <see cref="IPublicKeyDataProvider"/>
		/// </summary>
		/// <param name="publicKeyDataProvider">The <see cref="IPublicKeyDataProvider"/> for the local service</param>
		/// <param name="curve">The curve to use</param>
		/// <returns>A new <see cref="ITokenSigner"/></returns>
		public static ITokenSigner Create(
			IPublicKeyDataProvider publicKeyDataProvider,
			Curve curve
		) {
			return Create(
				publicKeyDataProvider,
				curve,
				keyLifetime: Constants.DEFAULT_KEY_LIFETIME,
				keyRotationPeriod: Constants.DEFAULT_KEY_ROTATION_PERIOD
			);
		}



		/// <summary>
		/// Creates an <see cref="ITokenSigner"/> instance which saves public keys to the provided <see cref="IPublicKeyDataProvider"/>
		/// </summary>
		/// <param name="publicKeyDataProvider">The <see cref="IPublicKeyDataProvider"/> for the local service</param>
		/// <param name="curve">The curve to use</param>
		/// <param name="keyLifetime">The max time a private key and its tokens may be used for</param>
		/// <param name="keyRotationPeriod">How often to switch to signing with a new private key. The difference between this and <paramref name="keyLifetime"/> is the maximum token lifetime.</param>
		/// <returns>A new <see cref="ITokenSigner"/></returns>
		public static ITokenSigner Create(
			IPublicKeyDataProvider publicKeyDataProvider,
			Curve curve,
			TimeSpan keyLifetime,
			TimeSpan keyRotationPeriod
		) {

			IDateTimeProvider dateTimeProvider = new DateTimeProvider();

			CngAlgorithm algorithm;
			switch( curve ) {
				case Curve.P521: {
					algorithm = CngAlgorithm.ECDsaP521;
					break;
				}
				case Curve.P384: {
					algorithm = CngAlgorithm.ECDsaP384;
					break;
				}
				case Curve.P256:
				default: {
					algorithm = CngAlgorithm.ECDsaP256;
					break;
				}
			}

			IPrivateKeyProvider privateKeyProvider = new EcDsaPrivateKeyProvider(
				PublicKeyDataProviderFactory.CreateInternal( publicKeyDataProvider ),
				dateTimeProvider,
				keyLifetime: keyLifetime,
				keyRotationPeriod: keyRotationPeriod,
				algorithm: algorithm
			);

			return new TokenSigner( privateKeyProvider );
		}
	}
}
