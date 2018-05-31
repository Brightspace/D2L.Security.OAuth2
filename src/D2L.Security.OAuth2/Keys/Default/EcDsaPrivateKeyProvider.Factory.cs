using System;
using System.Security.Cryptography;
using D2L.Security.OAuth2.Utilities;

namespace D2L.Security.OAuth2.Keys.Default {

	partial class EcDsaPrivateKeyProvider {

		internal static class Factory {

			internal static IPrivateKeyProvider Create(
				IPublicKeyDataProvider publicKeyDataProvider,
				TimeSpan keyLifetime,
				TimeSpan keyRotationPeriod,
				CngAlgorithm algorithm,
				IDateTimeProvider dateTimeProvider = null
			) {
				if( keyLifetime < keyRotationPeriod ) {
					throw new ArgumentException( "Private key lifetime must exceed the rotation period", "keyLifetime" );
				}

				dateTimeProvider = dateTimeProvider ?? DateTimeProvider.Instance;

				ID2LSecurityKeyFactory d2lSecurityTokenFactory = new D2LSecurityKeyFactory(
					dateTimeProvider,
					keyLifetime
				);

				IPrivateKeyProvider privateKeyProvider = new EcDsaPrivateKeyProvider(
					d2lSecurityTokenFactory,
					algorithm
				);

				privateKeyProvider = new SavingPrivateKeyProvider(
					privateKeyProvider,
					PublicKeyDataProviderFactory.CreateInternal( publicKeyDataProvider )
				);

				privateKeyProvider = new RotatingPrivateKeyProvider(
					privateKeyProvider,
					dateTimeProvider,
					keyRotationPeriod
				);

				return privateKeyProvider;
			}
		}
	}
}
