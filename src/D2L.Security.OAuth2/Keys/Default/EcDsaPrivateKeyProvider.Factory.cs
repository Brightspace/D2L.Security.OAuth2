using System;
using System.Security.Cryptography;
using D2L.Security.OAuth2.Utilities;

namespace D2L.Security.OAuth2.Keys.Default {
	internal partial class EcDsaPrivateKeyProvider {

		internal static class Factory {

			internal static IPrivateKeyProvider Create(
				IPublicKeyDataProvider publicKeyDataProvider,
				TimeSpan keyLifetime,
				TimeSpan keyRotationPeriod,
				ECCurve curve,
				IDateTimeProvider dateTimeProvider = null
			) {
				if( keyLifetime < keyRotationPeriod ) {
					throw new ArgumentException( "Private key lifetime must exceed the rotation period", "keyLifetime" );
				}

				dateTimeProvider = dateTimeProvider ?? DateTimeProvider.Instance;

				ID2LSecurityTokenFactory d2lSecurityTokenFactory = new D2LSecurityTokenFactory(
					dateTimeProvider,
					keyLifetime
				);

				IPrivateKeyProvider privateKeyProvider = new EcDsaPrivateKeyProvider(
					d2lSecurityTokenFactory,
					curve
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
