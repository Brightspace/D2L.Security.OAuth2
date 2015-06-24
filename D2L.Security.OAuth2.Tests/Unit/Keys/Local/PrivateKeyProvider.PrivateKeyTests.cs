using System;
using System.Security.Cryptography;
using D2L.Security.OAuth2.Keys.Local.Default;
using NUnit.Framework;

namespace D2L.Security.OAuth2.Tests.Unit.Keys.Local {
	
	[TestFixture]
	[Category( "Unit" )]
	internal sealed class PrivateKeyTests {

		[Test]
		public void Dispose_CalledOnce_DoesNotThrowException() {

			RSAParameters rsaParameters;
			using( RSACryptoServiceProvider csp = new RSACryptoServiceProvider( Constants.KEY_SIZE ) ) {
				csp.PersistKeyInCsp = false;
				rsaParameters = csp.ExportParameters( includePrivateParameters: true );
			}

			DateTime validFrom = DateTime.UtcNow;

			PrivateKeyProvider.PrivateKey privateKey =
				new PrivateKeyProvider.PrivateKey(
					Guid.NewGuid(),
					rsaParameters,
					validFrom,
					validFrom + TimeSpan.FromMinutes( 10 )
					);

			Assert.DoesNotThrow( privateKey.Dispose );
		}
	}
}
