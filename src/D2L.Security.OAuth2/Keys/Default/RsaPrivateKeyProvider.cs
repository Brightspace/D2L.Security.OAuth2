using System;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Tokens;

namespace D2L.Security.OAuth2.Keys.Default {
	internal sealed partial class RsaPrivateKeyProvider : IPrivateKeyProvider {

		private readonly ID2LSecurityKeyFactory m_d2lSecurityTokenFactory;

		public RsaPrivateKeyProvider(
			ID2LSecurityKeyFactory d2lSecurityTokenFactory
		) {
			m_d2lSecurityTokenFactory = d2lSecurityTokenFactory;
		}

		Task<D2LSecurityKey> IPrivateKeyProvider.GetSigningCredentialsAsync() {
			RSAParameters privateKey;
			using( var csp = new RSACryptoServiceProvider( Constants.GENERATED_RSA_KEY_SIZE ) { PersistKeyInCsp = false } ) {
				privateKey = csp.ExportParameters( includePrivateParameters: true );
			}

			D2LSecurityKey result = m_d2lSecurityTokenFactory.Create( () => {
				var csp = new RSACryptoServiceProvider() { PersistKeyInCsp = false };
				csp.ImportParameters( privateKey );
				var key = new RsaSecurityKey( csp );
				return new Tuple<AsymmetricSecurityKey, IDisposable>( key, csp );
			} );

			return Task.FromResult( result );
		}
	}
}