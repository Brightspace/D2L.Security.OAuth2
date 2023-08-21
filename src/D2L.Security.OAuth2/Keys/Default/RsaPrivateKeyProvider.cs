using System;
using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography;
using System.Threading.Tasks;
using D2L.CodeStyle.Annotations;

namespace D2L.Security.OAuth2.Keys.Default {
	internal sealed partial class RsaPrivateKeyProvider : IPrivateKeyProvider {

		private readonly ID2LSecurityTokenFactory m_d2lSecurityTokenFactory;

		public RsaPrivateKeyProvider(
			ID2LSecurityTokenFactory d2lSecurityTokenFactory
		) {
			m_d2lSecurityTokenFactory = d2lSecurityTokenFactory;
		}

		[GenerateSync]
		Task<D2LSecurityToken> IPrivateKeyProvider.GetSigningCredentialsAsync() {
			RSAParameters privateKey;
			using( var csp = new RSACryptoServiceProvider( Constants.GENERATED_RSA_KEY_SIZE ) { PersistKeyInCsp = false } ) {
				privateKey = csp.ExportParameters( includePrivateParameters: true );
			}

			D2LSecurityToken result = m_d2lSecurityTokenFactory.Create( () => {
				var csp = new RSACryptoServiceProvider() { PersistKeyInCsp = false };
				csp.ImportParameters( privateKey );
				var key = new RsaSecurityKey( csp );
				return new Tuple<AsymmetricSecurityKey, IDisposable>( key, csp );
			} );

			return Task.FromResult( result );
		}
	}
}
