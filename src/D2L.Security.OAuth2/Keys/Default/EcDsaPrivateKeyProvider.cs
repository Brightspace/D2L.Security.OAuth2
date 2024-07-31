using System;
using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography;
using System.Threading.Tasks;
using D2L.CodeStyle.Annotations;

namespace D2L.Security.OAuth2.Keys.Default {
	internal sealed partial class EcDsaPrivateKeyProvider : IPrivateKeyProvider {

		private readonly ID2LSecurityTokenFactory m_d2lSecurityTokenFactory;
		private readonly ECCurve m_curve;

		public EcDsaPrivateKeyProvider(
			ID2LSecurityTokenFactory d2lSecurityTokenFactory,
			ECCurve curve
		) {
			m_d2lSecurityTokenFactory = d2lSecurityTokenFactory;
			m_curve = curve;
		}

		[GenerateSync]
		Task<D2LSecurityToken> IPrivateKeyProvider.GetSigningCredentialsAsync() {
			var ecdsa = ECDsa.Create( m_curve );
			var parameters = ecdsa.ExportParameters( includePrivateParameters: true );

			D2LSecurityToken result = m_d2lSecurityTokenFactory.Create( () => {
				var ecDsa = ECDsa.Create( parameters );
				var key = new ECDsaSecurityKey( ecDsa );
				return new Tuple<AsymmetricSecurityKey, IDisposable>( key, ecDsa );
			} );

			return Task.FromResult( result );
		}
	}
}
