using System;
using System.IdentityModel.Tokens;
using System.Security.Cryptography;
using System.Threading.Tasks;
using D2L.CodeStyle.Annotations;

namespace D2L.Security.OAuth2.Keys.Default {
	internal sealed partial class EcDsaPrivateKeyProvider : IPrivateKeyProvider {

		private readonly ID2LSecurityTokenFactory m_d2lSecurityTokenFactory;
		[Mutability.Audited(
			"Todd Lang",
			"14-Aug-2018",
			".Net class we can't mark.")]
		private readonly CngAlgorithm m_algorithm;

		public EcDsaPrivateKeyProvider(
			ID2LSecurityTokenFactory d2lSecurityTokenFactory,
			CngAlgorithm algorithm
		) {
			m_d2lSecurityTokenFactory = d2lSecurityTokenFactory;
			m_algorithm = algorithm;
		}
		
		Task<D2LSecurityToken> IPrivateKeyProvider.GetSigningCredentialsAsync() {
			var creationParams = new CngKeyCreationParameters() {
				ExportPolicy = CngExportPolicies.AllowPlaintextExport,
				KeyUsage = CngKeyUsages.Signing
			};

			byte[] privateBlob;
			using( var cngKey = CngKey.Create( m_algorithm, null, creationParams ) ) {
				using( ECDsaCng ecDsa = new ECDsaCng( cngKey ) ) {
					privateBlob = ecDsa.Key.Export( CngKeyBlobFormat.EccPrivateBlob );
				}
			}

			D2LSecurityToken result = m_d2lSecurityTokenFactory.Create( () => {
				using( var cng = CngKey.Import( privateBlob, CngKeyBlobFormat.EccPrivateBlob ) ) {
					// ECDsaCng copies the CngKey, hence the using
					var ecDsa = new ECDsaCng( cng );
					var key = new EcDsaSecurityKey( ecDsa );
					return new Tuple<AsymmetricSecurityKey, IDisposable>( key, ecDsa );
				}
			} );

			return Task.FromResult( result );
		}
	}
}