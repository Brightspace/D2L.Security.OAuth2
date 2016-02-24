﻿using System;
using System.IdentityModel.Tokens;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace D2L.Security.OAuth2.Keys.Default {
	internal sealed partial class EcDsaPrivateKeyProvider : IPrivateKeyProvider {

		private readonly ID2LSecurityTokenFactory m_d2lSecurityTokenFactory;
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
				var key = new ECDsaSecurityKey( privateBlob, CngKeyBlobFormat.EccPrivateBlob );
				return new Tuple<AsymmetricSecurityKey, IDisposable>( key, key.CngKey );
			} );

			return Task.FromResult( result );
		}
	}
}