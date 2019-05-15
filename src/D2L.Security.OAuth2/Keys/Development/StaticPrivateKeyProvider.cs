using System;
using System.IdentityModel.Tokens;
using System.Security.Cryptography;
using System.Threading.Tasks;
using D2L.Security.OAuth2.Keys.Default;

namespace D2L.Security.OAuth2.Keys.Development {

	/// <summary>
	/// A private key provider with a fixed key for testing purposes
	/// </summary>
	[Obsolete( "Only use this in tests and for prototyping." )]
	internal sealed class StaticPrivateKeyProvider : IPrivateKeyProvider {
		private readonly string m_keyId;
		private readonly RSAParameters m_rsaParameters;

		public StaticPrivateKeyProvider(
			string keyId,
			RSAParameters rsaParameters
		) {
			m_keyId = keyId;
			m_rsaParameters = rsaParameters;
		}

		public Task<D2LSecurityToken> GetSigningCredentialsAsync() {
			var creds = new D2LSecurityToken(
				id: m_keyId,
				validFrom: DateTime.UtcNow - TimeSpan.FromDays( 1 ),
				validTo: DateTime.UtcNow + TimeSpan.FromDays( 365 ),
				keyFactory: () => {
					var csp = new RSACryptoServiceProvider() { PersistKeyInCsp = false };
					csp.ImportParameters( m_rsaParameters );
					var key = new RsaSecurityKey( csp );
					return new Tuple<AsymmetricSecurityKey, IDisposable>( key, csp );
				} )
				.Ref();

			return Task.FromResult( creds );
		}
	}
}
