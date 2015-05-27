using System;
using System.IdentityModel.Tokens;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace D2L.Security.OAuth2.Keys.Local.Default {

	/// <summary>
	/// A private key provider with a fixed key for testing purposes
	/// </summary>
	[Obsolete("Only use this in tests and for prototyping.")]
	internal sealed class StaticPrivateKeyProvider : IPrivateKeyProvider {
		private readonly Guid m_keyId;
		private readonly RSAParameters m_rsaParameters;

		public StaticPrivateKeyProvider(
			Guid keyId,
			RSAParameters rsaParameters
		) {
			m_keyId = keyId;
			m_rsaParameters = rsaParameters;	
		}

		public Task<D2LSecurityToken> GetSigningCredentialsAsync() {
			var csp = new RSACryptoServiceProvider();
			csp.ImportParameters( m_rsaParameters );

			var key = new RsaSecurityKey( csp );

			var creds = new D2LSecurityToken(
				id: m_keyId,
				validFrom: DateTime.UtcNow - TimeSpan.FromDays( 1 ),
				validTo: DateTime.UtcNow + TimeSpan.FromDays( 365 ),
				key: key );

			return Task.FromResult( creds );
		}
	}
}
