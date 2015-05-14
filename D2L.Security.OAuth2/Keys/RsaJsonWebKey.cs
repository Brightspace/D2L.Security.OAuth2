using System;
using System.IdentityModel.Tokens;
using System.Security.Cryptography;

namespace D2L.Security.OAuth2.Keys {

	/// <summary>
	/// RSA-specific implemention of <see cref="JsonWebKey"/>
	/// </summary>
	public sealed class RsaJsonWebKey : JsonWebKey {

		private readonly string m_modulus;
		private readonly string m_exponent;

		/// <summary>
		/// Constructs a new <see cref="RsaJsonWebKey"/> instance
		/// </summary>
		/// <param name="id">The key id (kid)</param>
		/// <param name="expiresAt">When the key expires</param>
		/// <param name="rsaParameters">The parameters needed to by the RSA algorithm</param>
		public RsaJsonWebKey(
			Guid id,
			DateTime expiresAt,
			RSAParameters rsaParameters
		) : base( id, expiresAt ) {
			m_modulus = Base64UrlEncoder.Encode( rsaParameters.Modulus );
			m_exponent = Base64UrlEncoder.Encode( rsaParameters.Exponent );
		}

		/// <summary>
		/// Constructs a new <see cref="RsaJsonWebKey"/> instance
		/// </summary>
		/// <param name="id">The key id (kid)</param>
		/// <param name="expiresAt">When the key expires</param>
		/// <param name="n">The RSA modulus</param>
		/// <param name="e">The RSA exponent</param>
		public RsaJsonWebKey(
			Guid id,
			DateTime? expiresAt,
			string n,
			string e
		) : base( id, expiresAt ) {
			m_modulus = n;
			m_exponent = e;
		}

		/// <summary>
		/// Converts the <see cref="RsaJsonWebKey"/> into a JWK DTO
		/// </summary>
		/// <returns>A JWK DTO</returns>
		public override object ToJwkDto() {
			if( ExpiresAt.HasValue ) {
				return new {
					kid = Id.ToString(),
					kty = "RSA",
					use = "sig",
					n = m_modulus,
					e = m_exponent,
					exp = ExpiresAt.Value.ToUnixTime()
				};
			}

			return new {
				kid = Id.ToString(),
				kty = "RSA",
				use = "sig",
				n = m_modulus,
				e = m_exponent,
			};
		}

		internal override D2LSecurityToken ToSecurityToken() {
			
			var e = Base64UrlEncoder.DecodeBytes( m_exponent );
			var n = Base64UrlEncoder.DecodeBytes( m_modulus );

			var rsaParams = new RSAParameters() {
				Exponent = e,
				Modulus = n
			};

			var rsa = new RSACryptoServiceProvider() { PersistKeyInCsp = false };
			rsa.ImportParameters( rsaParams );
			var key = new RsaSecurityKey( rsa );

			var token = new D2LSecurityToken(
				id: Id,
				validFrom: DateTime.Now,
				validTo: ExpiresAt ?? DateTime.Now.AddSeconds( Remote.Constants.KEY_MAXAGE_SECONDS ),
				key: key
			);
			
			return token;
		}
	}
}
