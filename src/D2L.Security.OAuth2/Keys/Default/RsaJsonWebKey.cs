using System;
using System.Security.Cryptography;
using D2L.Services;
using Microsoft.IdentityModel.Tokens;

namespace D2L.Security.OAuth2.Keys.Default {

	/// <summary>
	/// RSA-specific implemention of <see cref="JsonWebKey"/>
	/// </summary>
	internal sealed class RsaJsonWebKey : JsonWebKey {

		private readonly RSAParameters m_parameters;

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
			m_parameters = rsaParameters;
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
			m_parameters.Modulus = Base64UrlEncoder.DecodeBytes( n );
			m_parameters.Exponent = Base64UrlEncoder.DecodeBytes( e );
		}

		/// <summary>
		/// Converts the <see cref="RsaJsonWebKey"/> into a JWK DTO
		/// </summary>
		/// <returns>A JWK DTO</returns>
		public override object ToJwkDto() {
			var modulus = Base64UrlEncoder.Encode( m_parameters.Modulus );
			var exponent = Base64UrlEncoder.Encode( m_parameters.Exponent );

			if( ExpiresAt.HasValue ) {
				return new {
					kid = Id.ToString(),
					kty = "RSA",
					use = "sig",
					n = modulus,
					e = exponent,
					exp = ( long )ExpiresAt.Value.TimeSinceUnixEpoch().TotalSeconds
				};
			}

			return new {
				kid = Id.ToString(),
				kty = "RSA",
				use = "sig",
				n = modulus,
				e = exponent,
			};
		}

		internal override D2LSecurityKey ToSecurityKey() {
			var token = new D2LSecurityKey(
				id: Id,
				validFrom: DateTime.UtcNow,
				validTo: ExpiresAt ?? DateTime.UtcNow + Constants.REMOTE_KEY_MAX_LIFETIME,
				keyFactory: () => {
					var rsa = new RSACryptoServiceProvider() { PersistKeyInCsp = false };
					rsa.ImportParameters( m_parameters );
					var key = new RsaSecurityKey( rsa );
					return new Tuple<AsymmetricSecurityKey, IDisposable>( key, rsa );
				}
			);

			return token;
		}

		/// <summary>
		///	Get the internal RsaParameters 
		/// </summary>
		/// <returns></returns>
		[Obsolete( "Do not use this if you are not LMS 10.5.1!" )]
		public RSAParameters GetRsaParameters() {
			return m_parameters;
		}
	}
}
