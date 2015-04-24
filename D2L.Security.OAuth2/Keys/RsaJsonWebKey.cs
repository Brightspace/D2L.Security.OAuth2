using System;
using System.IdentityModel.Tokens;
using System.Security.Cryptography;

using D2L.Security.OAuth2.Utilities;
using D2L.Security.OAuth2.Validation.Exceptions;

namespace D2L.Security.OAuth2.Keys {
	public sealed class RsaJsonWebKey : JsonWebKey {

		private readonly string m_modulus;
		private readonly string m_exponent;

		public RsaJsonWebKey(
			Guid id,
			DateTime expiresAt,
			RSAParameters rsaParameters
		) : base( id, expiresAt ) {
			m_modulus = Base64Url.Encode( rsaParameters.Modulus );
			m_exponent = Base64Url.Encode( rsaParameters.Exponent );
		}

		public RsaJsonWebKey(
			Guid id,
			DateTime? expiresAt,
			string n,
			string e
		) : base( id, expiresAt ) {
			m_modulus = n;
			m_exponent = e;
		}

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

		public override D2LSecurityToken ToSecurityToken() {
			
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
