using System;
using System.Security.Cryptography;

using D2L.Security.OAuth2.Utilities;

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
			string kid,
			string n,
			string e
		) : base( Guid.Parse( kid ), null ) {
			m_modulus = n;
			m_exponent = e;
		}

		public override object ToJwkDto() {
			var jwk = new {
				kid = Id.ToString(),
				kty = "RSA",
				use = "sig",
				n = m_modulus,
				e = m_exponent
			};

			return jwk;
		}
	}
}
