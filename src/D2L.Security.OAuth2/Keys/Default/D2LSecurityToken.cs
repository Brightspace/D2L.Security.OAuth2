using System;
using System.IdentityModel.Tokens;
using System.Security.Cryptography;
using System.Threading;

namespace D2L.Security.OAuth2.Keys.Default {

	internal sealed partial class D2LSecurityToken : SecurityToken {

		private Guid m_id;
		private readonly DateTime m_validFrom;
		private readonly DateTime m_validTo;

		// This ThreadLocal is used as most implementations of the SecurityKeys
		// such as RSACryptoServiceProvider are not thread-safe
		// This allows us to share the D2LSecurityToken across threads, while still
		// respecting the thread safety warning of those implemtnations
		private readonly ThreadLocal<AsymmetricSecurityKey> m_key;

		public D2LSecurityToken(
			Guid id,
			DateTime validFrom,
			DateTime validTo,
			Func<AsymmetricSecurityKey> keyFactory
		) {
			if( validFrom >= validTo ) {
				throw new ArgumentException( "validFrom must be before validTo" );
			}

			m_id = id;
			m_validFrom = validFrom;
			m_validTo = validTo;

			m_key = new ThreadLocal<AsymmetricSecurityKey>(
				valueFactory: () => {
					var key = keyFactory();
					key.KeyId = id.ToString();
					return key;
				},
				trackAllValues: true
			);
		}

		public Guid KeyId { get { return m_id; } }
		
		public override DateTime ValidFrom {
			get { return m_validFrom; }
		}

		public override DateTime ValidTo {
			get { return m_validTo; }
		}

		public bool HasPrivateKey {
			get { return GetKey().HasPrivateKey; }
		}

		public SigningCredentials GetSigningCredentials() {
			string signatureAlgorithm;

			var key = GetKey();

			if( key is RsaSecurityKey ) {
				signatureAlgorithm = SecurityAlgorithms.RSA_SHA256;
			} else if( key is ECDsaSecurityKey ) {
				var ecdsaKey = key as ECDsaSecurityKey;
				switch( ecdsaKey.CngKey.KeySize ) {
					case 256: {
						signatureAlgorithm = SecurityAlgorithms.ECDSA_SHA256;
						break;
					}
					case 384: {
						signatureAlgorithm = SecurityAlgorithms.ECDSA_SHA384;
						break;
					}
					case 521: {
						signatureAlgorithm = SecurityAlgorithms.ECDSA_SHA512;
						break;
					}
					default: {
						throw new NotImplementedException();
					}
				}
			} else {
				throw new NotImplementedException();
			}

			var signingCredentials = new SigningCredentials(
				key,
				signatureAlgorithm
			);

			return signingCredentials;
		}

		public JsonWebKey ToJsonWebKey( bool includePrivateParameters = false ) {
			var key = GetKey();

			if( key is RsaSecurityKey ) {
				var rsaKey = key as RsaSecurityKey;

				if( includePrivateParameters && !rsaKey.HasPrivateKey ) {
					throw new Exception();
				}

				var parameters = rsaKey.Parameters;

				if( !includePrivateParameters && rsaKey.HasPrivateKey ) {
					var publicParameters = new RSAParameters();
					publicParameters.Modulus = parameters.Modulus;
					publicParameters.Exponent = parameters.Exponent;
					parameters = publicParameters;
				}

				return new RsaJsonWebKey( KeyId, ValidTo, parameters );
			} else if( key is ECDsaSecurityKey && !includePrivateParameters ) {
				var ecDsaKey = key as ECDsaSecurityKey;
				byte[] publicBlob = ecDsaKey.CngKey.Export( CngKeyBlobFormat.EccPublicBlob );

				return new EcDsaJsonWebKey( KeyId, ValidTo, publicBlob );
			}

			throw new NotImplementedException();
		}

		private AsymmetricSecurityKey GetKey() {
			return m_key.Value;
		}

	}
}
