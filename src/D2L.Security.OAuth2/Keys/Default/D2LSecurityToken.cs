using System;
using System.Security.Cryptography;
using System.Threading;
using Microsoft.IdentityModel.Tokens;

namespace D2L.Security.OAuth2.Keys.Default {

	internal sealed partial class D2LSecurityToken : SecurityToken {

		private Guid m_id;
		private readonly DateTime m_validFrom;
		private readonly DateTime m_validTo;

		// This ThreadLocal is used as most implementations of the SecurityKeys
		// such as RSACryptoServiceProvider are not thread-safe
		// This allows us to share the D2LSecurityToken across threads, while still
		// respecting the thread safety warning of those implemtnations
		private readonly ThreadLocal<Tuple<AsymmetricSecurityKey, IDisposable>> m_key;

		public D2LSecurityToken(
			Guid id,
			DateTime validFrom,
			DateTime validTo,
			Func<Tuple<AsymmetricSecurityKey, IDisposable>> keyFactory
		) {
			if( validFrom >= validTo ) {
				throw new ArgumentException( "validFrom must be before validTo" );
			}

			m_id = id;
			m_validFrom = validFrom;
			m_validTo = validTo;

			m_key = new ThreadLocal<Tuple<AsymmetricSecurityKey, IDisposable>>(
				valueFactory: () => {
					var result = keyFactory();
					result.Item1.KeyId = id.ToString();
					return result;
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
				signatureAlgorithm = SecurityAlgorithms.RsaSha256;
			} else if( key is ECDsaSecurityKey ) {
				var ecdsaKey = key as ECDsaSecurityKey;
				switch( ecdsaKey.KeySize ) {
					case 256: {
						signatureAlgorithm = SecurityAlgorithms.EcdsaSha256;
						break;
					}
					case 384: {
						signatureAlgorithm = SecurityAlgorithms.EcdsaSha384;
						break;
					}
					case 521: {
						signatureAlgorithm = SecurityAlgorithms.EcdsaSha512;
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
				var ecDsaCng = ecDsaKey.ECDsa as ECDsaCng;
				var cng = ecDsaCng?.Key;

				if (cng == null) {
					throw new Exception();
				}

				byte[] publicBlob = cng.Export( CngKeyBlobFormat.EccPublicBlob );

				return new EcDsaJsonWebKey( KeyId, ValidTo, publicBlob );
			}

			throw new NotImplementedException();
		}

		private AsymmetricSecurityKey GetKey() {
			return m_key.Value.Item1;
		}

	}
}
