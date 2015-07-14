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
				valueFactory: keyFactory,
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
			get { return m_key.Value.HasPrivateKey(); }	
		}

		public AsymmetricAlgorithm GetAsymmetricAlgorithm() {
			if( m_key.Value is X509AsymmetricSecurityKey ) {
				throw new InvalidOperationException(
					"This hacky thing is not applicable to the X509AsymmetricSecurityKey implementation"
				);
			}

			// Note: RsaSecurityKey ignores the "algorithm" parameter here.
			// See http://referencesource.microsoft.com/#System.IdentityModel/System/IdentityModel/Tokens/RsaSecurityKey.cs,63

			AsymmetricAlgorithm alg = m_key
				.Value
				.GetAsymmetricAlgorithm( "", HasPrivateKey );

			return alg;
		}

		public SigningCredentials GetSigningCredentials() {
			string signatureAlgorithm;
			string digestAlgorithm;

			if( m_key.Value is RsaSecurityKey ) {
				signatureAlgorithm = SecurityAlgorithms.RsaSha256Signature;
				digestAlgorithm = SecurityAlgorithms.Sha256Digest;
			} else if( m_key.Value is EcDsaSecurityKey ) {
				var ecdsaKey = m_key.Value as EcDsaSecurityKey;
				signatureAlgorithm = ecdsaKey.SignatureAlgorithm;
				digestAlgorithm = ecdsaKey.DigestAlgorithm;
			} else {
				throw new NotImplementedException();
			}

			var keyIdentifierClause = new NamedKeySecurityKeyIdentifierClause( name: "kid", id: Id );
			var securityKeyIdentifier = new SecurityKeyIdentifier( keyIdentifierClause );

			var signingCredentials = new SigningCredentials(
				m_key.Value,
				signatureAlgorithm,
				digestAlgorithm,
				securityKeyIdentifier );

			return signingCredentials;
		}

		public JsonWebKey ToJsonWebKey( bool includePrivateParameters = false ) {
			if( m_key.Value is RsaSecurityKey ) {
				var csp = GetAsymmetricAlgorithm() as RSACryptoServiceProvider;
				RSAParameters p = csp.ExportParameters( includePrivateParameters );

				return new RsaJsonWebKey( KeyId, ValidTo, p );
			} else if( m_key.Value is EcDsaSecurityKey && !includePrivateParameters ) {
				var ecDsa = GetAsymmetricAlgorithm() as ECDsaCng;
				byte[] publicBlob = ecDsa.Key.Export( CngKeyBlobFormat.EccPublicBlob );

				return new EcDsaJsonWebKey( KeyId, ValidTo, publicBlob );
			}

			throw new NotImplementedException();
		}

	}
}
