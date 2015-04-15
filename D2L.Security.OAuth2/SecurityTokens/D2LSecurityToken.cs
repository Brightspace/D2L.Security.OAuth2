using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IdentityModel.Tokens;
using System.Security.Cryptography;

namespace D2L.Security.OAuth2.SecurityTokens {
	/// <summary>
	/// This implementation of SecurityToken has a configurable validFrom/validTo
	/// </summary>
	public class D2LSecurityToken : SecurityToken, IDisposable {
		private readonly Guid m_id;
		private readonly DateTime m_validFrom;
		private readonly DateTime m_validTo;
		private readonly AsymmetricSecurityKey m_key;

		private string m_idAsString;

		/// <remarks>
		/// This class takes ownership of the AsymmetricSecurityKey
		/// </remarks>
		public D2LSecurityToken(
			TimeSpan lifespan,
			AsymmetricSecurityKey key
		) {
			m_id = Guid.NewGuid();
			m_validFrom = DateTime.UtcNow;
			m_validTo = m_validFrom + lifespan;
			m_key = key;
		}

		/// <remarks>
		/// This class takes ownership of the AsymmetricSecurityKey
		/// </remarks>
		public D2LSecurityToken(
			Guid id,
			DateTime validFrom,
			DateTime validTo,
			AsymmetricSecurityKey key
		) {
			if( id == new Guid() ) {
				throw new ArgumentException( "Use Guid.NewGuid() to create Guids - the default constructor always creates the same one." );
			}
			if( validFrom >= validTo ) {
				throw new ArgumentException( "validFrom must be before validTo" );
			}

			m_id = id;
			m_validFrom = validFrom;
			m_validTo = validTo;
			m_key = key;
		}

		public override string Id {
			get {
				if( m_idAsString == null ) {
					m_idAsString = m_id.ToString();
				}
				return m_idAsString;
			}
		}

		public virtual Guid KeyId {
			get { return m_id; }
		}

		public override ReadOnlyCollection<SecurityKey> SecurityKeys {
			get {
				return new ReadOnlyCollection<SecurityKey>(
					new List<SecurityKey> { m_key }
				);
			}
		}

		public override DateTime ValidFrom {
			get { return m_validFrom; }
		}

		public override DateTime ValidTo {
			get { return m_validTo; }
		}

		public virtual bool IsExpired() {
			return DateTime.UtcNow > m_validTo;
		}

		public virtual bool IsExpiringSoon( TimeSpan rolloverWindow ) {
			return DateTime.UtcNow >= m_validTo - rolloverWindow;
		}

		public virtual bool HasPrivateKey() {
			return m_key.HasPrivateKey();
		}

		public virtual AsymmetricAlgorithm GetAsymmetricAlgorithm() {
			if( m_key is X509AsymmetricSecurityKey ) {
				throw new InvalidOperationException(
					"This hacky thing is not applicable to the X509AsymmetricSecurityKey implementation"
				);
			}

			// Note: RsaSecurityKey ignores the "algorithm" parameter here.
			// See http://referencesource.microsoft.com/#System.IdentityModel/System/IdentityModel/Tokens/RsaSecurityKey.cs,63

			AsymmetricAlgorithm alg = m_key
				.GetAsymmetricAlgorithm( "", HasPrivateKey() );

			return alg;
		}

		public virtual void Dispose() {
			var alg = GetAsymmetricAlgorithm();
			alg.Dispose();
		}
	}
}
