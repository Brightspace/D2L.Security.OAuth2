﻿using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IdentityModel.Tokens;
using System.Security.Cryptography;

using D2L.Security.OAuth2.Provisioning;

namespace D2L.Security.OAuth2.SecurityTokens {
	/// <summary>
	/// This implementation of SecurityToken has a configurable validFrom/validTo
	/// </summary>
	public class D2LSecurityToken : NamedKeySecurityToken, IDisposable {
		private Guid? m_id;
		private readonly DateTime m_validFrom;
		private readonly DateTime m_validTo;
		private readonly AsymmetricSecurityKey m_key;

		/// <remarks>
		/// This class takes ownership of the AsymmetricSecurityKey
		/// </remarks>
		public D2LSecurityToken(
			TimeSpan lifespan,
			AsymmetricSecurityKey key
		) : base(
			name: ProvisioningConstants.AssertionGrant.KEY_ID_NAME,
			id: Guid.NewGuid().ToString(),
			key: key
		) {
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
		) : base(
			name: ProvisioningConstants.AssertionGrant.KEY_ID_NAME,
			id: id.ToString(),
			key: key
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

		public virtual Guid KeyId {
			get {
				if( m_id == null ) {
					m_id = Guid.Parse( Id );
				}
				return m_id.Value;
			}
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