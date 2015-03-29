using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IdentityModel.Tokens;

namespace D2L.Security.OAuth2.SecurityTokens {
	/// <summary>
	/// This implementation of SecurityToken has a configurable validFrom/validTo
	/// </summary>
	public sealed class D2LSecurityToken : SecurityToken {
		private readonly Guid m_id;
		private readonly DateTime m_validFrom;
		private readonly DateTime m_validTo;
		private readonly AsymmetricSecurityKey[] m_securityKeys;

		private string m_idAsString;

		public D2LSecurityToken(
			TimeSpan lifespan,
			AsymmetricSecurityKey key
		) {
			m_id = Guid.NewGuid();
			m_validFrom = DateTime.UtcNow;
			m_validTo = m_validFrom + lifespan;
			m_securityKeys = new[] {key};
		}

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
			m_securityKeys = new[] {key};
		}

		public override string Id {
			get {
				if( m_idAsString == null ) {
					m_idAsString = m_id.ToString();
				}
				return m_idAsString;
			}
		}

		public override ReadOnlyCollection<SecurityKey> SecurityKeys {
			get { return new ReadOnlyCollection<SecurityKey>( m_securityKeys ); }
		}

		public override DateTime ValidFrom {
			get { return m_validFrom; }
		}

		public override DateTime ValidTo {
			get { return m_validTo; }
		}

		public Guid KeyId {
			get { return m_id; }
		}

		public bool IsExpired() {
			return DateTime.UtcNow > m_validTo;
		}

		public bool IsExpiringSoon( TimeSpan rolloverWindow ) {
			return DateTime.UtcNow >= m_validTo - rolloverWindow;
		}

		public bool HasPrivateKey() {
			return m_securityKeys[ 0 ].HasPrivateKey();
		}
	}
}
