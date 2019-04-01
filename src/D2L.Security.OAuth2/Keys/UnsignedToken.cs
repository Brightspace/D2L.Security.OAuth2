using System;
using System.Collections.Generic;

namespace D2L.Security.OAuth2.Keys {

	/// <summary>
	/// A token that has yet to be signed
	/// </summary>
	public sealed class UnsignedToken {
		private readonly string m_issuer;
		private readonly string m_audience;
		private readonly IReadOnlyDictionary<string, object> m_claims;
		private readonly DateTime m_notBefore;
		private readonly DateTime m_expiresAt;

		/// <summary>
		/// Constructs a new <see cref="UnsignedToken"/> instance
		/// </summary>
		/// <param name="issuer">Identifies the issuer of the JWT; this is the 'iss' claim</param>
		/// <param name="audience">Identifies the recipients that the JWT is itended for; this is the 'aud' claim</param>
		/// <param name="claims">The token's claims</param>
		/// <param name="notBefore">When the token becomes valid; this is the 'nbf' claim</param>
		/// <param name="expiresAt">When the token expires; this is the 'exp' claim</param>
		public UnsignedToken(
			string issuer,
			string audience,
			IReadOnlyDictionary<string, object> claims,
			DateTime notBefore,
			DateTime expiresAt
		) {
			m_issuer = issuer;
			m_audience = audience;
			m_claims = claims;
			m_notBefore = notBefore;
			m_expiresAt = expiresAt;
		}

		/// <summary>
		/// Identifies the issuer of the JWT; this is the 'iss' claim
		/// </summary>
		public string Issuer {
			get { return m_issuer; }
		}

		/// <summary>
		/// Identifies the recipients that the JWT is itended for; this is the 'aud' claim
		/// </summary>
		public string Audience {
			get { return m_audience; }
		}

		/// <summary>
		/// The token's claims
		/// </summary>
		public IReadOnlyDictionary<string, object> Claims {
			get { return m_claims; }
		}

		/// <summary>
		/// When the token becomes valid; this is the 'nbf' claim
		/// </summary>
		public DateTime NotBefore {
			get { return m_notBefore; }
		}

		/// <summary>
		/// When the token expires; this is the 'exp' claim
		/// </summary>
		public DateTime ExpiresAt {
			get { return m_expiresAt; }
		}
	}
}
