using System;
using System.Collections.ObjectModel;
using System.IdentityModel.Tokens;

namespace D2L.Security.AuthTokenValidation.PublicKeys.Default {
	internal sealed class PublicKey : IPublicKey {

		private readonly SecurityKey m_securityKey;
		private readonly string m_issuer;

		internal PublicKey( SecurityToken token, string issuer ) {
			m_securityKey = ExtractKeyFrom( token );
			m_issuer = issuer;
		}

		SecurityKey IPublicKey.Key {
			get { return m_securityKey; }
		}

		string IPublicKey.Issuer {
			get { return m_issuer; }
		}

		private SecurityKey ExtractKeyFrom( SecurityToken token ) {
			ReadOnlyCollection<SecurityKey> securityKeys = token.SecurityKeys;

			if( securityKeys.Count != 1 ) {
				throw new Exception( string.Format( "Expected one security key and found {0}", securityKeys.Count ) );
			}

			return securityKeys[0];
		}
	}
}
