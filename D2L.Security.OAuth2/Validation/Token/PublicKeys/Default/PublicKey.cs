using System;
using System.Collections.ObjectModel;
using System.IdentityModel.Tokens;

namespace D2L.Security.OAuth2.Validation.Token.PublicKeys.Default {
	internal sealed class PublicKey : IPublicKey {

		private readonly SecurityKey m_securityKey;
		private readonly string m_issuer;

		internal PublicKey( SecurityToken securityToken, string issuer ) {

			if( securityToken == null ) {
				throw new ArgumentException( "Cannot be null", "securityToken" );
			}

			if( issuer == null ) {
				throw new ArgumentException( "Cannot be null", "issuer" );
			}

			m_securityKey = ExtractKeyFrom( securityToken );
			m_issuer = issuer;
		}

		SecurityKey IPublicKey.SecurityKey {
			get { return m_securityKey; }
		}

		string IPublicKey.Issuer {
			get { return m_issuer; }
		}

		private SecurityKey ExtractKeyFrom( SecurityToken securityToken ) {
			ReadOnlyCollection<SecurityKey> securityKeys = securityToken.SecurityKeys;

			if( securityKeys == null ) {
				throw new ArgumentException( "Cannot be null", "securityToken.SecurityKeys" );
			}

			if( securityKeys.Count != 1 ) {
				throw new Exception( string.Format( "Expected one security key but got {0}", securityKeys.Count ) );
			}

			return securityKeys[0];
		}
	}
}
