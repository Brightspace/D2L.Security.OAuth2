using System;
using System.Collections.Generic;
using System.Net;
using System.Text;

namespace D2L.Security.AuthTokenProvisioning.Invocation {

	/// <summary>
	/// Configures an access token provision invocation
	/// </summary>
	internal sealed class InvocationParameters {
		
		private readonly string m_authorization;
		private readonly string m_scopes;
		private readonly string m_assertionToken;

		internal InvocationParameters( 
			IEnumerable<string> scopes, 
			string assertionToken 
			) {

			// TODO: If we can solve US49562 we can get rid of this authorization header
			m_authorization = "lms.dev.d2l:lms_secret";
			
			m_authorization = ToBase64( m_authorization );
			m_authorization = "Basic " + m_authorization;

			m_scopes = string.Join( " ", scopes );
			m_scopes = WebUtility.UrlEncode( m_scopes );

			m_assertionToken = assertionToken;
		}

		internal string Authorization {
			get { return m_authorization; }
		}

		internal string Scope {
			get { return m_scopes; }
		}

		internal string GrantType {
			get { return Constants.AssertionGrant.GRANT_TYPE; }
		}

		internal string Assertion {
			get { return m_assertionToken; }
		}

		private static string ToBase64( string me ) {
			byte[] plainTextBytes = Encoding.UTF8.GetBytes( me );
			return Convert.ToBase64String( plainTextBytes );
		}
	}
}
