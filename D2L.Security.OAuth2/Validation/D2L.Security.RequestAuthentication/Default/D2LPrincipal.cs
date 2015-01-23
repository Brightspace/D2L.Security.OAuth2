using System;
using System.Collections.Generic;

namespace D2L.Security.RequestAuthentication.Default {
	internal sealed class D2LPrincipal : ID2LPrincipal {

		private readonly bool m_isXsrfSafe;

		internal D2LPrincipal( bool isXsrfSafe ) {
			m_isXsrfSafe = isXsrfSafe;
		}

		long? ID2LPrincipal.UserId {
			get { throw new NotImplementedException(); }
		}

		string ID2LPrincipal.ClientId {
			get { throw new NotImplementedException(); }
		}

		string ID2LPrincipal.TenantId {
			get { throw new NotImplementedException(); }
		}

		string ID2LPrincipal.TenantUrl {
			get { throw new NotImplementedException(); }
		}

		bool ID2LPrincipal.XsrfSafe {
			get { return m_isXsrfSafe; }
		}

		bool ID2LPrincipal.IsBrowserUser {
			get { throw new NotImplementedException(); }
		}

		bool ID2LPrincipal.IsService {
			get { throw new NotImplementedException(); }
		}

		IEnumerable<string> ID2LPrincipal.Scopes {
			get { throw new NotImplementedException(); }
		}
	}
}
