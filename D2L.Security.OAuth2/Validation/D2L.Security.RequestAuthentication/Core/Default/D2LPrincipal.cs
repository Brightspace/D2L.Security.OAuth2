using System;
using System.Collections.Generic;

namespace D2L.Security.RequestAuthentication.Core.Default {
	internal sealed class D2LPrincipal : ID2LPrincipal {

		internal D2LPrincipal() {
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
