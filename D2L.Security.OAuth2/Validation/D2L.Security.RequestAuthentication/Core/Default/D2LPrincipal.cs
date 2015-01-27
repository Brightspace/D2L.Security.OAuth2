using System;
using System.Collections.Generic;

namespace D2L.Security.RequestAuthentication.Core.Default {
	internal sealed class D2LPrincipal : ID2LPrincipal {

		internal D2LPrincipal() {
		}

		long? ID2LPrincipal.UserId {
			get { throw new NotImplementedException(); }
		}
		
		string ID2LPrincipal.TenantId {
			get { throw new NotImplementedException(); }
		}

		string ID2LPrincipal.TenantUrl {
			get { throw new NotImplementedException(); }
		}
		
		IEnumerable<string> ID2LPrincipal.Scopes {
			get { throw new NotImplementedException(); }
		}

		PrincipalType ID2LPrincipal.Type {
			get { throw new NotImplementedException(); }
		}
	}
}
