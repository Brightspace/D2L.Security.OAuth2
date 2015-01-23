using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using D2L.Security.AuthTokenValidation;
using D2L.Security.RequestAuthentication.Core.Default;

namespace D2L.Security.RequestAuthentication.Core {
	internal static class CoreAuthenticatorFactory {
		internal static ICoreAuthenticator Create( IAuthTokenValidator tokenValidator ) {
			return new CoreAuthenticator( tokenValidator );
		}
	}
}
