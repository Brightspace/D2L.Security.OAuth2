using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace D2L.Security.OAuth2.Validation.Jwks {
	public interface ISecurityKeyProvider {
		Task<SecurityKey> GetSecurityKeyAsync( Uri jwksEndPoint, string keyId );
	}
}
