using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace D2L.Security.OAuth2.Validation.Jwks {
	internal interface IPublicKeyProvider {
		Task<SecurityToken> GetSecurityTokenAsync( Uri jwksEndPoint, string keyId );
	}
}
