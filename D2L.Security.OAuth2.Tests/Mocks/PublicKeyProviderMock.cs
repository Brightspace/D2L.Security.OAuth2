using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using D2L.Security.OAuth2.Validation.Jwks;
using Moq;

namespace D2L.Security.OAuth2.Tests.Mocks {
	public static class PublicKeyProviderMock {

		internal static Mock<IPublicKeyProvider> Create(
			string keyId,
			SecurityToken returns_securityToken
		) {

			var mock = new Mock<IPublicKeyProvider>();
			mock.Setup(
				p => p.GetSecurityTokenAsync(
					It.IsAny<Uri>(),
					keyId
				)
			).Returns( Task.FromResult( returns_securityToken ) );
			
			return mock;

		}

	}
}
