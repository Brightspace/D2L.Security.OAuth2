using System;
using System.Threading.Tasks;
using D2L.Security.OAuth2.Keys.Default;
using Moq;

namespace D2L.Security.OAuth2.TestUtilities.Mocks {
	public static class PublicKeyProviderMock {
		internal static Mock<IPublicKeyProvider> Create(
			Uri jwksEndpoint,
			string keyId,
			D2LSecurityToken token
		) {
			var mock = new Mock<IPublicKeyProvider>();

			mock.Setup( p => p.GetByIdAsync(
				keyId
			) ).Returns( Task.FromResult( token ) );

			return mock;
		}
	}
}
