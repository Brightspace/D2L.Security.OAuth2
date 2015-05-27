using System;
using System.Threading.Tasks;
using D2L.Security.OAuth2.Keys;
using D2L.Security.OAuth2.Keys.Remote;
using Moq;

namespace D2L.Security.OAuth2.Tests.Utilities.Mocks {
	public static class PublicKeyProviderMock {

		internal static Mock<IPublicKeyProvider> Create(
			Uri jwksEndpoint,
			Guid keyId,
			D2LSecurityToken token
		) {

			var mock = new Mock<IPublicKeyProvider>();

			mock.Setup( p => p.GetSecurityTokenAsync(
				jwksEndpoint,
				keyId
			)).Returns( Task.FromResult( token ) );

			return mock;

		}

	}
}
