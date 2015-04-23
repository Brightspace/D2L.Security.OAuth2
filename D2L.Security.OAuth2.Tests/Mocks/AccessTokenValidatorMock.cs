using System;
using D2L.Security.OAuth2.Validation.AccessTokens;
using Moq;

namespace D2L.Security.OAuth2.Tests.Mocks {
	public static class AccessTokenValidatorMock {

		public static Mock<IAccessTokenValidator> Create(
			string accessToken,
			IValidationResponse response
		) {
			var mock = new Mock<IAccessTokenValidator>();

			mock.Setup(
				v => v.ValidateAsync(
					It.IsAny<Uri>(),
					accessToken
				)
			).ReturnsAsync( response );

			return mock;
		}

	}
}
