using D2L.Security.OAuth2.Validation.AccessTokens;
using Moq;

namespace D2L.Security.OAuth2.Tests.Utilities.Mocks {
	public static class AccessTokenValidatorMock {

		public static Mock<IAccessTokenValidator> Create(
			string accessToken,
			IValidationResponse response
		) {
			var mock = new Mock<IAccessTokenValidator>();

			mock.Setup(
				v => v.ValidateAsync(
					accessToken
				)
			).ReturnsAsync( response );

			return mock;
		}

	}
}
