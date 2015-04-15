using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading.Tasks;
using D2L.Security.OAuth2.Validation;
using D2L.Security.OAuth2.Validation.AccessTokens;
using Moq;

namespace D2L.Security.OAuth2.Tests.Mocks {
	public static class AccessTokenValidatorMock {

		public static Mock<IAccessTokenValidator> Create(
			string accessToken,
			ValidationResponse response
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
