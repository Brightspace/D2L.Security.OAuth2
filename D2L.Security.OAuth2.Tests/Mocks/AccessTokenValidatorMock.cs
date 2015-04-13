using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using D2L.Security.OAuth2.Validation;
using Moq;

namespace D2L.Security.OAuth2.Tests.Mocks {
	public static class AccessTokenValidatorMock {

		public static Mock<IAccessTokenValidator> Create(
			ValidationResponse response
		) {
			var mock = new Mock<IAccessTokenValidator>();

			mock.Setup(
				v => v.ValidateAsync(
					It.IsAny<Uri>(),
					It.IsAny<string>()
				)
			).ReturnsAsync( response );

			return mock;
		}

	}
}
