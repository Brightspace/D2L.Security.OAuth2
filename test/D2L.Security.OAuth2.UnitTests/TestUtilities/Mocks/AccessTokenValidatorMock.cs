using System;
using D2L.Security.OAuth2.Validation.AccessTokens;
using D2L.Security.OAuth2.Validation.Exceptions;
using Moq;
using NUnit.Framework;

namespace D2L.Security.OAuth2.TestUtilities.Mocks {
	public static class AccessTokenValidatorMock {
		public static Mock<IAccessTokenValidator> CreateAsync(
			string accessToken,
			IAccessToken accessTokenAfterValidation,
			Type expectedExceptionType
		) {
			var mock = new Mock<IAccessTokenValidator>();

			var invocation = mock.Setup( v => v.ValidateAsync( accessToken ) );
			if( expectedExceptionType == typeof( ValidationException ) ) {
				invocation.Throws( new ValidationException( "" ) );
			} else if( expectedExceptionType != null ) {
				invocation.Throws( ( Exception )Activator.CreateInstance( expectedExceptionType ) );
			} else {
				Assert.IsNotNull( accessTokenAfterValidation );
				invocation.ReturnsAsync( accessTokenAfterValidation );
			}

			return mock;
		}


		public static Mock<IAccessTokenValidator> Create(
			string accessToken,
			IAccessToken accessTokenAfterValidation,
			Type expectedExceptionType
		) {
			var mock = new Mock<IAccessTokenValidator>();

#pragma warning disable D2L0090 // Only methods can call blocking methods
			var invocation = mock.Setup( v => v.Validate( accessToken ) );
#pragma warning restore D2L0090 // Only methods can call blocking methods

			if( expectedExceptionType == typeof( ValidationException ) ) {
				invocation.Throws( new ValidationException( "" ) );
			} else if( expectedExceptionType != null ) {
				invocation.Throws( ( Exception )Activator.CreateInstance( expectedExceptionType ) );
			} else {
				Assert.IsNotNull( accessTokenAfterValidation );
				invocation.Returns( accessTokenAfterValidation );
			}

			return mock;
		}
	}
}
