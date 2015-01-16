using System;
using System.Linq;
using D2L.Security.AuthTokenValidation.TokenValidation;
using NUnit.Framework;

namespace D2L.Security.AuthTokenValidation.Tests.Utilities {
	internal static class Assertions {
		
		/// <summary>
		/// Asserts that the "scope" claim contains the specified value
		/// </summary>
		/// <param name="validatedJWT">A validated JWT</param>
		/// <param name="scopeValue">The value to use when checking</param>
		internal static void ContainsScopeValue( IValidatedJWT validatedJWT, string scopeValue ) {
			string scopeValueFromClaim = validatedJWT.Claims.First( x => x.Type == "scope" ).Value;
			Assert.AreEqual( scopeValue, scopeValueFromClaim );
		}

		/// <summary>
		/// Asserts that the inner most exception is of type T
		/// </summary>
		/// <typeparam name="T">Expected inner most exception type</typeparam>
		/// <param name="action">Action to perform</param>
		internal static void ExceptionStemsFrom<T>( Action action ) {
			try {
				action();
			} catch( Exception e ) {
				while( e.InnerException != null ) {
					e = e.InnerException;
				}
				Assert.IsTrue( typeof( T ) == e.GetType() );
			}
		}
	}
}
