using System;
using System.Linq;
using NUnit.Framework;

namespace D2L.Security.OAuth2.Validation.Token.Tests.Utilities {
	internal static class Assertions {

		/// <summary>
		/// Asserts that the "scope" claim contains the specified value
		/// </summary>
		/// <param name="validatedToken">A validated token</param>
		/// <param name="scopeValue">The value to use when checking</param>
		internal static void ContainsScopeValue( IValidatedToken validatedToken, string scopeValue ) {
			string scopeValueFromClaim = validatedToken.Claims.First( x => x.Type == "scope" ).Value;
			Assert.AreEqual( scopeValue, scopeValueFromClaim );
		}

		internal static void ScopeClaimsCountIsExactly( IValidatedToken validatedToken, long count ) {
			string scopeValueFromClaim = validatedToken.Claims.First( x => x.Type == "scope" ).Value;
			Assert.AreEqual( count, validatedToken.Claims.Count( x => x.Type == "scope" ) );
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
				Assert.AreEqual( typeof( T ), e.GetType() );
			}
		}

		/// <summary>
		/// Asserts that the specified action will throw an exception
		/// </summary>
		/// <param name="action">Action to perform</param>
		internal static void Throws( Action action ) {
			try {
				action();
			} catch {
				Assert.Pass();
			}
			Assert.Fail( "Expected an exception to be thrown but none was." );
		}

		/// <summary>
		/// Asserts that the specified action will throw an exception of type TOuter, 
		/// whose immediate inner exception is as specified
		/// </summary>
		/// <param name="action">Action to perform</param>
		/// <param name="action">Inner exception instance</param>
		internal static void ThrowsWithInner<TOuter>( Action action, Exception inner ) 
			where TOuter : Exception 
			{
			
			try {
				action();
			} catch ( TOuter e ) {
				Assert.IsTrue( Object.ReferenceEquals( inner, e.InnerException ) );
				Assert.Pass();
			} catch ( Exception e ) {
				Assert.Fail( 
					"Expected to catch " + 
					typeof( TOuter ).AssemblyQualifiedName + 
					" but caught " + 
					e.GetType().AssemblyQualifiedName 
					);
			}
			Assert.Fail( "Expected an exception to be thrown but none was." );
		}
	}
}
