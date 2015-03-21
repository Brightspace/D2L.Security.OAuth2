using System;
using NUnit.Framework;

namespace D2L.Security.OAuth2.Validation.Request.Tests.Utilities {
	internal static class Assertions {
		
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
	}
}
