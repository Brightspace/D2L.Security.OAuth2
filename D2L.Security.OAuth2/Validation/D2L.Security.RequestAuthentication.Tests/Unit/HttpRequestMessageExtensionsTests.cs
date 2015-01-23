using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using NUnit.Framework;

namespace D2L.Security.RequestAuthentication.Tests.Unit {
	
	[TestFixture]
	internal class HttpRequestMessageExtensionsTests {

		[Test]
		public void GetCookieValue_Null_ExpectNull() {
			Assert.IsNull( HttpRequestMessageExtensions.GetCookieValue( null, "dummycookiename" ) );
		}
	}
}
