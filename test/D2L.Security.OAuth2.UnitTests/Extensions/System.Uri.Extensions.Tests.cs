using System;
using NUnit.Framework;

namespace D2L.Security.OAuth2.Extensions {

	[TestFixture]
	internal sealed class SystemUriExtensionsTests {

		[Test]
		[TestCase( "https://example.com", "foo", ExpectedResult = "https://example.com/foo" )]
		[TestCase( "https://example.com", "/foo", ExpectedResult = "https://example.com/foo" )]
		[TestCase( "https://example.com/foo", "bar", ExpectedResult = "https://example.com/foo/bar" )]
		[TestCase( "https://example.com/foo", "/bar", ExpectedResult = "https://example.com/bar" )]
		[TestCase( "https://example.com/foo/", "bar", ExpectedResult = "https://example.com/foo/bar" )]
		[TestCase( "https://example.com/foo/", "/bar", ExpectedResult = "https://example.com/bar" )]
		public string RelativePathAsNonLeaf(
			string baseUri,
			string pathAddition
		) => new Uri( baseUri ).RelativePathAsNonLeaf( pathAddition ).AbsoluteUri;

	}
}
