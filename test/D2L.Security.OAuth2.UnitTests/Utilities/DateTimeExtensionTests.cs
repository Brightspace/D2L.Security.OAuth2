using System;
using NUnit.Framework;

namespace D2L.Security.OAuth2.Utilities {
	[TestFixture]
	internal sealed class DateTimeExtensionTests {

		private const int SPECIAL_DAY_SECONDS = 1234567890;
		private readonly DateTime SPECIAL_DAY = new DateTime( 2009, 2, 13, 23, 31, 30, DateTimeKind.Utc );

		[Test]
		public void FromUnixTime_0_IsEpoch() {
			DateTime actual = DateTimeHelpers.FromUnixTime( 0 );
			Assert.AreEqual( DateTimeHelpers.EPOCH, actual );
		}

		[Test]
		public void FromUnixTime_123456890__SPECIAL_DAY() {
			DateTime actual = DateTimeHelpers.FromUnixTime( SPECIAL_DAY_SECONDS );
			Assert.AreEqual( SPECIAL_DAY, actual );
		}
	}
}
