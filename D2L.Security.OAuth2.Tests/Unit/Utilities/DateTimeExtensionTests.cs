using System;

using NUnit.Framework;

namespace D2L.Security.OAuth2.Tests.Unit.Utilities {
	[TestFixture]
	[Category( "Unit" )]
	internal sealed class DateTimeExtensionTests {
		private readonly DateTime SPECIAL_DAY = new DateTime( 2009, 2, 14, 23, 31, 30, DateTimeKind.Utc );

		[Test]
		public void FromUnixTime_0_IsEpoch() {
			DateTime actual = DateTimeExtensions.FromUnixTime( 0 );
			Assert.AreEqual( DateTimeExtensions.EPOCH, actual );
		}

		[Test]
		public void FromUnixTime_123456890__SPECIAL_DAY() {
			DateTime actual = DateTimeExtensions.FromUnixTime( 1234567890 );
			Assert.AreEqual( SPECIAL_DAY, actual );
		}

		[Test]
		public void ToUnixTime_Epoch_0() {
			long actual = DateTimeExtensions.EPOCH.ToUnixTime();
			Assert.AreEqual( 0, actual );
		}

		[Test]
		public void ToUnixTime_Special_Day__123456890() {
			long actual = DateTimeExtensions.EPOCH.ToUnixTime();
			Assert.AreEqual( 123456890, actual );
		}
	}
}
