using System;

namespace D2L.Security.OAuth2.Utilities {
	internal sealed class DateTimeProvider : IDateTimeProvider {

		internal static readonly IDateTimeProvider Instance = new DateTimeProvider();

		public DateTimeOffset UtcNow {
			get { return DateTimeOffset.UtcNow; }
		}
	}
}
