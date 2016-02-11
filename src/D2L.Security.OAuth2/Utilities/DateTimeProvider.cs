using System;

namespace D2L.Security.OAuth2.Utilities {
	internal sealed class DateTimeProvider : IDateTimeProvider {
		public DateTime UtcNow {
			get { return DateTime.UtcNow; }
		}
	}
}
