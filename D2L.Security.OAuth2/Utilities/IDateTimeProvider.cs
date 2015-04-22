using System;

namespace D2L.Security.OAuth2.Utilities {
	internal interface IDateTimeProvider {
		DateTime UtcNow { get; }
	}
}
